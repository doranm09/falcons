# dashboard/tasks.py
from celery import shared_task
from .models import AgentCommand, CampaignRun, Link, Node, SbomReport, ScanRun, ScanVulnerability, Vulnerability
from .openvas_client import (
    openvas_session,
    create_target,
    start_scan,
    get_report_id,
    download_report,
    get_task_status,
)
from django.utils.timezone import now
import time
import xml.etree.ElementTree as ET
import subprocess
import ipaddress
import requests
import re
import select
import logging
import json
import shutil
import tempfile
import os
from datetime import datetime
from django.utils.dateparse import parse_datetime
from host_agent.sbom.os_sbom import generate_cyclonedx_sbom
from .sbom import extract_package_dicts_from_sbom, extract_vulnerabilities_from_sbom

logger = logging.getLogger(__name__)


def _campaign_step_meta(step, message, steps_completed, total_steps, details=None):
    meta = {
        "step": step,
        "message": message,
        "steps_completed": steps_completed,
        "total_steps": total_steps,
    }
    if details:
        meta["details"] = details
    return meta


def _campaign_log_line(step, message):
    timestamp = now().strftime("%H:%M:%S")
    label = str(step or "campaign").strip() or "campaign"
    text = str(message or "").strip()
    return f"{timestamp} [{label}] {text}"


def _safe_update_state(task, state, meta):
    try:
        task.update_state(state=state, meta=meta)
    except ValueError:
        logger.debug("Skipping task state update without active task id")


def _run_scanner(cmd, timeout_seconds):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return None, f"{cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return None, f"{cmd[0]} timed out after {timeout_seconds}s"

    if result.returncode != 0:
        return None, (result.stderr or result.stdout or "").strip() or f"{cmd[0]} exited with {result.returncode}"

    output = (result.stdout or "").strip()
    if not output:
        return None, f"{cmd[0]} produced no JSON output"

    try:
        return json.loads(output), ""
    except json.JSONDecodeError as exc:
        return None, f"{cmd[0]} returned invalid JSON: {exc}"


def _persist_scanner_vulnerabilities(node, vulnerabilities):
    if not node or not vulnerabilities:
        return 0

    deduped = {}
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve_id") or ""
        if not cve_id:
            continue
        existing = deduped.get(cve_id)
        if not existing:
            deduped[cve_id] = vuln
            continue
        current_score = vuln.get("score") or 0
        existing_score = existing.get("score") or 0
        if current_score > existing_score:
            deduped[cve_id] = vuln
        elif not existing.get("package") and vuln.get("package"):
            deduped[cve_id] = vuln

    persisted = 0
    for vuln in deduped.values():
        cve_id = vuln.get("cve_id") or ""
        if not cve_id:
            continue
        vuln_obj, _ = Vulnerability.objects.get_or_create(
            cve_id=cve_id[:32],
            defaults={
                "description": vuln.get("description") or f"SBOM reported {cve_id}",
                "severity": vuln.get("severity") or "",
                "score": vuln.get("score"),
                "published": now(),
                "last_modified": now(),
                "references": vuln.get("references") or "",
            },
        )
        updated = False
        if vuln.get("description") and vuln_obj.description != vuln.get("description"):
            vuln_obj.description = vuln.get("description")
            updated = True
        if vuln.get("severity") and vuln_obj.severity != vuln.get("severity"):
            vuln_obj.severity = vuln.get("severity")
            updated = True
        if vuln.get("score") is not None and vuln_obj.score != vuln.get("score"):
            vuln_obj.score = vuln.get("score")
            updated = True
        if vuln.get("references") and vuln_obj.references != vuln.get("references"):
            vuln_obj.references = vuln.get("references")
            updated = True
        if updated:
            vuln_obj.last_modified = now()
            vuln_obj.save(update_fields=["description", "severity", "score", "references", "last_modified"])
        node.vulnerability_set.add(vuln_obj)
        persisted += 1

    return persisted


@shared_task(bind=True)
def scan_sbom_vulnerabilities_task(self, agent_id=None, report_id=None):
    """
    Run Trivy and/or Grype on the server side against SBOM or cyber package data.
    """
    node = Node.objects.filter(agent_id=agent_id).first() if agent_id else None
    report = SbomReport.objects.filter(id=report_id).first() if report_id else None

    if report:
        source_payload = report.document
    elif node:
        source_payload = node.installed_libraries or []
    else:
        return {"status": "noop", "reason": "no agent or report found"}

    packages = extract_package_dicts_from_sbom(source_payload)
    if not packages:
        return {"status": "noop", "reason": "no packages to scan"}

    sbom_json = generate_cyclonedx_sbom(packages)
    timeout_seconds = int(os.environ.get("SBOM_SCANNER_TIMEOUT_SECONDS", "180") or 180)
    scanner_order = [name.strip() for name in os.environ.get("SBOM_SCANNERS", "trivy,grype").split(",") if name.strip()]
    findings = []
    scanner_results = []

    with tempfile.TemporaryDirectory(prefix="cyber-sbom-scan-") as tempdir:
        sbom_path = os.path.join(tempdir, "sbom.json")
        with open(sbom_path, "w", encoding="utf-8") as handle:
            json.dump(sbom_json, handle)

        for scanner in scanner_order:
            binary = shutil.which(scanner)
            if not binary:
                scanner_results.append({"scanner": scanner, "status": "missing"})
                continue

            if scanner == "trivy":
                parsed, error = _run_scanner([binary, "sbom", "--format", "json", sbom_path], timeout_seconds)
            elif scanner == "grype":
                parsed, error = _run_scanner([binary, f"sbom:{sbom_path}", "-o", "json"], timeout_seconds)
            else:
                scanner_results.append({"scanner": scanner, "status": "unsupported"})
                continue

            if parsed is None:
                scanner_results.append({"scanner": scanner, "status": "error", "error": error})
                continue

            scanner_findings = extract_vulnerabilities_from_sbom(parsed)
            findings.extend(scanner_findings)
            scanner_results.append({"scanner": scanner, "status": "ok", "findings": len(scanner_findings)})

    persisted = _persist_scanner_vulnerabilities(node, findings)
    return {
        "status": "ok",
        "agent_id": agent_id or "",
        "report_id": report_id or "",
        "packages": len(packages),
        "findings": len(findings),
        "persisted": persisted,
        "scanners": scanner_results,
    }


@shared_task(bind=True)
def scan_network_task(self, cidr, scan_id=None, progress_callback=None):
    from .models import ScanRun, Node, Link  # ensure local import in tasks
    import subprocess, ipaddress

    if scan_id:
        try:
            scan = ScanRun.objects.get(id=scan_id)
            if scan.cidr != cidr:
                scan.cidr = cidr
            scan.status = "RUNNING"
            scan.scan_type = "ping"
            scan.save(update_fields=["cidr", "status", "scan_type"])
        except ScanRun.DoesNotExist:
            scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="ping")
    else:
        scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="ping")

    network = ipaddress.ip_network(cidr, strict=False)
    if network.version == 4:
        total_hosts = network.num_addresses if network.prefixlen >= 31 else max(1, network.num_addresses - 2)
    else:
        total_hosts = max(1, network.num_addresses)
    update_every = max(1, int(total_hosts / 20))  # ~5% increments

    found_nodes = []
    scanned = 0

    for ip in network.hosts():
        scanned += 1
        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            latency = parse_ping_latency(result.stdout)
            node = Node.objects.create(
                scan_run=scan,
                ip_address=str(ip),
                name=str(ip)
            )
            found_nodes.append((node, latency))

        if scanned % update_every == 0 or scanned == total_hosts:
            percent = int((scanned / total_hosts) * 100)
            progress_meta = {
                "current": scanned,
                "total": total_hosts,
                "percent": percent,
                "hosts_found": len(found_nodes),
            }
            _safe_update_state(self, "PROGRESS", progress_meta)
            if callable(progress_callback):
                progress_callback(progress_meta)

    # Create weighted links between nodes
    for i in range(len(found_nodes)):
        for j in range(i + 1, len(found_nodes)):
            node1, latency1 = found_nodes[i]
            node2, latency2 = found_nodes[j]
            avg_latency = (latency1 + latency2) / 2
            Link.objects.create(scan_run=scan, source=node1, destination=node2, weight=avg_latency)
            Link.objects.create(scan_run=scan, source=node2, destination=node1, weight=avg_latency)

    scan.status = "COMPLETE"
    scan.result_summary = f"{len(found_nodes)} nodes, {len(found_nodes)*(len(found_nodes)-1)} links"
    scan.save()

    return scan.result_summary


@shared_task(bind=True)
def nmap_discovery_task(self, cidr, scan_id=None, progress_callback=None):
    if scan_id:
        try:
            scan = ScanRun.objects.get(id=scan_id)
            if scan.cidr != cidr:
                scan.cidr = cidr
            scan.status = "RUNNING"
            scan.scan_type = "nmap"
            scan.save(update_fields=["cidr", "status", "scan_type"])
        except ScanRun.DoesNotExist:
            scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="nmap")
    else:
        scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type="nmap")
    found_ips = []
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version == 4:
        total_hosts = network.num_addresses if network.prefixlen >= 31 else max(1, network.num_addresses - 2)
    else:
        total_hosts = max(1, network.num_addresses)
    initial_progress = {"current": 0, "total": total_hosts, "percent": 0.0, "hosts_found": 0}
    _safe_update_state(self, "PROGRESS", initial_progress)
    if callable(progress_callback):
        progress_callback(initial_progress)

    try:
        cmd = ["nmap", "-sn", cidr, "--stats-every", "1s", "-oG", "-"]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output_lines = []
        last_percent = -1.0
        last_progress_emit = 0.0
        def _emit_progress(progress_meta):
            _safe_update_state(self, "PROGRESS", progress_meta)
            if callable(progress_callback):
                progress_callback(progress_meta)

        def _handle_nmap_line(line):
            nonlocal last_percent, last_progress_emit
            output_lines.append(line)
            if "Status: Up" in line:
                match = re.search(r"Host:\s+(\S+)", line)
                if match:
                    found_ips.append(match.group(1))

            progress_match = re.search(r"About\s+([0-9.]+)%\s+done", line)
            if progress_match:
                try:
                    percent = float(progress_match.group(1))
                except (TypeError, ValueError):
                    percent = None
                if percent is not None:
                    current = int((percent / 100.0) * total_hosts)
                    should_emit = (
                        abs(percent - last_percent) >= 0.05
                        or (time.time() - last_progress_emit) >= 5
                    )
                    if should_emit:
                        _emit_progress({
                            "current": current,
                            "total": total_hosts,
                            "percent": round(percent, 2),
                            "hosts_found": len(found_ips),
                        })
                        last_percent = percent
                        last_progress_emit = time.time()
            elif "Stats:" in line and (time.time() - last_progress_emit) >= 5:
                _emit_progress({
                    "current": int((max(last_percent, 0.0) / 100.0) * total_hosts),
                    "total": total_hosts,
                    "percent": round(last_percent if last_percent >= 0 else 0.0, 2),
                    "hosts_found": len(found_ips),
                    "raw_stats": line.strip(),
                })
                last_progress_emit = time.time()

        supports_select = proc.stdout is not None and hasattr(proc.stdout, "fileno")
        if supports_select:
            while True:
                ready, _, _ = select.select([proc.stdout], [], [], 5)
                if ready:
                    line = proc.stdout.readline()
                    if not line:
                        if proc.poll() is not None:
                            break
                        continue
                    _handle_nmap_line(line)
                else:
                    # Heartbeat even when nmap output is temporarily silent.
                    if (time.time() - last_progress_emit) >= 5:
                        _emit_progress({
                            "current": int((max(last_percent, 0.0) / 100.0) * total_hosts),
                            "total": total_hosts,
                            "percent": round(last_percent if last_percent >= 0 else 0.0, 2),
                            "hosts_found": len(found_ips),
                            "raw_stats": "nmap running (awaiting next stats line)",
                        })
                        last_progress_emit = time.time()
        else:
            for line in proc.stdout:
                _handle_nmap_line(line)

        returncode = proc.wait()
        if returncode != 0:
            tail = "".join(output_lines[-5:]).strip()
            raise RuntimeError(tail or "nmap failed")

        for ip in found_ips:
            Node.objects.create(scan_run=scan, ip_address=ip, name=ip)

        final_progress = {
            "current": total_hosts,
            "total": total_hosts,
            "percent": 100,
            "hosts_found": len(found_ips),
        }
        _safe_update_state(self, "PROGRESS", final_progress)
        if callable(progress_callback):
            progress_callback(final_progress)

        scan.status = "COMPLETE"
        scan.result_summary = f"{len(found_ips)} hosts discovered (nmap)"
    except Exception as e:
        scan.status = "FAILED"
        scan.result_summary = str(e)

    scan.save()
    return scan.result_summary

def parse_ping_latency(output):
    for line in output.decode().splitlines():
        if 'time=' in line:
            try:
                return float(line.split('time=')[-1].split()[0])
            except:
                pass
    return 100.0  # Fallback default

def _severity_label(score):
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "None"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "None"

def parse_and_save_vulnerabilities(report_xml, scan):
    root = ET.fromstring(report_xml)
    for result in root.findall(".//{*}result"):
        host_ip = result.findtext("{*}host")
        if not host_ip:
            continue

        name = result.findtext("{*}name")
        nvt = result.find(".//{*}nvt")
        if not name and nvt is not None:
            name = nvt.findtext("{*}name")
        name = name or "OpenVAS finding"

        description = result.findtext("{*}description")
        if not description and nvt is not None:
            description = nvt.findtext("{*}description")
        description = description or ""

        severity_raw = result.findtext("{*}severity")
        severity_label = _severity_label(severity_raw)
        try:
            cvss_score = float(severity_raw)
        except (TypeError, ValueError):
            cvss_score = None

        cve_text = result.findtext(".//{*}cve") or ""
        cves = [c.strip() for c in cve_text.replace(";", ",").split(",") if c.strip()]
        if not cves:
            nvt_oid = nvt.attrib.get("oid") if nvt is not None else None
            cves = [nvt_oid or f"NVT-{host_ip}"]

        for cve_id in cves:
            ScanVulnerability.objects.update_or_create(
                scan_run=scan,
                host_ip=host_ip,
                cve_id=cve_id[:32],
                defaults={
                    "name": name,
                    "severity": severity_label,
                    "cvss_score": cvss_score,
                    "description": description,
                },
            )

NVD_API_KEY = 'fd4ab0bd-f3a2-4ad2-bc30-c28a09163034'  # put in env later
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def fetch_and_store_cves(keyword="scada"):
    headers = {'apiKey': NVD_API_KEY}
    params = {
        "keywordSearch": keyword,
        "startIndex": 0,
        "resultsPerPage": 100,
    }

    resp = requests.get(NVD_API_URL, headers=headers, params=params)
    data = resp.json()

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        published = parse_datetime(cve["published"])
        modified = parse_datetime(cve["lastModified"])
        score = None
        severity = ""

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]

        refs = "\n".join([
            r["url"]
            for r in cve.get("references", [])
            if "url" in r
        ])

        vuln, _ = Vulnerability.objects.update_or_create(
            cve_id=cve_id,
            defaults={
                "description": description,
                "published": published,
                "last_modified": modified,
                "score": score,
                "severity": severity,
                "references": refs
            }
        )

@shared_task
def launch_openvas_scan_task(cidr, config_name=None, scan_id=None, excluded_hosts=None):
    if scan_id:
        scan = ScanRun.objects.get(id=scan_id)
        if scan.cidr != cidr:
            scan.cidr = cidr
        scan.status = "IN_PROGRESS"
    else:
        scan = ScanRun.objects.create(cidr=cidr, status="IN_PROGRESS", scan_type="openvas")

    try:
        gmp = openvas_session()
        target_id = create_target(gmp, cidr, excluded_hosts=excluded_hosts)
        task_id = start_scan(gmp, target_id, config_name=config_name)
        scan.openvas_task_id = task_id
        scan.result_summary = f"OpenVAS scan launched. Task ID: {task_id}"
    except Exception as e:
        scan.status = "FAILED"
        scan.result_summary = str(e)

    scan.save()
    return scan.result_summary

@shared_task
def poll_openvas_results():
    scans = ScanRun.objects.filter(status="IN_PROGRESS", scan_type="openvas")

    for scan in scans:
        try:
            gmp = openvas_session()
            info = get_task_status(gmp, scan.openvas_task_id)
            status = info.get("status")

            if status != "Done":
                continue

            report_id = info.get("report_id") or get_report_id(gmp, scan.openvas_task_id)
            report_xml = download_report(gmp, report_id)
            parse_and_save_vulnerabilities(report_xml, scan)

            scan.status = "COMPLETE"
            scan.result_summary = f"Scan complete. Report ID: {report_id}"
            scan.save()

        except Exception as e:
            scan.result_summary = f"Polling error: {e}"
            scan.save()


@shared_task(bind=True)
def run_ot_campaign_task(
    self,
    cidr,
    scan_method="nmap",
    agent_id=None,
    max_hosts=None,
    run_openvas=True,
    openvas_config="full_and_fast",
    openvas_timeout_seconds=180,
    sliver_session_id="",
    sliver_command="whoami",
    collect_loot=True,
    campaign_run_id=None,
):
    """
    End-to-end OT campaign orchestration:
    1) Discovery scan
    2) Optional agent scan queue
    3) Optional OpenVAS vulnerability workflow
    4) Optional Sliver command + loot collection
    """
    total_steps = 4
    campaign_run = (
        CampaignRun.objects.filter(id=campaign_run_id).first()
        if campaign_run_id
        else None
    )
    task_id = str(getattr(self.request, "id", "") or "")

    result = {
        "cidr": cidr,
        "scan_method": scan_method,
        "agent_id": agent_id or "",
        "run_openvas": bool(run_openvas),
        "openvas_config": openvas_config or "",
        "sliver_session_id": sliver_session_id or "",
        "sliver_command": sliver_command or "",
        "collect_loot": bool(collect_loot),
        "discovered_ips": [],
        "openvas": {},
        "sliver": {},
        "agent_scan": {},
        "errors": [],
    }
    campaign_log_lines = []
    if campaign_run and isinstance(campaign_run.result_payload, dict):
        existing_lines = campaign_run.result_payload.get("log_lines") or []
        if isinstance(existing_lines, list):
            campaign_log_lines = [str(line) for line in existing_lines if line is not None][-200:]

    def _persist_progress(step, message, steps_completed, details=None):
        log_line = _campaign_log_line(step, message)
        if not campaign_log_lines or campaign_log_lines[-1] != log_line:
            campaign_log_lines.append(log_line)
            if len(campaign_log_lines) > 200:
                del campaign_log_lines[:-200]
        if campaign_run:
            CampaignRun.objects.filter(id=campaign_run.id).update(
                status=CampaignRun.Status.RUNNING,
                celery_task_id=task_id or campaign_run.celery_task_id,
                current_step=step,
                step_message=(message or "")[:255],
                steps_completed=steps_completed,
                total_steps=total_steps,
                result_payload={"log_lines": campaign_log_lines[-200:]},
            )
        _safe_update_state(
            self,
            "PROGRESS",
            _campaign_step_meta(step, message, steps_completed, total_steps, details=details),
        )

    def _record_error(step_name, exc, steps_completed):
        message = f"{step_name}: {exc}"
        result["errors"].append(message)
        _persist_progress(step_name, f"Error: {exc}", steps_completed, details={"error": str(exc)})
        logger.exception("OT campaign step failed (%s): %s", step_name, exc)

    if campaign_run:
        CampaignRun.objects.filter(id=campaign_run.id).update(
            status=CampaignRun.Status.RUNNING,
            celery_task_id=task_id or campaign_run.celery_task_id,
            current_step="queued",
            step_message="Campaign task started.",
            steps_completed=0,
            total_steps=total_steps,
        )

    # Step 1: discovery
    try:
        _persist_progress("discovery", "Starting discovery scan...", 0)
        discovery_scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type=scan_method.lower())
        last_discovery_percent = -1
        last_discovery_emit = 0.0

        def _discovery_progress(meta):
            nonlocal last_discovery_percent, last_discovery_emit
            if not isinstance(meta, dict):
                return
            percent = meta.get("percent")
            if percent is not None:
                try:
                    percent = float(percent)
                except (TypeError, ValueError):
                    percent = None
            raw_stats = str(meta.get("raw_stats") or "").strip()
            now_ts = time.time()
            percent_changed = (
                percent is None
                or last_discovery_percent < 0
                or abs(percent - last_discovery_percent) >= 0.05
            )
            heartbeat_due = bool(raw_stats) and (now_ts - last_discovery_emit) >= 5
            if not percent_changed and not heartbeat_due:
                return
            if percent is not None:
                last_discovery_percent = percent
            last_discovery_emit = now_ts

            current = meta.get("current")
            total = meta.get("total")
            hosts_found = meta.get("hosts_found", 0)
            if raw_stats and not percent_changed:
                progress_message = f"Discovery heartbeat: {raw_stats} hosts found: {hosts_found}."
            elif percent is not None and current is not None and total:
                progress_message = (
                    f"Discovery in progress: {percent:.2f}% ({current}/{total}), hosts found: {hosts_found}."
                )
            elif percent is not None:
                progress_message = f"Discovery in progress: {percent:.2f}%, hosts found: {hosts_found}."
            else:
                progress_message = f"Discovery in progress, hosts found: {hosts_found}."

            _persist_progress(
                "discovery",
                progress_message,
                0,
                details={
                    "progress": percent,
                    "current": current,
                    "total": total,
                    "hosts_found": hosts_found,
                },
            )

        if scan_method.lower() == "ping":
            scan_network_task(cidr, discovery_scan.id, progress_callback=_discovery_progress)
        else:
            nmap_discovery_task(cidr, discovery_scan.id, progress_callback=_discovery_progress)

        discovery_scan.refresh_from_db()
        discovered_ips = list(
            Node.objects.filter(scan_run=discovery_scan)
            .order_by("ip_address")
            .values_list("ip_address", flat=True)
        )
        result["discovered_ips"] = discovered_ips
        result["discovery_scan_id"] = discovery_scan.id
        result["discovery_summary"] = discovery_scan.result_summary or ""
        _persist_progress(
            "discovery",
            f"Discovery completed ({len(discovered_ips)} hosts).",
            1,
            details={"scan_id": discovery_scan.id, "hosts_found": len(discovered_ips)},
        )
    except Exception as exc:
        _record_error("discovery", exc, 0)

    # Step 2: optional agent scan queue
    try:
        if agent_id:
            params = {"cidr": cidr}
            if max_hosts:
                params["max_hosts"] = max_hosts
            command = AgentCommand.objects.create(agent_id=agent_id, action="scan", parameters=params)
            result["agent_scan"] = {
                "queued": True,
                "command_id": command.id,
                "parameters": params,
            }
        else:
            result["agent_scan"] = {
                "queued": False,
                "reason": "No agent selected",
            }
        _persist_progress("agent_scan", "Agent scan step complete.", 2)
    except Exception as exc:
        _record_error("agent_scan", exc, 2)

    # Step 3: optional OpenVAS vulnerability pass
    try:
        if run_openvas:
            _persist_progress("openvas", "Launching OpenVAS scan...", 2)
            vuln_scan = ScanRun.objects.create(
                cidr=cidr,
                status=ScanRun.Status.IN_PROGRESS,
                scan_type="openvas",
            )
            if campaign_run:
                CampaignRun.objects.filter(id=campaign_run.id).update(openvas_scan_id=vuln_scan.id)
            launch_openvas_scan_task.apply(args=(cidr, openvas_config, vuln_scan.id))
            vuln_scan.refresh_from_db()
            result["openvas"]["scan_id"] = vuln_scan.id
            result["openvas"]["task_id"] = vuln_scan.openvas_task_id

            if vuln_scan.openvas_task_id:
                deadline = time.time() + max(15, int(openvas_timeout_seconds))
                last_state = "LAUNCHING"
                while time.time() < deadline:
                    gmp = openvas_session()
                    info = get_task_status(gmp, vuln_scan.openvas_task_id)
                    state = info.get("status") or "UNKNOWN"
                    progress = info.get("progress")
                    if state != last_state:
                        _persist_progress(
                            "openvas",
                            f"OpenVAS state: {state}",
                            2,
                            details={"progress": progress},
                        )
                        last_state = state
                    if state == "Done":
                        report_id = info.get("report_id") or get_report_id(gmp, vuln_scan.openvas_task_id)
                        report_xml = download_report(gmp, report_id)
                        parse_and_save_vulnerabilities(report_xml, vuln_scan)
                        vuln_scan.status = "COMPLETE"
                        vuln_scan.result_summary = f"Scan complete. Report ID: {report_id}"
                        vuln_scan.save(update_fields=["status", "result_summary"])
                        result["openvas"]["report_id"] = report_id
                        if campaign_run:
                            CampaignRun.objects.filter(id=campaign_run.id).update(openvas_report_id=report_id or "")
                        break
                    if state in {"Stopped", "ERROR", "Error"}:
                        break
                    time.sleep(5)
                else:
                    result["openvas"]["timeout"] = True

            vuln_count = ScanVulnerability.objects.filter(scan_run=vuln_scan).count()
            result["openvas"]["vulnerability_count"] = vuln_count
            result["openvas"]["status"] = ScanRun.objects.get(id=vuln_scan.id).status
        else:
            result["openvas"] = {"skipped": True}

        _persist_progress("openvas", "OpenVAS step complete.", 3)
    except Exception as exc:
        _record_error("openvas", exc, 3)

    # Step 4: optional Sliver automation
    try:
        target_session_id = (sliver_session_id or "").strip()
        if not target_session_id and result["discovered_ips"]:
            try:
                from sliver.models import SliverSession
                session = SliverSession.objects.filter(
                    status=SliverSession.Status.ACTIVE,
                    remote_address__in=result["discovered_ips"],
                ).order_by("-last_checkin").first()
                if session:
                    target_session_id = session.session_id
            except Exception:
                target_session_id = ""

        if target_session_id and (sliver_command or "").strip():
            from sliver.tasks import collect_loot_task, execute_sliver_command_task

            cmd_result = execute_sliver_command_task.apply(
                kwargs={
                    "session_id": target_session_id,
                    "command": sliver_command.strip(),
                    "user_id": None,
                    "parameters": {},
                }
            ).result
            result["sliver"]["session_id"] = target_session_id
            result["sliver"]["command_result"] = cmd_result

            if collect_loot:
                loot_result = collect_loot_task.apply(
                    kwargs={"session_id": target_session_id, "user_id": None}
                ).result
                result["sliver"]["loot_result"] = loot_result
        else:
            result["sliver"] = {
                "skipped": True,
                "reason": "No Sliver session/command provided or discoverable",
            }

        _persist_progress("sliver", "Sliver step complete.", 4)
    except Exception as exc:
        _record_error("sliver", exc, 4)

    result["status"] = "completed_with_errors" if result["errors"] else "completed"
    result["log_lines"] = campaign_log_lines[-200:]
    if campaign_run:
        campaign_run.refresh_from_db(fields=["started_at"])
        completed_at = now()
        duration = int(max(0, (completed_at - campaign_run.started_at).total_seconds()))
        CampaignRun.objects.filter(id=campaign_run.id).update(
            finished_at=completed_at,
            duration_seconds=duration,
            status=CampaignRun.Status.COMPLETED if not result["errors"] else CampaignRun.Status.FAILED,
            current_step="complete",
            step_message="Campaign completed." if not result["errors"] else "Campaign completed with errors.",
            steps_completed=total_steps,
            total_steps=total_steps,
            discovered_hosts_count=len(result.get("discovered_ips") or []),
            vulnerability_count=int(result.get("openvas", {}).get("vulnerability_count") or 0),
            error_count=len(result.get("errors") or []),
            error_details="\n".join(result.get("errors") or []),
            result_payload=result,
        )
    return result
