from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib import messages
from .models import (
    AgentCommand,
    AgentStatus,
    CommandResult,
    MinimegaExecutionLog,
    NetworkConnection,
    NetworkMetadata,
    Node,
    NodeInterface,
    RiskNodeMapping,
    SbomReport,
    ScanRun,
    SiemEvent,
    Vulnerability,
    AlertRule,
    Alert,
    Case,
    CaseNote,
    CaseEvidence,
    Hunt,
    HuntNote,
    HuntSearch,
    HuntTag,
    SiemUserRole,
    SiemAuditLog,
    ResearchProfile,
    ThreatIntelIndicator,
    ThreatIntelMatch,
)
import ipaddress
import subprocess
import requests
from django.http import JsonResponse, FileResponse, Http404, HttpResponse, StreamingHttpResponse
from .tasks import (
    scan_network_task,
    launch_openvas_scan_task,
    nmap_discovery_task,
    parse_and_save_vulnerabilities,
)
from .openvas_client import openvas_session, get_task_status, get_report_id, download_report
from celery.result import AsyncResult
from .models import Link
from .risk_assessment import build_cyber_data_for_risk_nodes, summarize_risk_results
from .utils import dijkstra, list_interfaces
from .sbom import (
    detect_sbom_format,
    extract_os_summary_from_sbom,
    extract_packages_from_sbom,
    extract_vulnerabilities_from_sbom,
    compute_payload_hash,
)
from .minimega import build_minimega_script, build_digital_twin_manifest
from django.views.decorators.http import require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.timezone import now
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import os
from collections import defaultdict
from django.conf import settings
from django.db import transaction
from django.db.models import Count
from ipaddress import ip_network
from pathlib import Path
import time
from datetime import timedelta
from functools import wraps
from .siem import normalize_siem_event, parse_siem_search_params, SiemNormalizeError, SiemQueryError
from .siem_adapters import (
    adapt_agent_status,
    adapt_scan_run,
    adapt_sbom_report,
    adapt_vulnerability,
)
from .siem_pipeline import transform_pipeline_events, SiemPipelineError
from .opensearch_client import bulk_index_events, OpensearchError
from .siem_query import parse_search_request, search_siem_events
from .siem_pivot import resolve_siem_pivot
from .siem_alerting import process_alerts_for_events
from .siem_cases import build_case_from_alert, export_case_payload
from .siem_hunts import (
    build_query_payload_from_form,
    clean_query_params,
    parse_hunt_tags,
    replay_hunt_search,
    validate_hunt_query,
)
from .siem_export import (
    EXPORT_SCHEMA_VERSION,
    build_event_queryset,
    export_parquet_bytes,
    ndjson_stream,
)
from .siem_research import apply_profile_max_batch, activate_profile, get_active_profile
from .siem_rbac import get_siem_role, require_siem_role
from .siem_audit import record_siem_audit
from .siem_threat_intel import ingest_indicators, match_indicators, persist_ioc_matches
from .siem_syslog import syslog_to_event
from .siem_windows import windows_event_to_event
from .health import health_snapshot, metrics_payload

SNIFFER_BASE_URL = 'http://localhost:5050'
RISK_ASSESSMENT_TIMEOUT = 15
SIEM_WRITE_ROLES = (SiemUserRole.Role.ADMIN, SiemUserRole.Role.ANALYST)
SIEM_ADMIN_ROLES = (SiemUserRole.Role.ADMIN,)


def _risk_call(func, path, **kwargs):
    last_exc = None
    for attempt in range(2):
        try:
            response = func(_risk_api_url(path), timeout=RISK_ASSESSMENT_TIMEOUT, **kwargs)
            response.raise_for_status()
            return response
        except Exception as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(0.5)
    if last_exc:
        raise last_exc
    raise RuntimeError("Risk service request failed.")

def home(request):
    nodes = Node.objects.all().values('ip_address', 'name')

    # Get process information from all agents
    agents = AgentStatus.objects.filter(processes__isnull=False).order_by('-last_heartbeat')[:10]
    current_processes = []

    for agent in agents:
        if agent.processes:
            for process in agent.processes[:5]:  # Limit to 5 processes per agent
                current_processes.append({
                    'hostname': agent.hostname,
                    'agent_id': agent.agent_id,
                    'pid': process.get('pid'),
                    'name': process.get('name'),
                    'agent_status': agent.status
                })

    return render(request, 'dashboard/home.html', {
        'nodes': nodes,
        'current_processes': current_processes[:20],  # Show top 20 processes
        'timestamp': now().timestamp()
    })


def network_scans(request):
    scan_history = ScanRun.objects.all().order_by('-timestamp')[:20]
    agents = AgentStatus.objects.all().order_by("hostname")
    return render(request, 'dashboard/network_scans.html', {
        'scan_history': scan_history,
        'agents': agents,
    })


def start_scan_ajax(request):
    print(f"[DEBUG] Method received: {request.method}")
    if request.method == "POST":
        cidr = request.POST.get("cidr")
        method = (request.POST.get("scan_method") or "ping").lower()
        print(f"[DEBUG] Received CIDR: {cidr}")
        if not cidr:
            return JsonResponse({"error": "cidr is required"}, status=400)

        scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type=method)
        if method == "nmap":
            task = nmap_discovery_task.delay(cidr, scan.id)
        else:
            task = scan_network_task.delay(cidr, scan.id)
        scan.task_id = task.id
        scan.save(update_fields=["task_id"])
        print(f"[DEBUG] Task dispatched: {task.id}")
        return JsonResponse({"task_id": task.id, "scan_id": scan.id, "method": method})
    else:
        return JsonResponse({"error": "Only POST allowed"}, status=405)


def check_scan_status(request, task_id):
    result = AsyncResult(str(task_id))
    try:
        state = result.state
    except Exception:
        state = "PENDING"

    # Fetch all nodes with interfaces
    nodes = Node.objects.all()
    node_data = []
    for node in nodes:
        node_data.append({
            "ip_address": node.ip_address,
            "name": node.name,
            "status": node.status,
            "description": node.description,
            "last_heartbeat": node.last_heartbeat,
            "interfaces": [
                {
                    "name": iface.name,
                    "ip": iface.ip,
                    "mac": iface.mac
                } for iface in node.interfaces.all()
            ]
        })

    progress = None
    if isinstance(result.info, dict):
        progress = {
            "current": result.info.get("current"),
            "total": result.info.get("total"),
            "percent": result.info.get("percent"),
        }

    response = {
        "state": state,
        "nodes": node_data,
        "progress": progress,
    }

    if state in ['PENDING', 'STARTED'] and progress is None:
        response["progress"] = "Scan is running..."

    if hasattr(result, "ready") and result.ready():
        try:
            result_val = result.result
            if isinstance(result_val, Exception):
                response["result"] = str(result_val)
            else:
                response["result"] = result_val
        except Exception as e:
            response["result"] = f"Error fetching result: {str(e)}"

    return JsonResponse(response)


@csrf_exempt
@require_http_methods(["POST"])
def start_agent_scan(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        data = request.POST

    agent_id = data.get("agent_id")
    cidr = data.get("cidr")
    max_hosts = data.get("max_hosts")

    if not agent_id or not cidr:
        return JsonResponse({"error": "agent_id and cidr are required"}, status=400)

    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    scan = ScanRun.objects.create(cidr=cidr, status="IN_PROGRESS", scan_type="agent")

    parameters = {"cidr": cidr, "scan_id": scan.id}
    if max_hosts:
        parameters["max_hosts"] = max_hosts

    command = AgentCommand.objects.create(
        agent_id=agent_id,
        action="scan",
        parameters=parameters,
    )

    agent.last_command_sent = now()
    agent.save(update_fields=["last_command_sent"])

    return JsonResponse({
        "status": "command_sent",
        "scan_id": scan.id,
        "command_id": command.id,
    })


@csrf_exempt
@require_http_methods(["POST"])
def agent_scan_results(request):
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    cidr = data.get("cidr")
    scan_id = data.get("scan_id")
    hosts = data.get("hosts", [])

    if not agent_id or not cidr:
        return JsonResponse({"error": "agent_id and cidr are required"}, status=400)

    scan = None
    if scan_id:
        try:
            scan = ScanRun.objects.get(id=scan_id)
        except ScanRun.DoesNotExist:
            scan = None
    if not scan:
        scan = ScanRun.objects.create(cidr=cidr, status="IN_PROGRESS", scan_type="agent")

    # Ensure a stable node for the scanning agent itself (agent_id is globally unique)
    agent_node = None
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        agent = None

    try:
        agent_node = Node.objects.get(agent_id=agent_id)
    except Node.DoesNotExist:
        if agent:
            agent_node = Node.objects.create(
                agent_id=agent_id,
                name=agent.hostname or f"agent-{agent_id}",
                ip_address=agent.ip_address,
                status="online",
                description=f"Scanner agent {agent_id}",
            )

    created_nodes = 0
    created_links = 0
    for host in hosts:
        ip_address = host.get("ip") if isinstance(host, dict) else host
        if not ip_address:
            continue
        node, created = Node.objects.get_or_create(
            scan_run=scan,
            ip_address=ip_address,
            defaults={
                "name": ip_address,
                "status": "online",
                "description": f"Reported by agent {agent_id}",
            },
        )
        if not created:
            node.status = "online"
            node.description = f"Reported by agent {agent_id}"
            node.save(update_fields=["status", "description"])
        created_nodes += 1

        # Build directed links (both directions) when we have a scanning agent node
        if agent_node:
            latency_ms = None
            if isinstance(host, dict):
                latency_ms = host.get("latency_ms")
            try:
                weight = float(latency_ms) if latency_ms is not None else 1.0
            except (TypeError, ValueError):
                weight = 1.0

            link1, link1_created = Link.objects.update_or_create(
                scan_run=scan,
                source=agent_node,
                destination=node,
                defaults={"weight": weight},
            )
            link2, link2_created = Link.objects.update_or_create(
                scan_run=scan,
                source=node,
                destination=agent_node,
                defaults={"weight": weight},
            )
            if link1_created:
                created_links += 1
            if link2_created:
                created_links += 1

    scan.status = "COMPLETE"
    scan.result_summary = f"{created_nodes} hosts reported by agent {agent_id}"
    if created_links:
        scan.result_summary += f" ({created_links} links)"
    scan.save(update_fields=["status", "result_summary"])

    return JsonResponse({
        "status": "received",
        "scan_id": scan.id,
        "nodes_added": created_nodes,
    })

def shortest_paths(request, start_node_id=None):
    if start_node_id is None:
        start_node_id = request.POST.get("start_node_id") or request.GET.get("start_node_id")
    if not start_node_id:
        return JsonResponse({"error": "start_node_id is required"}, status=400)

    try:
        start_node_id = int(start_node_id)
    except (TypeError, ValueError):
        return JsonResponse({"error": "start_node_id must be an integer"}, status=400)

    nodes = Node.objects.all()
    links = Link.objects.all()
    distances = dijkstra(nodes, links, start_node_id)

    # Convert keys to strings or extract node info
    distances_serialized = {
        str(node_id): distance for node_id, distance in distances.items()
    }

    return JsonResponse(distances_serialized, encoder=DjangoJSONEncoder, safe=False)

def history(request):
    from .models import ScanVulnerability
    runs = ScanRun.objects.all().order_by('-timestamp')

    run_data = []
    for run in runs:
        vulns = ScanVulnerability.objects.filter(scan_run=run)
        run_data.append({
            "run": run,
            "vuln_count": vulns.count(),
        })

    return render(request, 'dashboard/history.html', {'runs': run_data})

def graph_data(request):
    scan_run_id = request.GET.get("scan_run_id")
    if scan_run_id:
        try:
            scan_run_id = int(scan_run_id)
        except ValueError:
            return JsonResponse({"error": "Invalid scan_run_id"}, status=400)

        nodes = (
            Node.objects.filter(scan_run_id=scan_run_id)
            .select_related('scan_run')
            .order_by('-scan_run__timestamp', '-id')
        )
        latest_ping_scan = ScanRun.objects.filter(id=scan_run_id).first()
    else:
        scan_window = now() - timedelta(hours=24)
        recent_scan_ids = list(
            ScanRun.objects.filter(nodes__isnull=False, timestamp__gte=scan_window)
            .order_by('-timestamp')
            .values_list('id', flat=True)
            .distinct()
        )

        nodes = Node.objects.none()
        if recent_scan_ids:
            nodes = (
                Node.objects.filter(scan_run_id__in=recent_scan_ids)
                .select_related('scan_run')
                .order_by('-scan_run__timestamp', '-id')
            )

        latest_ping_scan = ScanRun.objects.filter(scan_type="ping", nodes__isnull=False).order_by('-timestamp').first()

    ping_node_by_ip = {}
    if latest_ping_scan:
        for ping_node in Node.objects.filter(scan_run=latest_ping_scan):
            ping_node_by_ip[ping_node.ip_address] = ping_node.id

    elements = []
    nodes_by_id = {}
    ip_to_node_id = {}
    edge_ids = set()

    def add_node(node_id, label, ip=None, status=None, extra=None, node_db_id=None, path_id=None):
        if node_id in nodes_by_id:
            return
        data = {
            "id": node_id,
            "label": label,
        }
        if ip:
            data["ip"] = ip
        if status:
            data["status"] = status
        if node_db_id is not None:
            data["node_id"] = node_db_id
        if path_id is not None:
            data["path_id"] = path_id
        if extra:
            data.update(extra)
        nodes_by_id[node_id] = data

    def add_edge(edge_id, source, target, label, raw_weight=1.0, kind=None):
        if edge_id in edge_ids:
            return
        data = {
            "id": edge_id,
            "source": source,
            "target": target,
            "weight": label,
            "raw_weight": raw_weight,
        }
        if kind:
            data["kind"] = kind
        elements.append({"data": data})
        edge_ids.add(edge_id)

    # Online agents for metadata + optional node enrichment
    agents = AgentStatus.objects.filter(status="online")
    agents_by_ip = {a.ip_address: a for a in agents if a.ip_address}

    # Scan nodes (dedupe by IP; keep most recent per IP)
    for node in nodes:
        if node.ip_address in ip_to_node_id:
            continue
        cyber_data = node.get_cyber_template_data()
        node_id = str(node.id)

        agent = agents_by_ip.get(node.ip_address)
        extra = {
            "cyber_data": cyber_data,
            "has_cyber_data": any(cyber_data.values()),
        }
        if agent:
            extra.update({
                "type": "agent",
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "os_type": agent.os_type,
            })

        path_id = ping_node_by_ip.get(node.ip_address)
        add_node(
            node_id=node_id,
            label=node.name,
            ip=node.ip_address,
            status=node.status,
            extra=extra,
            node_db_id=node.id,
            path_id=path_id,
        )
        ip_to_node_id[node.ip_address] = node_id

    # Agent nodes (only if not already represented by scan nodes)
    for agent in agents:
        if agent.ip_address and agent.ip_address in ip_to_node_id:
            continue
        agent_node = None
        try:
            agent_node = Node.objects.filter(agent_id=agent.agent_id).first()
        except Exception:
            agent_node = None
        agent_node_id = f"agent:{agent.agent_id}"
        add_node(
            node_id=agent_node_id,
            label=agent.hostname,
            ip=agent.ip_address,
            status=agent.status,
            extra={
                "type": "agent",
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "os_type": agent.os_type,
                "last_heartbeat": agent.last_heartbeat.strftime("%Y-%m-%d %H:%M:%S") if agent.last_heartbeat else "Never",
            },
            node_db_id=agent_node.id if agent_node else None,
            path_id=ping_node_by_ip.get(agent.ip_address),
        )
        if agent.ip_address:
            ip_to_node_id.setdefault(agent.ip_address, agent_node_id)

    # Scan links from latest ping scan (best for latency graph)
    if latest_ping_scan:
        ping_links = Link.objects.filter(scan_run=latest_ping_scan).select_related("source", "destination")
        for link in ping_links:
            src_ip = link.source.ip_address
            dst_ip = link.destination.ip_address
            src_id = ip_to_node_id.get(src_ip, str(link.source.id))
            dst_id = ip_to_node_id.get(dst_ip, str(link.destination.id))
            if src_id not in nodes_by_id:
                add_node(
                    node_id=src_id,
                    label=src_ip,
                    ip=src_ip,
                    status="unknown",
                    node_db_id=link.source.id,
                    path_id=link.source.id,
                )
                ip_to_node_id[src_ip] = src_id
            if dst_id not in nodes_by_id:
                add_node(
                    node_id=dst_id,
                    label=dst_ip,
                    ip=dst_ip,
                    status="unknown",
                    node_db_id=link.destination.id,
                    path_id=link.destination.id,
                )
                ip_to_node_id[dst_ip] = dst_id
            add_edge(
                edge_id=f"scan:{link.id}",
                source=src_id,
                target=dst_id,
                label=f"{link.weight:.2f}",
                raw_weight=link.weight,
                kind="scan",
            )

    # Network metadata connections (last hour)
    recent_connections = NetworkConnection.objects.filter(
        agent__status="online",
        last_seen__gte=now() - timedelta(hours=1),
    ).select_related("agent")

    flows = defaultdict(int)
    for conn in recent_connections:
        if not conn.remote_address or conn.remote_address in ["127.0.0.1", "localhost", "::1"]:
            continue

        src_id = f"agent:{conn.agent.agent_id}"
        dst_ip = conn.remote_address
        dst_id = ip_to_node_id.get(dst_ip)
        if not dst_id:
            dst_id = f"ip:{dst_ip}"
            add_node(
                node_id=dst_id,
                label=dst_ip,
                ip=dst_ip,
                status="unknown",
                extra={"type": "ip"},
            )
            ip_to_node_id[dst_ip] = dst_id

        flow_key = (src_id, dst_id, conn.protocol)
        flows[flow_key] += 1

    for (src_id, dst_id, protocol), count in flows.items():
        add_edge(
            edge_id=f"conn:{src_id}->{dst_id}:{protocol}",
            source=src_id,
            target=dst_id,
            label=f"{protocol} ({count})",
            raw_weight=1.0,
            kind="connection",
        )

    elements = [{"data": data} for data in nodes_by_id.values()] + elements
    return JsonResponse(elements, safe=False)


@require_GET
def node_details(request, node_id):
    """Detailed view for a specific node with cyber template data."""
    try:
        node = Node.objects.get(id=node_id)
    except Node.DoesNotExist:
        return JsonResponse({"error": "Node not found"}, status=404)

    # Get related agent status if available
    agent_status = None
    if node.agent_id:
        try:
            agent_status = AgentStatus.objects.get(agent_id=node.agent_id)
        except AgentStatus.DoesNotExist:
            pass

    node_data = {
        "id": node.id,
        "name": node.name,
        "ip_address": node.ip_address,
        "status": node.status,
        "description": node.description,
        "last_heartbeat": node.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if node.last_heartbeat else "Never",
        "agent_id": node.agent_id,
        "cyber_data": node.get_cyber_template_data(),
        "system_info": {
            "cpu_count": node.cpu_count,
            "memory_total": node.memory_total,
            "platform_info": node.platform_info,
        },
        "interfaces": [
            {
                "name": iface.name,
                "ip": iface.ip,
                "mac": iface.mac
            } for iface in node.interfaces.all()
        ],
        "agent_status": {
            "hostname": agent_status.hostname if agent_status else None,
            "os_type": agent_status.os_type if agent_status else None,
            "os_version": agent_status.os_version if agent_status else None,
            "status": agent_status.status if agent_status else None,
            "last_heartbeat": agent_status.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent_status and agent_status.last_heartbeat else None,
        } if agent_status else None
    }

    return JsonResponse(node_data)


@require_GET
def node_detail_page(request, node_id):
    """HTML page for node characteristics and composition."""
    try:
        node = Node.objects.get(id=node_id)
    except Node.DoesNotExist:
        messages.error(request, "Node not found")
        return redirect('dashboard:dashboard-home')

    agent_status = None
    if node.agent_id:
        try:
            agent_status = AgentStatus.objects.get(agent_id=node.agent_id)
        except AgentStatus.DoesNotExist:
            agent_status = None

    network_metadata = None
    if agent_status:
        network_metadata = NetworkMetadata.objects.filter(agent=agent_status).order_by('-timestamp').first()

    return render(request, 'dashboard/node_detail.html', {
        'node': node,
        'interfaces': node.interfaces.all(),
        'agent_status': agent_status,
        'network_metadata': network_metadata,
    })

def get_interfaces(request):
    return JsonResponse({'interfaces': list_interfaces()})

@csrf_exempt
@require_http_methods(["POST"])
def start_listener(request):
    iface = request.POST.get("interface")
    try:
        res = requests.post(f"{SNIFFER_BASE_URL}/start", json={"interface": iface})
        return JsonResponse(res.json(), status=res.status_code)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def stop_listener(request):
    try:
        res = requests.post(f"{SNIFFER_BASE_URL}/stop")
        return JsonResponse(res.json(), status=res.status_code)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@require_GET
def get_scan_history(request):
    recent = ScanRun.objects.all().order_by('-timestamp')[:10]
    history = [{
        "id": run.id,
        "timestamp": run.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "cidr": run.cidr,
        "status": run.status,
        "scan_type": run.scan_type,
        "task_id": run.task_id,
        "summary": run.result_summary or "-"
    } for run in recent]
    return JsonResponse({"history": history})

@csrf_exempt
@require_http_methods(["POST"])
def agent_report(request):
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    hostname = data.get("hostname")
    interfaces = data.get("interfaces", [])

    # Filter out loopback interface and localhost IPs
    external_interfaces = [
        iface for iface in interfaces
        if iface.get("ip") and
           not iface.get("ip", "").startswith("127.") and
           iface.get("ip", "") != "127.0.0.1" and
           iface.get("ip", "") != "localhost" and
           iface.get("ip", "") != "::1"
    ]

    # Use external interface IP, fallback to first interface, then fallback IP
    ip = (external_interfaces[0].get("ip")
          if external_interfaces
          else (interfaces[0].get("ip", "192.168.0.1") if interfaces else "192.168.0.1"))

    # Update or create AgentStatus record
    agent_status, created = AgentStatus.objects.update_or_create(
        agent_id=agent_id,
        defaults={
            "hostname": hostname,
            "ip_address": ip,
            "status": "online",
            "os_type": data.get("os", ""),
            "os_version": data.get("os_version", ""),
            "platform": data.get("platform", ""),
            "cpu_count": data.get("cpu_count"),
            "memory_total": data.get("memory_total"),
            "interfaces": interfaces,
            "processes": data.get("processes", []),
            "agent_version": data.get("agent_version", ""),
            "last_version_check": now(),
        }
    )

    # Record the heartbeat
    agent_status.record_heartbeat(data)

    # Also update/create Node record for backward compatibility
    node, _ = Node.objects.update_or_create(
        agent_id=agent_id,
        defaults={
            "name": hostname,
            "ip_address": ip,
            "description": f"Reported from agent {agent_id}",
            "status": "online",
            "cpu_count": data.get("cpu_count"),
            "memory_total": data.get("memory_total"),
            "platform_info": data.get("platform"),
        }
    )

    # Clear old interfaces
    node.interfaces.all().delete()

    # Save current interfaces
    for iface in interfaces:
        NodeInterface.objects.create(
            node=node,
            name=iface.get("name", "unknown"),
            ip=iface.get("ip", "0.0.0.0"),
            mac=iface.get("mac", "00:00:00:00:00:00")
        )

    return JsonResponse({"status": "ok", "node_id": node.id, "agent_status_id": agent_status.id})


@csrf_exempt
@require_http_methods(["POST"])
def agent_cyber_report(request):
    """Handle cyber template data from agents."""
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    cyber_data = data.get("cyber_data")

    if not agent_id or not cyber_data:
        return JsonResponse({"error": "agent_id and cyber_data are required"}, status=400)

    try:
        node = Node.objects.get(agent_id=agent_id)
        node.update_cyber_data(cyber_data)
        return JsonResponse({"status": "cyber_data_updated"})
    except Node.DoesNotExist:
        return JsonResponse({"error": "Node not found"}, status=404)

@csrf_exempt
@require_http_methods(["POST"])
def sbom_ingest(request):
    """Receive and store SBOM payloads from agents."""
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = request.headers.get("X-Agent-ID")
    if isinstance(data, dict):
        agent_id = agent_id or data.get("agent_id")
    if not agent_id:
        return JsonResponse({"error": "agent_id is required"}, status=400)

    payload = data.get("sbom") if isinstance(data, dict) and isinstance(data.get("sbom"), (dict, list)) else data

    packages = extract_packages_from_sbom(payload)
    os_summary = extract_os_summary_from_sbom(payload)
    format_info = detect_sbom_format(payload)
    payload_hash = compute_payload_hash(payload)
    vulnerabilities = extract_vulnerabilities_from_sbom(data) + extract_vulnerabilities_from_sbom(payload)
    if vulnerabilities:
        deduped = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue
            existing = deduped.get(cve_id)
            if not existing:
                deduped[cve_id] = vuln
                continue
            if (vuln.get("score") or 0) > (existing.get("score") or 0):
                deduped[cve_id] = vuln
        vulnerabilities = list(deduped.values())

    node = None
    try:
        node = Node.objects.get(agent_id=agent_id)
    except Node.DoesNotExist:
        node = None

    if node:
        updates = {"installed_libraries": packages[:200]}
        if os_summary:
            updates["os_info"] = os_summary
        for field, value in updates.items():
            setattr(node, field, value)
        node.save(update_fields=list(updates.keys()))

    report = SbomReport.objects.create(
        node=node,
        agent_id=agent_id,
        format=format_info["format"],
        bom_format=format_info["bom_format"],
        spec_version=format_info["spec_version"],
        document=payload,
        package_count=len(packages),
        os_summary=os_summary,
        sha256=payload_hash,
    )

    if node and vulnerabilities:
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id") or ""
            if not cve_id:
                continue
            vuln_obj, created = Vulnerability.objects.get_or_create(
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
            if not created:
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
            vuln_obj.nodes.add(node)

    return JsonResponse({
        "status": "sbom_received",
        "sbom_id": report.id,
        "package_count": report.package_count,
        "agent_id": agent_id,
    })


def _check_siem_token(request) -> bool:
    token = getattr(settings, "SIEM_INGEST_TOKEN", "")
    required = getattr(settings, "SIEM_INGEST_TOKEN_REQUIRED", True)
    if not required:
        return True
    if not token:
        return False
    header = request.headers.get("X-SIEM-Token") or request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        header = header.split(" ", 1)[1].strip()
    return header == token


def _check_agent_token(request) -> bool:
    token = getattr(settings, "AGENT_API_TOKEN", "")
    required = getattr(settings, "AGENT_API_TOKEN_REQUIRED", True)
    if not required:
        return True
    if not token:
        return False
    header = request.headers.get("X-Agent-Token") or request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        header = header.split(" ", 1)[1].strip()
    return header == token


def _persist_normalized_events(normalized):
    normalized = match_indicators(normalized)
    event_records = [
        {
            "timestamp": item.get("timestamp"),
            "source": item.get("source"),
            "event_type": item.get("event_type"),
            "severity": item.get("severity"),
            "asset_id": item.get("asset_id"),
            "asset_ip": item.get("asset_ip"),
            "summary": item.get("summary"),
            "raw": item.get("raw"),
        }
        for item in normalized
    ]
    created_events = SiemEvent.objects.bulk_create(
        [SiemEvent(**item) for item in event_records], batch_size=200
    )
    persist_ioc_matches(normalized, created_events)
    alerts = process_alerts_for_events(normalized)

    payload = {"ingested": len(normalized), "alerts": len(alerts)}
    try:
        payload["opensearch"] = bulk_index_events(normalized)
    except OpensearchError as exc:
        payload["opensearch_error"] = str(exc)
    return payload


@require_http_methods(["GET"])
def healthz(request):
    snapshot = health_snapshot()
    status_code = 200 if snapshot.get("status") == "ok" else 503
    return JsonResponse(snapshot, status=status_code)


@require_http_methods(["GET"])
def metrics(request):
    payload = metrics_payload()
    return HttpResponse(payload, content_type="text/plain; version=0.0.4")


@csrf_exempt
@require_http_methods(["POST"])
def siem_event_ingest(request):
    """Ingest SIEM events into the local event store."""
    if not _check_siem_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    events = payload if isinstance(payload, list) else [payload]
    max_batch = getattr(settings, "SIEM_MAX_INGEST_BATCH", 500)
    max_batch = apply_profile_max_batch(max_batch)
    if len(events) > max_batch:
        return JsonResponse({"error": f"Batch too large (max {max_batch})"}, status=413)

    normalized = []
    errors = []
    for idx, event in enumerate(events):
        try:
            normalized.append(normalize_siem_event(event))
        except SiemNormalizeError as exc:
            errors.append({"index": idx, "error": str(exc)})

    if errors:
        return JsonResponse({"error": "Invalid event payload", "details": errors}, status=400)

    response_payload = _persist_normalized_events(normalized)
    return JsonResponse(response_payload, status=201)


@csrf_exempt
@require_http_methods(["POST"])
def siem_pipeline_ingest(request):
    """Ingest raw pipeline events, normalize, and store in the SIEM log store."""
    if not _check_siem_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    raw_events = payload if isinstance(payload, list) else [payload]
    max_batch = getattr(settings, "SIEM_MAX_INGEST_BATCH", 500)
    max_batch = apply_profile_max_batch(max_batch)
    if len(raw_events) > max_batch:
        return JsonResponse({"error": f"Batch too large (max {max_batch})"}, status=413)

    try:
        transformed = transform_pipeline_events(raw_events)
    except SiemPipelineError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    normalized = []
    errors = []
    for idx, event in enumerate(transformed):
        try:
            normalized.append(normalize_siem_event(event))
        except SiemNormalizeError as exc:
            errors.append({"index": idx, "error": str(exc)})

    if errors:
        return JsonResponse({"error": "Invalid event payload", "details": errors}, status=400)

    response_payload = _persist_normalized_events(normalized)
    return JsonResponse(response_payload, status=201)


@require_http_methods(["GET"])
def siem_event_search(request):
    """Search SIEM events by time range, filters, and aggregations."""
    try:
        params = parse_search_request(request.GET)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    payload = search_siem_events(params)
    return JsonResponse(payload)


@require_http_methods(["GET"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_export", resource_type="siem_event")
def siem_export(request):
    """Export SIEM events for research reproducibility."""
    fmt = (request.GET.get("format") or "ndjson").lower()
    start = request.GET.get("start")
    end = request.GET.get("end")
    schema_version = request.GET.get("schema_version") or EXPORT_SCHEMA_VERSION

    qs = build_event_queryset(start, end).order_by("timestamp")
    filename_suffix = "ndjson" if fmt == "ndjson" else fmt
    filename = f"siem_export_{timezone.now():%Y%m%d_%H%M%S}.{filename_suffix}"

    if fmt == "parquet":
        try:
            payload = export_parquet_bytes(qs, schema_version)
        except RuntimeError as exc:
            return JsonResponse({"error": str(exc)}, status=400)
        response = HttpResponse(payload, content_type="application/parquet")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        record_siem_audit(
            request,
            action="siem_export",
            resource_type="siem_event",
            metadata={"format": fmt, "schema_version": schema_version},
        )
        return response

    response = StreamingHttpResponse(
        ndjson_stream(qs.iterator(), schema_version),
        content_type="application/x-ndjson",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    record_siem_audit(
        request,
        action="siem_export",
        resource_type="siem_event",
        metadata={"format": "ndjson", "schema_version": schema_version},
    )
    return response


@require_http_methods(["GET"])
def siem_event_explorer(request):
    """Render the SIEM Event Explorer UI."""
    now_ts = timezone.now()
    since = now_ts - timedelta(hours=24)

    recent_qs = SiemEvent.objects.filter(timestamp__gte=since)
    summary = {
        "total_24h": recent_qs.count(),
        "sources_24h": recent_qs.values("source").distinct().count(),
        "types_24h": recent_qs.values("event_type").distinct().count(),
    }

    top_sources = list(
        recent_qs.values("source").annotate(count=Count("id")).order_by("-count")[:5]
    )
    top_types = list(
        recent_qs.values("event_type").annotate(count=Count("id")).order_by("-count")[:5]
    )

    events = list(SiemEvent.objects.all()[:50])
    health = health_snapshot()
    context = {
        "summary": summary,
        "top_sources": top_sources,
        "top_types": top_types,
        "events": events,
        "health": health,
        "default_start": timezone.localtime(since).strftime("%Y-%m-%dT%H:%M"),
        "default_end": timezone.localtime(now_ts).strftime("%Y-%m-%dT%H:%M"),
    }
    return render(request, "dashboard/siem_events.html", context)


@require_http_methods(["GET"])
def siem_adapter_agent(request, agent_id):
    agent = get_object_or_404(AgentStatus, agent_id=agent_id)
    payload = adapt_agent_status(agent)
    return JsonResponse(payload, json_dumps_params={"indent": 2})


@require_http_methods(["GET"])
def siem_adapter_scan(request, scan_id):
    scan = get_object_or_404(ScanRun, id=scan_id)
    payload = adapt_scan_run(scan)
    return JsonResponse(payload, json_dumps_params={"indent": 2})


@require_http_methods(["GET"])
def siem_adapter_vulnerability(request, vuln_id):
    vuln = get_object_or_404(Vulnerability, id=vuln_id)
    node_id = request.GET.get("node_id")
    node = None
    if node_id:
        node = Node.objects.filter(id=node_id).first()
    payload = adapt_vulnerability(vuln, node=node)
    return JsonResponse(payload, json_dumps_params={"indent": 2})


@require_http_methods(["GET"])
def siem_adapter_sbom(request, sbom_id):
    report = get_object_or_404(SbomReport, id=sbom_id)
    payload = adapt_sbom_report(report)
    return JsonResponse(payload, json_dumps_params={"indent": 2})


@require_http_methods(["GET"])
def siem_pivot_lookup(request):
    asset_ip = request.GET.get("asset_ip")
    asset_id = request.GET.get("asset_id")
    if not asset_ip and not asset_id:
        return JsonResponse({"error": "asset_ip or asset_id is required"}, status=400)

    result = resolve_siem_pivot(asset_ip, asset_id)
    if not result:
        return JsonResponse({"found": False})

    return JsonResponse({"found": True, **result})


@require_http_methods(["GET"])
def siem_alerts_page(request):
    status = request.GET.get("status", "open")
    alerts = Alert.objects.filter(status=status).order_by("-last_seen")[:200]
    rules = AlertRule.objects.all().order_by("name")
    return render(request, "dashboard/siem_alerts.html", {"alerts": alerts, "rules": rules, "status": status})


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_rule_toggle", resource_type="alert_rule")
def siem_toggle_rule(request, rule_id):
    rule = get_object_or_404(AlertRule, id=rule_id)
    rule.enabled = not rule.enabled
    rule.save(update_fields=["enabled"])
    record_siem_audit(
        request,
        action="siem_rule_toggle",
        resource_type="alert_rule",
        resource_id=rule.id,
        metadata={"enabled": rule.enabled},
    )
    return redirect(request.META.get("HTTP_REFERER", reverse("dashboard:siem_alerts_page")))


@require_http_methods(["GET"])
def siem_cases_page(request):
    status = request.GET.get("status", "open")
    cases = Case.objects.filter(status=status).order_by("-updated_at")[:200]
    return render(request, "dashboard/siem_cases.html", {"cases": cases, "status": status})


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_case_create", resource_type="case")
def siem_case_create(request):
    title = request.POST.get("title") or "New Case"
    description = request.POST.get("description", "")
    priority = request.POST.get("priority") or Case.Priority.MEDIUM
    case = Case.objects.create(
        title=title,
        description=description,
        priority=priority,
        status=Case.Status.OPEN,
        created_by=request.user if request.user.is_authenticated else None,
    )
    record_siem_audit(
        request,
        action="siem_case_create",
        resource_type="case",
        resource_id=case.id,
        metadata={"priority": priority},
    )
    return redirect(reverse("dashboard:siem_case_detail", args=[case.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_case_promote_alert", resource_type="case")
def siem_case_promote_alert(request, alert_id):
    alert = get_object_or_404(Alert, id=alert_id)
    case = build_case_from_alert(alert)
    case.created_by = request.user if request.user.is_authenticated else None
    case.save()
    case.alerts.add(alert)
    record_siem_audit(
        request,
        action="siem_case_promote_alert",
        resource_type="case",
        resource_id=case.id,
        metadata={"alert_id": alert.id},
    )
    return redirect(reverse("dashboard:siem_case_detail", args=[case.id]))


@require_http_methods(["GET"])
def siem_case_detail(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    return render(request, "dashboard/siem_case_detail.html", {"case": case})


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_case_update_status", resource_type="case")
def siem_case_update_status(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    status = request.POST.get("status") or Case.Status.OPEN
    case.status = status
    if status == Case.Status.CLOSED and not case.closed_at:
        case.closed_at = timezone.now()
    if status == Case.Status.OPEN:
        case.closed_at = None
    case.save(update_fields=["status", "closed_at"])
    record_siem_audit(
        request,
        action="siem_case_update_status",
        resource_type="case",
        resource_id=case.id,
        metadata={"status": status},
    )
    return redirect(reverse("dashboard:siem_case_detail", args=[case.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_case_add_note", resource_type="case_note")
def siem_case_add_note(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    note_text = request.POST.get("note")
    if note_text:
        note = CaseNote.objects.create(
            case=case,
            author=request.user if request.user.is_authenticated else None,
            note=note_text,
        )
        record_siem_audit(
            request,
            action="siem_case_add_note",
            resource_type="case_note",
            resource_id=note.id,
            metadata={"case_id": case.id},
        )
    return redirect(reverse("dashboard:siem_case_detail", args=[case.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_case_add_evidence", resource_type="case_evidence")
def siem_case_add_evidence(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    label = request.POST.get("label") or "Evidence"
    evidence_type = request.POST.get("evidence_type") or CaseEvidence.EvidenceType.TEXT
    details = request.POST.get("details", "")
    evidence = CaseEvidence.objects.create(
        case=case,
        label=label,
        evidence_type=evidence_type,
        details=details,
    )
    record_siem_audit(
        request,
        action="siem_case_add_evidence",
        resource_type="case_evidence",
        resource_id=evidence.id,
        metadata={"case_id": case.id, "evidence_type": evidence_type},
    )
    return redirect(reverse("dashboard:siem_case_detail", args=[case.id]))


@require_http_methods(["GET"])
def siem_case_export(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    payload = export_case_payload(case)
    response = JsonResponse(payload, json_dumps_params={"indent": 2})
    response["Content-Disposition"] = f'attachment; filename="case_{case.id}.json"'
    return response


@require_http_methods(["GET"])
def siem_hunts_page(request):
    status = request.GET.get("status", "open")
    hunts = Hunt.objects.filter(status=status).order_by("-updated_at")[:200]
    return render(request, "dashboard/siem_hunts.html", {"hunts": hunts, "status": status})


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_hunt_create", resource_type="hunt")
def siem_hunt_create(request):
    name = request.POST.get("name") or "New Hunt"
    description = request.POST.get("description", "")
    tags = parse_hunt_tags(request.POST.get("tags", ""))

    base_name = name
    counter = 1
    while Hunt.objects.filter(name=name).exists():
        counter += 1
        name = f"{base_name} ({counter})"

    hunt = Hunt.objects.create(
        name=name,
        description=description,
        status=Hunt.Status.OPEN,
        created_by=request.user if request.user.is_authenticated else None,
    )
    for tag in tags:
        HuntTag.objects.get_or_create(hunt=hunt, name=tag)
    record_siem_audit(
        request,
        action="siem_hunt_create",
        resource_type="hunt",
        resource_id=hunt.id,
        metadata={"tags": tags},
    )
    return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))


@require_http_methods(["GET"])
def siem_hunt_detail(request, hunt_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    return render(request, "dashboard/siem_hunt_detail.html", {"hunt": hunt})


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_hunt_update_status", resource_type="hunt")
def siem_hunt_update_status(request, hunt_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    status = request.POST.get("status") or Hunt.Status.OPEN
    hunt.status = status
    hunt.save(update_fields=["status"])
    record_siem_audit(
        request,
        action="siem_hunt_update_status",
        resource_type="hunt",
        resource_id=hunt.id,
        metadata={"status": status},
    )
    return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_hunt_add_note", resource_type="hunt_note")
def siem_hunt_add_note(request, hunt_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    note_text = request.POST.get("note")
    if note_text:
        note = HuntNote.objects.create(
            hunt=hunt,
            author=request.user if request.user.is_authenticated else None,
            title=request.POST.get("title", ""),
            note=note_text,
        )
        record_siem_audit(
            request,
            action="siem_hunt_add_note",
            resource_type="hunt_note",
            resource_id=note.id,
            metadata={"hunt_id": hunt.id},
        )
    return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_hunt_add_tag", resource_type="hunt_tag")
def siem_hunt_add_tag(request, hunt_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    tags = parse_hunt_tags(request.POST.get("tags", ""))
    for tag in tags:
        HuntTag.objects.get_or_create(hunt=hunt, name=tag)
    if tags:
        record_siem_audit(
            request,
            action="siem_hunt_add_tag",
            resource_type="hunt_tag",
            resource_id=hunt.id,
            metadata={"tags": tags},
        )
    return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_hunt_add_search", resource_type="hunt_search")
def siem_hunt_add_search(request, hunt_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    search_name = request.POST.get("search_name") or "Saved Search"
    query_params = build_query_payload_from_form(request.POST)
    try:
        validate_hunt_query(query_params)
    except ValueError as exc:
        messages.error(request, f"Invalid search params: {exc}")
        return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))

    search = HuntSearch.objects.create(
        hunt=hunt,
        name=search_name,
        query_params=clean_query_params(query_params),
    )
    record_siem_audit(
        request,
        action="siem_hunt_add_search",
        resource_type="hunt_search",
        resource_id=search.id,
        metadata={"hunt_id": hunt.id},
    )
    return redirect(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))


@require_http_methods(["GET"])
def siem_hunt_replay_search(request, hunt_id, search_id):
    hunt = get_object_or_404(Hunt, id=hunt_id)
    search = get_object_or_404(HuntSearch, id=search_id, hunt=hunt)
    payload = replay_hunt_search(search.query_params)
    return JsonResponse({"hunt_id": hunt.id, "search_id": search.id, **payload})


@require_http_methods(["GET"])
@require_siem_role(SIEM_ADMIN_ROLES, action="siem_audit_view", resource_type="audit_log")
def siem_audit_log(request):
    qs = SiemAuditLog.objects.all()
    action = request.GET.get("action")
    status = request.GET.get("status")
    if action:
        qs = qs.filter(action=action)
    if status:
        qs = qs.filter(status=status)

    if request.GET.get("format") == "json":
        payload = [
            {
                "id": entry.id,
                "timestamp": entry.created_at.isoformat(),
                "actor_id": entry.actor_id,
                "role": entry.role,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "status": entry.status,
                "ip_address": entry.ip_address,
                "metadata": entry.metadata or {},
            }
            for entry in qs[:500]
        ]
        return JsonResponse({"count": qs.count(), "results": payload})

    return render(request, "dashboard/siem_audit.html", {"entries": qs[:200], "action": action, "status": status})


@require_http_methods(["GET"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_research_profiles_view", resource_type="research_profile")
def siem_research_profiles_page(request):
    profiles = ResearchProfile.objects.all().order_by("-updated_at")
    active = profiles.filter(active=True).first()
    return render(
        request,
        "dashboard/siem_research_profiles.html",
        {"profiles": profiles, "active": active},
    )


@require_http_methods(["POST"])
@require_siem_role(SIEM_WRITE_ROLES, action="siem_research_profile_activate", resource_type="research_profile")
def siem_research_profile_activate(request, profile_id):
    profile = get_object_or_404(ResearchProfile, id=profile_id)
    activate_profile(profile)
    record_siem_audit(
        request,
        action="siem_research_profile_activate",
        resource_type="research_profile",
        resource_id=profile.id,
        metadata={
            "name": profile.name,
            "version": profile.version,
            "pipeline_version": profile.pipeline_version,
            "ruleset_version": profile.ruleset_version,
            "retention_days": profile.retention_days,
        },
    )
    return redirect(reverse("dashboard:siem_research_profiles_page"))


@csrf_exempt
@require_http_methods(["POST"])
def siem_threat_intel_ingest(request):
    """Ingest threat intel indicators from a MISP-like payload or list."""
    token_ok = _check_siem_token(request)
    if not token_ok:
        role = get_siem_role(request.user)
        if role not in SIEM_WRITE_ROLES:
            record_siem_audit(
                request,
                action="siem_threat_intel_ingest",
                resource_type="threat_intel",
                status="denied",
                metadata={"role": role},
            )
            return JsonResponse({"error": "Forbidden"}, status=403)

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    stats = ingest_indicators(payload)
    record_siem_audit(
        request,
        action="siem_threat_intel_ingest",
        resource_type="threat_intel",
        metadata={"ingested": stats, "token_auth": token_ok},
    )
    return JsonResponse({"ingested": stats})


@require_http_methods(["GET"])
def siem_threat_intel_list(request):
    indicator_type = request.GET.get("type")
    active = request.GET.get("active")
    qs = ThreatIntelIndicator.objects.all()
    if indicator_type:
        qs = qs.filter(indicator_type=indicator_type)
    if active in ("0", "1"):
        qs = qs.filter(active=active == "1")
    indicators = [
        {
            "id": i.id,
            "type": i.indicator_type,
            "value": i.value,
            "source": i.source,
            "confidence": i.confidence,
            "tlp": i.tlp,
            "active": i.active,
        }
        for i in qs.order_by("-updated_at")[:500]
    ]
    return JsonResponse({"count": len(indicators), "results": indicators})


@csrf_exempt
@require_http_methods(["POST"])
def siem_syslog_ingest(request):
    """Ingest syslog lines and forward to SIEM pipeline."""
    if not _check_siem_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)

    body = (request.body or b"").decode("utf-8", errors="ignore")
    lines = [line for line in body.splitlines() if line.strip()]
    events = [syslog_to_event(line) for line in lines]
    if not events:
        return JsonResponse({"error": "No syslog messages provided"}, status=400)

    normalized = [normalize_siem_event(event) for event in events]
    response_payload = _persist_normalized_events(normalized)
    return JsonResponse(response_payload, status=201)


@csrf_exempt
@require_http_methods(["POST"])
def siem_windows_ingest(request):
    """Ingest Windows Event Log payloads (JSON) and forward to SIEM pipeline."""
    if not _check_siem_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    items = payload if isinstance(payload, list) else [payload]
    events = [windows_event_to_event(item) for item in items if isinstance(item, dict)]
    if not events:
        return JsonResponse({"error": "No events provided"}, status=400)

    normalized = [normalize_siem_event(event) for event in events]
    response_payload = _persist_normalized_events(normalized)
    return JsonResponse(response_payload, status=201)


@require_GET
def agent_sbom_export(request, agent_id):
    fmt = (request.GET.get("format") or "json").lower()
    report = SbomReport.objects.filter(agent_id=agent_id).order_by("-created_at").first()
    if not report:
        return JsonResponse({"error": "SBOM not found"}, status=404)

    if fmt == "csv":
        packages = extract_packages_from_sbom(report.document)
        filename = f"sbom_{agent_id}_{report.created_at:%Y%m%d_%H%M%S}.csv"
        lines = ["package"]
        lines.extend(packages)
        response = HttpResponse("\n".join(lines), content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    data = {
        "agent_id": report.agent_id,
        "created_at": report.created_at.isoformat(),
        "format": report.format,
        "bom_format": report.bom_format,
        "spec_version": report.spec_version,
        "package_count": report.package_count,
        "os_summary": report.os_summary,
        "document": report.document,
    }
    return JsonResponse(data, json_dumps_params={"indent": 2})


@require_GET
def agent_sbom_diff(request, agent_id):
    reports = list(SbomReport.objects.filter(agent_id=agent_id).order_by("-created_at")[:2])
    if len(reports) < 2:
        return JsonResponse({"error": "Not enough SBOM reports to diff"}, status=400)

    newest, previous = reports[0], reports[1]
    newest_pkgs = set(extract_packages_from_sbom(newest.document))
    previous_pkgs = set(extract_packages_from_sbom(previous.document))

    added = sorted(newest_pkgs - previous_pkgs)
    removed = sorted(previous_pkgs - newest_pkgs)
    unchanged = sorted(newest_pkgs & previous_pkgs)

    return JsonResponse({
        "agent_id": agent_id,
        "from_report_id": previous.id,
        "to_report_id": newest.id,
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged_count": len(unchanged),
    })


@require_GET
def agent_sbom_bundle(request, agent_id):
    reports = list(SbomReport.objects.filter(agent_id=agent_id).order_by("-created_at")[:2])
    if not reports:
        return JsonResponse({"error": "SBOM not found"}, status=404)

    latest = reports[0]
    packages = extract_packages_from_sbom(latest.document)
    csv_lines = ["package"]
    csv_lines.extend(packages)

    diff_payload = {}
    if len(reports) >= 2:
        previous = reports[1]
        newest_pkgs = set(extract_packages_from_sbom(latest.document))
        previous_pkgs = set(extract_packages_from_sbom(previous.document))
        diff_payload = {
            "agent_id": agent_id,
            "from_report_id": previous.id,
            "to_report_id": latest.id,
            "added": sorted(newest_pkgs - previous_pkgs),
            "removed": sorted(previous_pkgs - newest_pkgs),
            "unchanged": sorted(newest_pkgs & previous_pkgs),
        }
    else:
        diff_payload = {
            "agent_id": agent_id,
            "error": "Not enough SBOM reports to diff",
        }

    import io
    import zipfile

    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("sbom.json", json.dumps({
            "agent_id": latest.agent_id,
            "created_at": latest.created_at.isoformat(),
            "format": latest.format,
            "bom_format": latest.bom_format,
            "spec_version": latest.spec_version,
            "package_count": latest.package_count,
            "os_summary": latest.os_summary,
            "document": latest.document,
        }, indent=2))
        zip_file.writestr("sbom.csv", "\n".join(csv_lines))
        zip_file.writestr("diff.json", json.dumps(diff_payload, indent=2))

    bundle.seek(0)
    filename = f"sbom_bundle_{agent_id}_{latest.created_at:%Y%m%d_%H%M%S}.zip"
    response = FileResponse(bundle, as_attachment=True, filename=filename)
    response["Content-Type"] = "application/zip"
    return response

@require_http_methods(["GET"])
def agent_commands(request):
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    agent_id = request.GET.get("agent_id")
    commands = AgentCommand.objects.filter(agent_id=agent_id, acknowledged=False)
    serialized = [
        {"id": cmd.id, "action": cmd.action, "parameters": cmd.parameters}
        for cmd in commands
    ]
    # mark them as acknowledged
    commands.update(acknowledged=True)
    return JsonResponse({"commands": serialized})


@csrf_exempt
@require_http_methods(["POST"])
def agent_command_result(request):
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    data = json.loads(request.body)
    agent_id = data.get("agent_id")
    command_id = data.get("command_id")
    output = data.get("output")

    try:
        cmd = AgentCommand.objects.get(id=command_id)
    except AgentCommand.DoesNotExist:
        return JsonResponse({"error": "Command not found"}, status=404)

    CommandResult.objects.create(
        agent_id=agent_id,
        command=cmd,
        output=output
    )

    if cmd.action == "sliver_deploy":
        try:
            from sliver.models import ImplantArtifact
            from sliver.utils import log_audit_action

            artifact_id = None
            if isinstance(cmd.parameters, dict):
                artifact_id = cmd.parameters.get("artifact_id")
            artifact = None
            if artifact_id:
                artifact = ImplantArtifact.objects.select_related('engagement__teamserver').filter(id=artifact_id).first()

            if artifact and artifact.engagement and artifact.engagement.teamserver:
                normalized = (output or "").lower()
                if "executed pid=" in normalized:
                    action = "IMPLANT_EXECUTED"
                elif "failed" in normalized:
                    action = "IMPLANT_DEPLOY_FAILED"
                else:
                    action = "IMPLANT_DELIVERED"

                log_audit_action(
                    action=action,
                    user=None,
                    teamserver=artifact.engagement.teamserver,
                    engagement=artifact.engagement,
                    details={
                        "artifact_id": artifact.id,
                        "artifact_name": artifact.name,
                        "agent_id": agent_id,
                        "output": output,
                    }
                )
        except Exception:
            pass

    return JsonResponse({"status": "received"})


# -----------------------------
# Agent Monitoring Views
# -----------------------------
def agent_monitoring(request):
    """Main agent monitoring dashboard."""
    agents = AgentStatus.objects.all().order_by('-last_heartbeat')

    # Update status for all agents based on heartbeat timing
    for agent in agents:
        agent.update_status()

    # Get recent command results
    recent_results = CommandResult.objects.all().order_by('-timestamp')[:20]

    # Get pending commands
    pending_commands = AgentCommand.objects.filter(acknowledged=False).order_by('-created')[:10]

    return render(request, 'dashboard/agent_monitoring.html', {
        'agents': agents,
        'recent_results': recent_results,
        'pending_commands': pending_commands,
        'total_agents': agents.count(),
        'online_agents': agents.filter(status='online').count(),
        'offline_agents': agents.filter(status='offline').count(),
    })


@require_GET
def agent_status_api(request):
    """API endpoint for real-time agent status updates."""
    agents = AgentStatus.objects.all().order_by('-last_heartbeat')

    # Update status for all agents
    for agent in agents:
        agent.update_status()

    agent_data = []
    for agent in agents:
        agent_data.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "status": agent.status,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "cpu_count": agent.cpu_count,
            "memory_total": agent.memory_total,
            "agent_version": agent.agent_version or "Unknown",
            "last_heartbeat": agent.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent.last_heartbeat else "Never",
            "uptime": str(agent.get_uptime()) if agent.get_uptime() else "Unknown",
            "consecutive_failures": agent.consecutive_failures,
            "interfaces": agent.interfaces or [],
        })

    return JsonResponse({
        "agents": agent_data,
        "timestamp": now().strftime('%Y-%m-%d %H:%M:%S')
    })


@csrf_exempt
@require_http_methods(["POST"])
def send_agent_command(request):
    """Send a command to a specific agent."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    action = data.get("action")
    parameters = data.get("parameters", {})

    if not agent_id or not action:
        return JsonResponse({"error": "agent_id and action are required"}, status=400)

    if agent_id == "all":
        agents = list(AgentStatus.objects.all())
        if not agents:
            return JsonResponse({"error": "No agents available"}, status=404)

        commands = [
            AgentCommand.objects.create(agent_id=agent.agent_id, action=action, parameters=parameters)
            for agent in agents
        ]
        AgentStatus.objects.filter(agent_id__in=[a.agent_id for a in agents]).update(last_command_sent=now())

        return JsonResponse({
            "status": "command_sent",
            "command_ids": [cmd.id for cmd in commands],
            "agent_id": agent_id,
            "action": action,
            "count": len(commands),
        })

    # Check if agent exists
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    # Create command
    command = AgentCommand.objects.create(
        agent_id=agent_id,
        action=action,
        parameters=parameters
    )

    # Update agent's last_command_sent timestamp
    agent.last_command_sent = now()
    agent.save(update_fields=["last_command_sent"])

    return JsonResponse({
        "status": "command_sent",
        "command_id": command.id,
        "agent_id": agent_id,
        "action": action
    })


@require_GET
def agent_details(request, agent_id):
    """Detailed view for a specific agent."""
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
        agent.update_status()  # Update status before displaying
    except AgentStatus.DoesNotExist:
        messages.error(request, f"Agent {agent_id} not found")
        return redirect('dashboard:agent_monitoring')

    # Get associated Node for cyber template data (if it exists)
    node = None
    try:
        node = Node.objects.get(agent_id=agent_id)
    except Node.DoesNotExist:
        pass  # Some agents might not have sent cyber reports yet

    # Get command history for this agent
    commands = AgentCommand.objects.filter(agent_id=agent_id).order_by('-created')[:20]
    results = CommandResult.objects.filter(agent_id=agent_id).order_by('-timestamp')[:20]
    sbom_reports = SbomReport.objects.filter(agent_id=agent_id).order_by('-created_at')[:5]

    # Sliver artifacts for quick deployment (if available)
    try:
        from sliver.models import ImplantArtifact
        sliver_artifacts = ImplantArtifact.objects.filter(
            status='READY'
        ).order_by('-created_at')[:50]
    except Exception:
        sliver_artifacts = []

    return render(request, 'dashboard/agent_details.html', {
        'agent': agent,
        'node': node,
        'commands': commands,
        'results': results,
        'sbom_reports': sbom_reports,
        'sliver_artifacts': sliver_artifacts,
    })


@require_GET
def agent_command_history(request, agent_id):
    """Get command history for a specific agent."""
    commands = AgentCommand.objects.filter(agent_id=agent_id).order_by('-created')[:50]
    results = CommandResult.objects.filter(agent_id=agent_id).order_by('-timestamp')[:50]

    history = []
    for cmd in commands:
        history.append({
            "type": "command",
            "id": cmd.id,
            "action": cmd.action,
            "parameters": cmd.parameters,
            "created": cmd.created.strftime('%Y-%m-%d %H:%M:%S'),
            "acknowledged": cmd.acknowledged,
        })

    for result in results:
        history.append({
            "type": "result",
            "id": result.id,
            "command_id": result.command.id,
            "output": result.output[:200] + "..." if len(result.output) > 200 else result.output,
            "timestamp": result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        })

    # Sort by timestamp
    history.sort(key=lambda x: x.get('created') or x.get('timestamp'), reverse=True)

    return JsonResponse({"history": history[:50]})


@require_GET
def agent_analysis(request, agent_id):
    """Analysis view for aggregated node data from a specific agent."""
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
        agent.update_status()
    except AgentStatus.DoesNotExist:
        messages.error(request, f"Agent {agent_id} not found")
        return redirect('dashboard:agent_monitoring')

    # Get associated Node for cyber template data
    node = None
    try:
        node = Node.objects.get(agent_id=agent_id)
    except Node.DoesNotExist:
        pass

    # ====================
    # SYSTEM INFO ANALYSIS
    # ====================
    system_info = {
        'cpu_count': agent.cpu_count,
        'memory_total': agent.memory_total,
        'os_type': agent.os_type,
        'os_version': agent.os_version,
        'platform': agent.platform,
        'agent_version': agent.agent_version,
    }

    # ====================
    # COMMAND HISTORY ANALYSIS
    # ====================
    total_commands = AgentCommand.objects.filter(agent_id=agent_id).count()
    total_command_results = CommandResult.objects.filter(agent_id=agent_id).count()

    # Command success/error analysis
    command_action_counts = defaultdict(int)
    recent_commands = AgentCommand.objects.filter(agent_id=agent_id).order_by('-created')[:50]

    for cmd in recent_commands:
        command_action_counts[cmd.action] += 1

    # ====================
    # NETWORK METADATA ANALYSIS
    # ====================
    network_metadata = NetworkMetadata.objects.filter(agent=agent).order_by('-timestamp')[:20]

    # Connection patterns analysis
    all_connections = NetworkConnection.objects.filter(agent=agent).order_by('-last_seen')[:100]

    connection_stats = {
        'total_connections': len(all_connections),
        'by_protocol': defaultdict(int),
        'by_status': defaultdict(int),
        'by_process': defaultdict(int),
        'external_connections': 0,
        'recent_connections': len([c for c in all_connections if c.last_seen and (now() - c.last_seen).seconds < 3600]),  # Last hour
    }

    # Analyze connections
    for conn in all_connections:
        connection_stats['by_protocol'][conn.protocol] += 1
        connection_stats['by_status'][conn.status] += 1
        if conn.process_name:
            connection_stats['by_process'][conn.process_name] += 1

        # Count external connections (not localhost)
        if conn.remote_address and conn.remote_address not in ['127.0.0.1', 'localhost', '::1']:
            connection_stats['external_connections'] += 1

    # Interface statistics over time
    interface_stats_over_time = []
    for metadata in network_metadata:
        if metadata.interface_statistics:
            for iface_stat in metadata.interface_statistics:
                interface_stats_over_time.append({
                    'timestamp': metadata.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'interface': iface_stat.get('interface', 'Unknown'),
                    'bytes_sent': iface_stat.get('bytes_sent', 0),
                    'bytes_recv': iface_stat.get('bytes_recv', 0),
                    'packets_sent': iface_stat.get('packets_sent', 0),
                    'packets_recv': iface_stat.get('packets_recv', 0),
                })

    # ====================
    # CYBER TEMPLATE ANALYSIS
    # ====================
    cyber_template_analysis = {}
    if node and node.installed_libraries:
        # Libraries analysis
        libraries = node.installed_libraries
        cyber_template_analysis['total_libraries'] = len(libraries)
        cyber_template_analysis['libraries'] = libraries[:20]  # First 20 for display

        # Categorize libraries by common patterns
        library_categories = defaultdict(int)
        for lib in libraries:
            lib_lower = lib.lower()
            if any(keyword in lib_lower for keyword in ['python', 'pip', 'setuptools']):
                library_categories['Python Packages'] += 1
            elif any(keyword in lib_lower for keyword in ['openssl', 'libssl', 'crypto']):
                library_categories['Cryptographic Libraries'] += 1
            elif any(keyword in lib_lower for keyword in ['systemd', 'dbus', 'udev']):
                library_categories['System Libraries'] += 1
            else:
                library_categories['Other'] += 1

        cyber_template_analysis['categories'] = dict(library_categories)

    # Ports analysis
    if node and node.active_ports:
        active_ports = node.active_ports
        cyber_template_analysis['total_ports'] = len(active_ports)
        cyber_template_analysis['ports'] = active_ports[:20]  # First 20 for display

        # Categorize ports
        port_categories = defaultdict(int)
        well_known_ports = {
            22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 25: 'SMTP',
            53: 'DNS', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis'
        }
        for port_info in active_ports:
            try:
                port_id = int(port_info.get('id', 0))
            except (ValueError, TypeError):
                port_id = 0

            if port_id in well_known_ports:
                port_categories[well_known_ports[port_id]] += 1
            elif port_id < 1024:
                port_categories['System (<1024)'] += 1
            elif port_id < 49152:
                port_categories['User (1024-49151)'] += 1
            else:
                port_categories['Dynamic (49152+)'] += 1

        cyber_template_analysis['port_categories'] = dict(port_categories)
    # ====================
    # HEARTBEAT/UPTIME ANALYSIS
    # ====================
    heartbeat_analysis = {
        'uptime': str(agent.get_uptime()) if agent.get_uptime() else "Unknown",
        'last_heartbeat': agent.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent.last_heartbeat else "Never",
        'consecutive_failures': agent.consecutive_failures,
        'heartbeat_interval': agent.heartbeat_interval,
    }

    # ====================
    # AGGREGATE SUMMARY
    # ====================
    summary_stats = {
        'total_commands_sent': total_commands,
        'total_command_results': total_command_results,
        'total_network_metadata_records': network_metadata.count(),
        'total_connections_tracked': connection_stats['total_connections'],
        'active_network_sessions': len([1 for conn in all_connections if conn.status == 'ESTABLISHED']),
        'has_cyber_data': bool(node and (node.installed_libraries or node.active_ports or node.mac_addresses)),
        'has_network_data': bool(network_metadata.exists()),
    }

    return render(request, 'dashboard/agent_analysis.html', {
        'agent': agent,
        'node': node,
        'system_info': system_info,
        'command_analysis': {
            'total_commands': total_commands,
            'total_results': total_command_results,
            'action_counts': dict(command_action_counts),
            'recent_commands': recent_commands[:10],  # Last 10 commands
        },
        'network_analysis': {
            'metadata_records': network_metadata,
            'connection_stats': connection_stats,
            'interface_stats_history': interface_stats_over_time[:20],  # Last 20 interface readings
        },
        'cyber_template_analysis': cyber_template_analysis,
        'heartbeat_analysis': heartbeat_analysis,
        'summary_stats': summary_stats,
    })


def vulnerability_detail(request, scan_id):
    scan = ScanRun.objects.get(id=scan_id)
    vulns = scan.vulnerabilities.all().order_by("-severity")
    return render(request, "dashboard/vulnerabilities.html", {
        "scan": scan,
        "vulnerabilities": vulns
    })

@csrf_exempt
@require_http_methods(["POST"])
def start_openvas_scan(request):
    print("***********start openvas scan")

    # get cidr from form field (your JS uses FormData on vuln-scan-form)
    cidr = request.POST.get("vuln_cidr") or request.POST.get("cidr")
    if not cidr:
        latest_scan = ScanRun.objects.order_by("-timestamp").first()
        if latest_scan:
            cidr = latest_scan.cidr
        else:
            return JsonResponse({"error": "cidr is required (e.g., 10.0.0.0/24) and no previous scans were found"}, status=400)

    # validate
    try:
        ip_network(cidr, strict=False)
    except ValueError:
        return JsonResponse({"error": f"invalid CIDR: {cidr}"}, status=400)

    config_name = request.POST.get("gvmd_config")
    try:
        with transaction.atomic():
            scan = ScanRun.objects.create(
                cidr=cidr,
                status=ScanRun.Status.IN_PROGRESS,
                scan_type="openvas",
            )
            async_result = launch_openvas_scan_task.delay(
                cidr=cidr,
                config_name=config_name,
                scan_id=scan.id,
            )
    except Exception as exc:
        return JsonResponse({"error": f"failed to launch OpenVAS scan: {exc}"}, status=500)

    return JsonResponse({"scan_id": scan.id, "task_id": async_result.id, "cidr": cidr}, status=202)

@require_GET
def vuln_scan_status(request, scan_id):
    try:
        scan = ScanRun.objects.get(id=scan_id)
    except ScanRun.DoesNotExist:
        return JsonResponse({"error": "scan_id not found"}, status=404)

    if not scan.openvas_task_id:
        return JsonResponse({"state": "LAUNCHING", "scan_status": scan.status})

    try:
        gmp = openvas_session()
        info = get_task_status(gmp, scan.openvas_task_id)
        state = info.get("status") or "UNKNOWN"
        progress = info.get("progress")
        report_id = info.get("report_id")

        if state == "Done" and scan.status != "COMPLETE":
            report_id = report_id or get_report_id(gmp, scan.openvas_task_id)
            report_xml = download_report(gmp, report_id)
            parse_and_save_vulnerabilities(report_xml, scan)
            scan.status = "COMPLETE"
            scan.result_summary = f"Scan complete. Report ID: {report_id}"
            scan.save(update_fields=["status", "result_summary"])

        return JsonResponse({
            "state": state,
            "progress": progress,
            "scan_status": scan.status,
            "report_id": report_id,
        })
    except Exception as exc:
        return JsonResponse({"state": "ERROR", "error": str(exc)}, status=500)


# -----------------------------
# Agent Download and Distribution
# -----------------------------
@require_GET
def agent_download_page(request):
    """Page for downloading the host agent software."""
    from host_agent.agent import AGENT_VERSION, AGENT_NAME
    from django.urls import reverse

    # Get the latest agent information
    latest_agents = AgentStatus.objects.filter(
        agent_version__isnull=False
    ).order_by('-last_version_check')[:5]

    return render(request, 'dashboard/agent_download.html', {
        'agent_version': AGENT_VERSION,
        'agent_name': AGENT_NAME,
        'latest_agents': latest_agents,
        'download_url': reverse("download_host_agent")
    })


@require_http_methods(["GET", "HEAD"])
def download_host_agent(request):
    """Download the host agent as a ZIP file using FileResponse for efficient streaming."""
    import zipfile
    import tempfile
    import shutil

    print(f"[DEBUG] Download request from {request.META.get('REMOTE_ADDR', 'unknown')}")

    # Define a temporary directory for ZIP files (or use media root if configured)
    zips_dir = Path(settings.MEDIA_ROOT) / "exports" if hasattr(settings, 'MEDIA_ROOT') and settings.MEDIA_ROOT else Path("/tmp/cyber_agent_zips")
    zips_dir.mkdir(parents=True, exist_ok=True)

    filename = "host_agent.zip"
    file_path = (zips_dir / filename).resolve()

    # Basic safety check: ensure it's inside the folder we expect
    if not str(file_path).startswith(str(zips_dir.resolve())):
        raise Http404("Invalid path")

    # Check if ZIP already exists and is recent (within 1 hour)
    if file_path.exists():
        file_age = time.time() - file_path.stat().st_mtime
        if file_age < 3600:  # 1 hour
            # File exists and is recent, stream it
            response = FileResponse(open(file_path, "rb"), as_attachment=True, filename=file_path.name)
            response["Content-Type"] = "application/zip"
            response['Cache-Control'] = 'no-cache'
            print(f"[DEBUG] Serving cached ZIP file")
            return response

    # ZIP doesn't exist or is old, create it
    # Try to download from GitHub repo release first
    try:
        repo_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'
        release_response = requests.get(repo_url, timeout=10)

        if release_response.status_code == 200:
            release_data = release_response.json()
            zipball_url = release_data.get('zipball_url')

            if zipball_url:
                zip_response = requests.get(zipball_url, timeout=30)
                if zip_response.status_code == 200:
                    print("[DEBUG] Downloaded latest agent ZIP from repo release")
                    tag_name = release_data.get('tag_name', 'latest')
                    # Save to file
                    with open(file_path, 'wb') as f:
                        f.write(zip_response.content)
                    # Stream it using FileResponse
                    response = FileResponse(open(file_path, "rb"), as_attachment=True, filename=f"{tag_name}_cyber_host_agent.zip" if tag_name != 'latest' else filename)
                    response["Content-Type"] = "application/zip"
                    response['Cache-Control'] = 'no-cache'
                    print(f"[DEBUG] Download response prepared with repo ZIP via FileResponse")
                    return response
        print("[DEBUG] Could not download from repo release, falling back to local ZIP creation")

    except Exception as e:
        print(f"[DEBUG] Error downloading from repo: {e}, falling back to local ZIP creation")

    # Fallback to creating ZIP with local agent files
    try:
        with zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Base agent directory
            agent_base = os.path.join(settings.BASE_DIR, 'host_agent')

            files_added = 0
            # Walk through all files in host_agent directory recursively
            for root, dirs, files in os.walk(agent_base):
                # Skip venv directory if it exists
                dirs[:] = [d for d in dirs if d != 'venv']

                for file in files:
                    # Skip __pycache__ directories and .pyc files
                    if '__pycache__' in root or file.endswith('.pyc') or file.startswith('.'):
                        continue

                    file_path_src = os.path.join(root, file)
                    # Calculate relative path for ZIP file
                    rel_path = os.path.relpath(file_path_src, agent_base)

                    try:
                        zip_file.write(file_path_src, rel_path)
                        files_added += 1
                        print(f"[DEBUG] Added {rel_path} to ZIP")
                    except Exception as e:
                        print(f"[DEBUG] Failed to add {rel_path}: {e}")
                        continue

            if files_added == 0:
                print("[ERROR] No agent files found for download")
                return HttpResponse("Error: No agent files found", status=404)

        print(f"[DEBUG] ZIP file created and saved to {file_path}")

        # FileResponse streams efficiently
        response = FileResponse(open(file_path, "rb"), as_attachment=True, filename=file_path.name)
        response["Content-Type"] = "application/zip"
        response['Cache-Control'] = 'no-cache'
        print(f"[DEBUG] Download response prepared with local files via FileResponse")
        return response

    except Exception as e:
        print(f"[ERROR] Failed to create download ZIP: {e}")
        raise Http404("Error creating download")


@require_GET
def agent_version_api(request):
    """API endpoint for agent version information."""
    try:
        from host_agent.agent import AGENT_VERSION, AGENT_NAME
    except Exception:
        AGENT_VERSION = "unknown"
        AGENT_NAME = "host_agent"

    # Get version information from all agents
    agents = AgentStatus.objects.filter(
        agent_version__isnull=False
    ).values('agent_id', 'hostname', 'agent_version', 'last_version_check')

    return JsonResponse({
        'current_version': AGENT_VERSION,
        'agent_name': AGENT_NAME,
        'agents': list(agents),
        'total_agents_with_version': agents.count()
    })


# -----------------------------
# Network Metadata and Security Onion-like Monitoring
# -----------------------------
@csrf_exempt
@require_http_methods(["POST"])
def agent_network_metadata(request):
    """Receive detailed network metadata from agents."""
    if not _check_agent_token(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    network_connections = data.get("network_connections", [])
    interface_statistics = data.get("interface_statistics", [])
    active_ports = data.get("active_ports", [])
    interfaces = data.get("interfaces", [])

    if not agent_id:
        return JsonResponse({"error": "agent_id is required"}, status=400)

    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    # Create network metadata record
    metadata = NetworkMetadata.objects.create(
        agent=agent,
        network_connections=network_connections,
        interface_statistics=interface_statistics,
        active_ports=active_ports,
        interfaces=interfaces,
        total_connections=len(network_connections),
        total_interfaces=len(interface_statistics)
    )

    # Create individual connection records for detailed analysis
    for conn_data in network_connections:
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=agent,
            protocol=conn_data.get("protocol", "TCP"),
            local_address=conn_data.get("local_address"),
            remote_address=conn_data.get("remote_address"),
            status=conn_data.get("status", "UNKNOWN"),
            process_pid=conn_data.get("process", {}).get("pid"),
            process_name=conn_data.get("process", {}).get("name"),
            process_username=conn_data.get("process", {}).get("username"),
            process_cmdline=conn_data.get("process", {}).get("cmdline")
        )

    return JsonResponse({
        "status": "network_metadata_received",
        "metadata_id": metadata.id,
        "connections_recorded": len(network_connections),
        "interfaces_recorded": len(interface_statistics)
    })


@require_GET
def network_monitoring_dashboard(request):
    """Security Onion-like network monitoring dashboard."""
    agents = AgentStatus.objects.filter(status='online').order_by('-last_heartbeat')

    # Get recent network metadata
    recent_metadata = NetworkMetadata.objects.all().order_by('-timestamp')[:20]

    # Get active connections across all agents
    recent_connections = NetworkConnection.objects.all().order_by('-last_seen')[:50]

    # Get interface statistics
    interface_stats = []
    for metadata in recent_metadata:
        if metadata.interface_statistics:
            for iface_stat in metadata.interface_statistics:
                interface_stats.append({
                    'agent': metadata.agent.hostname,
                    'interface': iface_stat.get('interface'),
                    'bytes_sent': iface_stat.get('bytes_sent', 0),
                    'bytes_recv': iface_stat.get('bytes_recv', 0),
                    'packets_sent': iface_stat.get('packets_sent', 0),
                    'packets_recv': iface_stat.get('packets_recv', 0),
                    'timestamp': metadata.timestamp
                })

    return render(request, 'dashboard/network_monitoring.html', {
        'agents': agents,
        'recent_metadata': recent_metadata,
        'recent_connections': recent_connections,
        'interface_stats': interface_stats[:20],  # Limit to 20 for display
        'total_agents': agents.count(),
        'total_connections': recent_connections.count(),
        'total_metadata_records': recent_metadata.count()
    })


# -----------------------------
# Digital Twin / MiniMega
# -----------------------------
def _staff_required_json(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)
        if not request.user.is_staff:
            return JsonResponse({"error": "forbidden"}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def _run_minimega_command(command, timeout=60):
    try:
        return subprocess.run(
            ["minimega", "-e", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        ), None
    except FileNotFoundError:
        return None, JsonResponse({"error": "minimega binary not found on server"}, status=500)
    except subprocess.TimeoutExpired:
        return None, JsonResponse({"error": "minimega execution timed out"}, status=504)


def _resolve_scan_for_twin(scan_id):
    if scan_id:
        try:
            return ScanRun.objects.get(id=scan_id), None
        except ScanRun.DoesNotExist:
            return None, JsonResponse({"error": "scan_id not found"}, status=404)
    scan = ScanRun.objects.order_by("-timestamp").first()
    if not scan:
        return None, JsonResponse({"error": "no scan data available"}, status=404)
    return scan, None


def _build_twin_payload(scan, disk_image, vlan, enable_virtio, memory_mb):
    nodes = list(scan.nodes.all().order_by("ip_address"))
    if not nodes:
        return None, JsonResponse({"error": "scan has no nodes"}, status=400)

    agent_ids = [node.agent_id for node in nodes if node.agent_id]
    sbom_by_agent = {}
    if agent_ids:
        for sbom in SbomReport.objects.filter(agent_id__in=agent_ids).order_by("agent_id", "-created_at"):
            sbom_by_agent.setdefault(sbom.agent_id, sbom)

    node_entries = []
    for node in nodes:
        sbom = sbom_by_agent.get(node.agent_id) if node.agent_id else None
        package_count = sbom.package_count if sbom else (len(node.installed_libraries or []))
        os_summary = sbom.os_summary if sbom and sbom.os_summary else (node.os_info or "")
        node_entries.append({
            "id": node.id,
            "name": node.name,
            "ip": node.ip_address,
            "agent_id": node.agent_id,
            "os": os_summary,
            "packages": package_count,
        })

    links = [
        {
            "source": link.source.ip_address,
            "destination": link.destination.ip_address,
            "weight": link.weight,
        }
        for link in scan.links.select_related("source", "destination")
    ]

    script = build_minimega_script(
        nodes=node_entries,
        disk_image=disk_image,
        vlan=vlan,
        enable_virtio=enable_virtio,
        memory_mb=memory_mb,
    )

    manifest = build_digital_twin_manifest(
        scan_id=scan.id,
        nodes=node_entries,
        links=links,
        disk_image=disk_image,
        vlan=vlan,
        enable_virtio=enable_virtio,
        memory_mb=memory_mb,
    )

    return {
        "script": script,
        "manifest": manifest,
        "node_count": len(node_entries),
        "link_count": len(links),
        "scan_id": scan.id,
    }, None


@require_GET
def digital_twin_page(request):
    scans = ScanRun.objects.all().order_by("-timestamp")[:20]
    latest_scan = scans[0] if scans else None
    return render(request, "dashboard/digital_twin.html", {
        "scans": scans,
        "latest_scan": latest_scan,
    })


@csrf_exempt
@require_http_methods(["POST"])
def digital_twin_generate(request):
    if request.content_type and "application/json" in request.content_type:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    else:
        data = request.POST

    scan_id = data.get("scan_id")
    disk_image = data.get("disk_image")
    vlan = data.get("vlan", "100")
    enable_virtio = str(data.get("enable_virtio", "")).lower() in {"1", "true", "yes", "on"}
    try:
        memory_mb = int(data.get("memory_mb", 2048))
    except (TypeError, ValueError):
        return JsonResponse({"error": "memory_mb must be an integer"}, status=400)

    if not disk_image:
        return JsonResponse({"error": "disk_image is required"}, status=400)
    if "\n" in disk_image or "\r" in disk_image:
        return JsonResponse({"error": "disk_image contains invalid characters"}, status=400)

    scan, error = _resolve_scan_for_twin(scan_id)
    if error:
        return error

    payload, error = _build_twin_payload(scan, disk_image, vlan, enable_virtio, memory_mb)
    if error:
        return error

    return JsonResponse({
        "status": "generated",
        "scan_id": payload["scan_id"],
        "script": payload["script"],
        "manifest": payload["manifest"],
        "node_count": payload["node_count"],
        "link_count": payload["link_count"],
    })


@require_http_methods(["POST"])
def digital_twin_export(request):
    if request.content_type and "application/json" in request.content_type:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    else:
        data = request.POST

    scan_id = data.get("scan_id")
    disk_image = data.get("disk_image")
    vlan = data.get("vlan", "100")
    enable_virtio = str(data.get("enable_virtio", "")).lower() in {"1", "true", "yes", "on"}
    try:
        memory_mb = int(data.get("memory_mb", 2048))
    except (TypeError, ValueError):
        return JsonResponse({"error": "memory_mb must be an integer"}, status=400)

    if not disk_image:
        return JsonResponse({"error": "disk_image is required"}, status=400)
    if "\n" in disk_image or "\r" in disk_image:
        return JsonResponse({"error": "disk_image contains invalid characters"}, status=400)

    scan, error = _resolve_scan_for_twin(scan_id)
    if error:
        return error

    payload, error = _build_twin_payload(scan, disk_image, vlan, enable_virtio, memory_mb)
    if error:
        return error

    import zipfile
    import io

    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(f"cybertwin_scan_{payload['scan_id']}.mm", payload["script"])
        zip_file.writestr("manifest.json", json.dumps(payload["manifest"], indent=2))

    bundle.seek(0)
    filename = f"cybertwin_scan_{payload['scan_id']}_bundle.zip"
    response = FileResponse(bundle, as_attachment=True, filename=filename)
    response["Content-Type"] = "application/zip"
    return response


@csrf_exempt
@require_http_methods(["POST"])
def digital_twin_execute(request):
    if request.content_type and "application/json" in request.content_type:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    else:
        data = request.POST

    if os.environ.get("MINIMEGA_EXECUTION_ENABLED") != "1":
        return JsonResponse({"error": "MiniMega execution is disabled on this server"}, status=403)

    if str(data.get("confirm", "")).strip() != "RUN_MINIMEGA":
        return JsonResponse({"error": "Confirmation token missing. Set confirm=RUN_MINIMEGA to proceed."}, status=400)

    scan_id = data.get("scan_id")
    disk_image = data.get("disk_image")
    vlan = data.get("vlan", "100")
    enable_virtio = str(data.get("enable_virtio", "")).lower() in {"1", "true", "yes", "on"}
    try:
        memory_mb = int(data.get("memory_mb", 2048))
    except (TypeError, ValueError):
        return JsonResponse({"error": "memory_mb must be an integer"}, status=400)

    if not disk_image:
        return JsonResponse({"error": "disk_image is required"}, status=400)
    if "\n" in disk_image or "\r" in disk_image:
        return JsonResponse({"error": "disk_image contains invalid characters"}, status=400)

    if not os.path.exists(disk_image):
        return JsonResponse({"error": f"disk_image not found: {disk_image}"}, status=400)

    scan, error = _resolve_scan_for_twin(scan_id)
    if error:
        return error

    payload, error = _build_twin_payload(scan, disk_image, vlan, enable_virtio, memory_mb)
    if error:
        return error

    base_dir = getattr(settings, "MINIMEGA_SCRIPT_DIR", "/tmp/cybertwin_minimega")
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    script_name = f"twin_scan_{payload['scan_id']}_{now():%Y%m%d_%H%M%S}.mm"
    script_path = Path(base_dir) / script_name
    script_path.write_text(payload["script"])

    result, error = _run_minimega_command(f"read {script_path}")
    if error:
        MinimegaExecutionLog.objects.create(
            action=MinimegaExecutionLog.Action.EXECUTE,
            user=request.user if request.user.is_authenticated else None,
            scan=scan,
            disk_image=disk_image,
            vlan=vlan,
            memory_mb=memory_mb,
            enable_virtio=enable_virtio,
            script_path=str(script_path),
            command=f"read {script_path}",
            status="failed",
            stdout="",
            stderr=error.content.decode("utf-8") if hasattr(error, "content") else "",
        )
        return error

    log = MinimegaExecutionLog.objects.create(
        action=MinimegaExecutionLog.Action.EXECUTE,
        user=request.user if request.user.is_authenticated else None,
        scan=scan,
        disk_image=disk_image,
        vlan=vlan,
        memory_mb=memory_mb,
        enable_virtio=enable_virtio,
        script_path=str(script_path),
        command=f"read {script_path}",
        status="success" if result.returncode == 0 else "failed",
        returncode=result.returncode,
        stdout=result.stdout[:10000],
        stderr=result.stderr[:10000],
    )

    return JsonResponse({
        "status": "executed",
        "script_path": str(script_path),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "log_id": log.id,
    })


@require_http_methods(["POST"])
def deploy_minimega_script(request):
    return digital_twin_execute(request)


@require_GET
def stream_minimega_execution(request):
    return JsonResponse({"error": "streaming_not_configured"}, status=501)


@require_GET
def stream_minimega_execution_async(request):
    return JsonResponse({"error": "streaming_not_configured"}, status=501)


@require_http_methods(["POST"])
@_staff_required_json
def digital_twin_reset(request):
    if os.environ.get("MINIMEGA_EXECUTION_ENABLED") != "1" or os.environ.get("MINIMEGA_ALLOW_RESET") != "1":
        return JsonResponse({"error": "MiniMega reset is disabled on this server"}, status=403)

    confirm = ""
    if request.body:
        try:
            confirm = json.loads(request.body).get("confirm", "")
        except json.JSONDecodeError:
            confirm = ""
    confirm = str(request.POST.get("confirm") or confirm).strip()
    if confirm != "RESET_MINIMEGA":
        return JsonResponse({"error": "Confirmation token missing. Set confirm=RESET_MINIMEGA to proceed."}, status=400)

    command = os.environ.get("MINIMEGA_RESET_COMMAND", "clear vm")
    result, error = _run_minimega_command(command)
    if error:
        MinimegaExecutionLog.objects.create(
            action=MinimegaExecutionLog.Action.RESET,
            user=request.user,
            command=command,
            status="failed",
            stdout="",
            stderr=error.content.decode("utf-8") if hasattr(error, "content") else "",
        )
        return error

    log = MinimegaExecutionLog.objects.create(
        action=MinimegaExecutionLog.Action.RESET,
        user=request.user,
        command=command,
        status="success" if result.returncode == 0 else "failed",
        returncode=result.returncode,
        stdout=result.stdout[:10000],
        stderr=result.stderr[:10000],
    )
    return JsonResponse({
        "status": "reset",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "log_id": log.id,
    })


@require_http_methods(["POST"])
@_staff_required_json
def digital_twin_kill(request):
    if os.environ.get("MINIMEGA_EXECUTION_ENABLED") != "1" or os.environ.get("MINIMEGA_ALLOW_KILL") != "1":
        return JsonResponse({"error": "MiniMega kill is disabled on this server"}, status=403)

    confirm = ""
    if request.body:
        try:
            confirm = json.loads(request.body).get("confirm", "")
        except json.JSONDecodeError:
            confirm = ""
    confirm = str(request.POST.get("confirm") or confirm).strip()
    if confirm != "KILL_MINIMEGA":
        return JsonResponse({"error": "Confirmation token missing. Set confirm=KILL_MINIMEGA to proceed."}, status=400)

    command = os.environ.get("MINIMEGA_KILL_COMMAND", "quit")
    result, error = _run_minimega_command(command)
    if error:
        MinimegaExecutionLog.objects.create(
            action=MinimegaExecutionLog.Action.KILL,
            user=request.user,
            command=command,
            status="failed",
            stdout="",
            stderr=error.content.decode("utf-8") if hasattr(error, "content") else "",
        )
        return error

    log = MinimegaExecutionLog.objects.create(
        action=MinimegaExecutionLog.Action.KILL,
        user=request.user,
        command=command,
        status="success" if result.returncode == 0 else "failed",
        returncode=result.returncode,
        stdout=result.stdout[:10000],
        stderr=result.stderr[:10000],
    )
    return JsonResponse({
        "status": "killed",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "log_id": log.id,
    })


@require_GET
def minimega_execution_logs(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication_required"}, status=401)
    if not request.user.is_staff:
        return JsonResponse({"error": "forbidden"}, status=403)

    logs = MinimegaExecutionLog.objects.select_related("user", "scan").all()[:200]
    return render(request, "dashboard/minimega_logs.html", {"logs": logs})

@require_GET
def minimega_provisions(request):
    return redirect("dashboard:digital_twin_page")


@require_GET
def network_metadata_api(request):
    """API endpoint for real-time network metadata."""
    agent_id = request.GET.get('agent_id')
    limit = int(request.GET.get('limit', 20))

    if agent_id:
        # Get metadata for specific agent
        metadata = NetworkMetadata.objects.filter(agent__agent_id=agent_id).order_by('-timestamp')[:limit]
    else:
        # Get recent metadata from all agents
        metadata = NetworkMetadata.objects.all().order_by('-timestamp')[:limit]

    metadata_list = []
    for record in metadata:
        metadata_list.append({
            'id': record.id,
            'agent_id': record.agent.agent_id,
            'hostname': record.agent.hostname,
            'timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'total_connections': record.total_connections,
            'total_interfaces': record.total_interfaces,
            'collection_duration_ms': record.collection_duration_ms,
            'connections': record.network_connections[:10] if record.network_connections else [],  # First 10 connections
            'interface_statistics': record.interface_statistics[:5] if record.interface_statistics else []  # First 5 interfaces
        })

    return JsonResponse({
        'metadata': metadata_list,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


@require_GET
def network_connections_api(request):
    """API endpoint for network connections data."""
    agent_id = request.GET.get('agent_id')
    limit = int(request.GET.get('limit', 50))

    if agent_id:
        # Get connections for specific agent
        connections = NetworkConnection.objects.filter(agent__agent_id=agent_id).order_by('-last_seen')[:limit]
    else:
        # Get recent connections from all agents
        connections = NetworkConnection.objects.all().order_by('-last_seen')[:limit]

    connections_list = []
    for conn in connections:
        connections_list.append({
            'id': conn.id,
            'agent_id': conn.agent.agent_id,
            'hostname': conn.agent.hostname,
            'protocol': conn.protocol,
            'local_address': conn.local_address,
            'local_port': conn.local_port,
            'remote_address': conn.remote_address,
            'remote_port': conn.remote_port,
            'status': conn.status,
            'process_name': conn.process_name or 'Unknown',
            'process_username': conn.process_username or 'Unknown',
            'first_seen': conn.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': conn.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        })

    return JsonResponse({
        'connections': connections_list,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


@require_GET
def network_topology_api(request):
    """API endpoint for network topology visualization."""
    # Get all agents and their recent connections
    agents = AgentStatus.objects.filter(status='online')

    nodes = []
    edges = []

    # Add agent nodes
    for agent in agents:
        nodes.append({
            'id': agent.agent_id,
            'label': agent.hostname,
            'ip_address': agent.ip_address,
            'type': 'agent',
            'status': agent.status,
            'os_type': agent.os_type,
            'last_heartbeat': agent.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent.last_heartbeat else 'Never'
        })

    # Get recent connections to build edges
    recent_connections = NetworkConnection.objects.filter(
        agent__status='online',
        last_seen__gte=now() - timedelta(hours=1)  # Last hour
    ).select_related('agent')

    # Group connections by source/destination to create flows
    flows = {}
    for conn in recent_connections:
        if conn.remote_address and conn.remote_address != '127.0.0.1' and conn.remote_address != 'localhost':
            flow_key = (conn.agent.agent_id, conn.remote_address, conn.protocol)
            if flow_key not in flows:
                flows[flow_key] = {
                    'source': conn.agent.agent_id,
                    'target': conn.remote_address,
                    'protocol': conn.protocol,
                    'connection_count': 0,
                    'total_bytes': 0
                }
            flows[flow_key]['connection_count'] += 1

    # Convert flows to edges
    for flow in flows.values():
        edges.append({
            'from': flow['source'],
            'to': flow['target'],
            'label': f"{flow['protocol']} ({flow['connection_count']} conn)",
            'protocol': flow['protocol'],
            'connection_count': flow['connection_count']
        })

    return JsonResponse({
        'nodes': nodes,
        'edges': edges,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


def risk_assessment_page(request):
    return render(request, 'dashboard/risk_assessment.html')


@require_GET
def risk_assessment_status_api(request):
    try:
        response = _risk_call(requests.get, '/status')
        return JsonResponse(response.json())
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=502)


@require_GET
def risk_assessment_nodes_api(request):
    try:
        response = _risk_call(requests.get, '/nodes')
        return JsonResponse(response.json())
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=502)


@require_http_methods(["POST"])
def risk_assessment_probability_api(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    try:
        response = _risk_call(
            requests.post,
            '/probability',
            json=payload,
        )
        return JsonResponse(response.json())
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=502)


@require_GET
def risk_assessment_network_compute_api(request):
    try:
        scan_run_id = request.GET.get("scan_run_id")
        if scan_run_id:
            try:
                scan_run_id = int(scan_run_id)
            except ValueError:
                return JsonResponse({'error': 'Invalid scan_run_id.'}, status=400)
        else:
            scan_run_id = None

        nodes_response = _risk_call(requests.get, '/nodes')
        payload = nodes_response.json()
        variables = payload.get("variables", {})
        risk_nodes = list(variables.keys())

        cyber_data, mapped_nodes = build_cyber_data_for_risk_nodes(risk_nodes, scan_run_id=scan_run_id)

        probability_response = _risk_call(
            requests.post,
            '/probability',
            json=cyber_data,
        )
        result_payload = probability_response.json()
        results = result_payload.get("results", {})

        summary = summarize_risk_results(mapped_nodes, results)

        return JsonResponse({
            "risk_nodes_count": len(risk_nodes),
            "scan_run_id": scan_run_id,
            "mapped_nodes": summary,
            "results": results,
        })
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=502)


@require_http_methods(["GET", "POST"])
def risk_assessment_mappings_api(request):
    if request.method == "GET":
        risk_nodes = []
        risk_error = None
        try:
            response = requests.get(_risk_api_url('/nodes'), timeout=RISK_ASSESSMENT_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            variables = payload.get("variables")
            if isinstance(variables, dict):
                risk_nodes = [str(key) for key in variables.keys()]
            else:
                nodes_payload = payload.get("nodes")
                if isinstance(nodes_payload, list):
                    for node in nodes_payload:
                        if isinstance(node, str):
                            risk_nodes.append(node)
                        elif isinstance(node, dict):
                            name = node.get("name") or node.get("node") or node.get("id")
                            if name:
                                risk_nodes.append(str(name))
        except Exception as exc:
            risk_error = str(exc)

        mapping_ids = list(
            RiskNodeMapping.objects.values_list("risk_node_id", flat=True).distinct()
        )
        merged_ids = {rid for rid in risk_nodes if rid}
        merged_ids.update(mapping_ids)
        risk_nodes = sorted(merged_ids)

        nodes = []
        for node in Node.objects.order_by("name", "ip_address"):
            nodes.append({
                "id": node.id,
                "name": node.name,
                "ip_address": node.ip_address,
                "os_info": node.os_info,
                "platform_info": node.platform_info,
                "cpu_count": node.cpu_count,
                "memory_total": node.memory_total,
                "mac_addresses": node.mac_addresses or [],
                "active_ports": node.active_ports or [],
                "last_heartbeat": node.last_heartbeat.isoformat() if node.last_heartbeat else None,
            })
        mappings = list(
            RiskNodeMapping.objects.select_related("node").order_by("risk_node_id")
        )

        mapping_payload = []
        for mapping in mappings:
            mapping_payload.append({
                "risk_node_id": mapping.risk_node_id,
                "node_id": mapping.node_id,
                "node_name": mapping.node.name if mapping.node else None,
                "ip_address": mapping.ip_address,
                "label": mapping.label,
                "notes": mapping.notes,
                "active": mapping.active,
                "updated_at": mapping.updated_at.isoformat(),
            })

        response_payload = {
            "risk_nodes": risk_nodes,
            "nodes": nodes,
            "mappings": mapping_payload,
        }
        if risk_error:
            response_payload["risk_error"] = risk_error

        return JsonResponse(response_payload)

    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    if isinstance(payload.get("mappings"), list):
        errors = []
        saved = []
        for index, item in enumerate(payload.get("mappings", [])):
            if not isinstance(item, dict):
                errors.append({"index": index, "error": "Each mapping must be an object."})
                continue
            risk_node_id = str(item.get("risk_node_id") or "").strip()
            if not risk_node_id:
                errors.append({"index": index, "error": "risk_node_id is required."})
                continue

            node_id = item.get("node_id")
            if node_id in ("", None):
                node_id = None

            node = None
            if node_id is not None:
                try:
                    node = Node.objects.get(id=node_id)
                except Node.DoesNotExist:
                    errors.append({"index": index, "risk_node_id": risk_node_id, "error": "Invalid node_id."})
                    continue

            ip_address = str(item.get("ip_address") or "").strip() or None
            if ip_address:
                try:
                    ipaddress.ip_address(ip_address)
                except ValueError:
                    errors.append({"index": index, "risk_node_id": risk_node_id, "error": "Invalid ip_address."})
                    continue

            label = str(item.get("label") or "").strip()
            notes = str(item.get("notes") or "").strip()
            active = item.get("active", True)
            if isinstance(active, str):
                active = active.lower() in ("1", "true", "yes", "on")

            mapping, _ = RiskNodeMapping.objects.update_or_create(
                risk_node_id=risk_node_id,
                defaults={
                    "node": node,
                    "ip_address": ip_address,
                    "label": label,
                    "notes": notes,
                    "active": bool(active),
                },
            )

            saved.append({
                "risk_node_id": mapping.risk_node_id,
                "node_id": mapping.node_id,
                "node_name": mapping.node.name if mapping.node else None,
                "ip_address": mapping.ip_address,
                "label": mapping.label,
                "notes": mapping.notes,
                "active": mapping.active,
                "updated_at": mapping.updated_at.isoformat(),
            })

        if errors:
            return JsonResponse({"error": "Validation failed.", "errors": errors, "mappings": saved}, status=400)

        return JsonResponse({"mappings": saved})

    risk_node_id = str(payload.get("risk_node_id") or "").strip()
    if not risk_node_id:
        return JsonResponse({'error': 'risk_node_id is required.'}, status=400)

    node_id = payload.get("node_id")
    if node_id in ("", None):
        node_id = None

    node = None
    if node_id is not None:
        try:
            node = Node.objects.get(id=node_id)
        except Node.DoesNotExist:
            return JsonResponse({'error': 'Invalid node_id.'}, status=400)

    ip_address = str(payload.get("ip_address") or "").strip() or None
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return JsonResponse({'error': 'Invalid ip_address.'}, status=400)

    label = str(payload.get("label") or "").strip()
    notes = str(payload.get("notes") or "").strip()
    active = payload.get("active", True)
    if isinstance(active, str):
        active = active.lower() in ("1", "true", "yes", "on")

    mapping, _ = RiskNodeMapping.objects.update_or_create(
        risk_node_id=risk_node_id,
        defaults={
            "node": node,
            "ip_address": ip_address,
            "label": label,
            "notes": notes,
            "active": bool(active),
        },
    )

    return JsonResponse({
        "mapping": {
            "risk_node_id": mapping.risk_node_id,
            "node_id": mapping.node_id,
            "node_name": mapping.node.name if mapping.node else None,
            "ip_address": mapping.ip_address,
            "label": mapping.label,
            "notes": mapping.notes,
            "active": mapping.active,
            "updated_at": mapping.updated_at.isoformat(),
        }
    })


@require_http_methods(["POST"])
def risk_assessment_testbed_generate(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    cidr = str(payload.get("cidr") or "192.168.236.0/24").strip()
    cve_input = payload.get("cves") or []
    max_cves = payload.get("max_cves_per_node", 10)

    try:
        max_cves = int(max_cves)
    except (TypeError, ValueError):
        max_cves = 10
    max_cves = max(0, min(max_cves, 50))

    try:
        network = ip_network(cidr, strict=False)
    except ValueError:
        return JsonResponse({'error': 'Invalid CIDR.'}, status=400)

    if isinstance(cve_input, str):
        raw = cve_input.replace("\r", "\n").replace(",", "\n")
        cve_list = [entry.strip().upper() for entry in raw.split("\n") if entry.strip()]
    elif isinstance(cve_input, list):
        cve_list = [str(entry).strip().upper() for entry in cve_input if str(entry).strip()]
    else:
        cve_list = []

    cve_list = list(dict.fromkeys(cve_list))

    try:
        response = _risk_call(requests.get, '/nodes')
        payload = response.json()
    except Exception as exc:
        return JsonResponse({'error': f'Risk service unavailable: {exc}'}, status=502)

    variables = payload.get("variables", {})
    risk_nodes = list(variables.keys()) if isinstance(variables, dict) else []
    if not risk_nodes:
        nodes_payload = payload.get("nodes")
        if isinstance(nodes_payload, list):
            for node in nodes_payload:
                if isinstance(node, str):
                    risk_nodes.append(node)
                elif isinstance(node, dict):
                    name = node.get("name") or node.get("node") or node.get("id")
                    if name:
                        risk_nodes.append(str(name))

    if not risk_nodes:
        return JsonResponse({'error': 'No risk nodes returned from risk service.'}, status=400)

    host_iter = network.hosts()
    assigned_hosts = []
    for _ in range(len(risk_nodes)):
        try:
            assigned_hosts.append(str(next(host_iter)))
        except StopIteration:
            break

    if len(assigned_hosts) < len(risk_nodes):
        return JsonResponse({
            'error': 'CIDR does not have enough usable addresses for the risk nodes.',
            'risk_nodes': len(risk_nodes),
            'available_hosts': len(assigned_hosts),
        }, status=400)

    scan_run = ScanRun.objects.create(
        cidr=str(network),
        status="COMPLETE",
        scan_type="agent",
        result_summary=f"Risk testbed generated ({len(risk_nodes)} nodes).",
    )

    now_ts = timezone.now()
    vuln_objects = {}
    if cve_list:
        for cve in cve_list[:max_cves]:
            vuln, _ = Vulnerability.objects.update_or_create(
                cve_id=cve,
                defaults={
                    "description": "Synthetic risk testbed vulnerability.",
                    "severity": "High",
                    "score": 7.5,
                    "published": now_ts,
                    "last_modified": now_ts,
                },
            )
            vuln_objects[cve] = vuln

    created_nodes = 0
    mappings_updated = 0
    created_links = 0

    def purdue_tier(risk_node_id: str) -> str:
        name = risk_node_id.upper()
        if any(token in name for token in ["ERP", "MES", "CORP", "ENTERPRISE", "BUSINESS", "IT", "OFFICE"]):
            return "L4-L5"
        if any(token in name for token in ["DMZ", "FIREWALL", "PROXY", "JUMP", "GATEWAY", "HISTORIAN", "OPC"]):
            return "L3.5"
        if any(token in name for token in ["SCADA", "HMI", "SERVER", "OPS", "ENGINEER", "SUPERVISOR"]):
            return "L3"
        if any(token in name for token in ["PLC", "RTU", "IED", "DCS", "CONTROLLER", "CTRL"]):
            return "L2"
        if any(token in name for token in ["SENSOR", "VALVE", "PUMP", "MOTOR", "HEATER", "PRESSURIZER", "SPRAY", "HV", "PV", "CV", "PT", "LT", "TT", "FT", "PORV"]):
            return "L0-L1"
        return "L2"

    with transaction.atomic():
        created_node_objects = []
        tiered = []
        for risk_node_id, ip_addr in zip(risk_nodes, assigned_hosts):
            tier = purdue_tier(risk_node_id)
            tiered.append((risk_node_id, ip_addr, tier))

        for risk_node_id, ip_addr, tier in tiered:
            node = Node.objects.create(
                scan_run=scan_run,
                name=risk_node_id,
                ip_address=ip_addr,
                status="online",
                description=f"Generated from risk assessment schema. Purdue tier: {tier}.",
            )
            created_nodes += 1
            created_node_objects.append(node)

            RiskNodeMapping.objects.update_or_create(
                risk_node_id=risk_node_id,
                defaults={
                    "node": node,
                    "ip_address": ip_addr,
                    "label": risk_node_id,
                    "active": True,
                },
            )
            mappings_updated += 1

            if vuln_objects:
                node.vulnerability_set.add(*vuln_objects.values())

        if created_node_objects:
            tiers = {"L0-L1": [], "L2": [], "L3": [], "L3.5": [], "L4-L5": []}
            for (risk_node_id, _ip_addr, tier), node in zip(tiered, created_node_objects):
                tiers.setdefault(tier, []).append(node)

            tier_order = ["L0-L1", "L2", "L3", "L3.5", "L4-L5"]
            # Intra-tier ring to show local segmentation
            for tier_key in tier_order:
                tier_nodes = tiers.get(tier_key, [])
                if len(tier_nodes) > 1:
                    for idx, node in enumerate(tier_nodes):
                        next_node = tier_nodes[(idx + 1) % len(tier_nodes)]
                        Link.objects.create(
                            scan_run=scan_run,
                            source=node,
                            destination=next_node,
                            weight=1.0,
                        )
                        created_links += 1

            # Inter-tier north-south links
            for lower_key, upper_key in zip(tier_order, tier_order[1:]):
                lower_nodes = tiers.get(lower_key, [])
                upper_nodes = tiers.get(upper_key, [])
                if not lower_nodes or not upper_nodes:
                    continue
                for idx, node in enumerate(lower_nodes):
                    target = upper_nodes[idx % len(upper_nodes)]
                    Link.objects.create(
                        scan_run=scan_run,
                        source=node,
                        destination=target,
                        weight=1.0,
                    )
                    created_links += 1

    return JsonResponse({
        "scan_run_id": scan_run.id,
        "cidr": str(network),
        "risk_nodes": len(risk_nodes),
        "nodes_created": created_nodes,
        "mappings_updated": mappings_updated,
        "links_created": created_links,
        "cves_applied": list(vuln_objects.keys()),
    })


def _risk_api_url(path: str) -> str:
    base = getattr(settings, 'RISK_ASSESSMENT_API_URL', 'http://127.0.0.1:7890')
    return f"{base.rstrip('/')}/{path.lstrip('/')}"
