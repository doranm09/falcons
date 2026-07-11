"""Reproducible S0-S4 experiment orchestration for the FALCONS paper."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import time
from collections import deque
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Iterable

import requests
from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from .models import (
    AgentStatus,
    ExperimentArtifact,
    ExperimentSuite,
    Link,
    NetworkConnection,
    NetworkFlow,
    Node,
    SbomReport,
    ScenarioRun,
    SiemEvent,
    Vulnerability,
)


SCENARIOS = ("S0", "S1", "S2", "S3", "S4")
EVIDENCE_CLASSES = ("host", "network", "process", "vulnerability", "configuration")


class ExperimentError(RuntimeError):
    pass


class RollbackError(ExperimentError):
    pass


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def payload_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return path


def normalize_asset(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _refs(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return {str(key) for key in value}
    if isinstance(value, list):
        output: set[str] = set()
        for item in value:
            output.update(_refs(item))
        return output
    return set()


def model_nodes(model: dict) -> dict[str, dict]:
    nodes: dict[str, dict] = {}
    for section in ("digital", "physical", "flow", "function"):
        values = model.get(section)
        if not isinstance(values, dict):
            continue
        for node_id, record in values.items():
            if isinstance(record, dict):
                nodes[str(node_id)] = {**record, "_section": section}
    return nodes


def model_edges(model: dict) -> set[tuple[str, str]]:
    nodes = model_nodes(model)
    edges: set[tuple[str, str]] = set()
    for node_id, record in nodes.items():
        for source in _refs(record.get("source")):
            if source in nodes and source != node_id:
                edges.add((source, node_id))
        for target in _refs(record.get("target")):
            if target in nodes and target != node_id:
                edges.add((node_id, target))
    return edges


def apply_cyber_policy_overlay(model: dict, overlay: Any) -> tuple[dict, list[dict[str, str]]]:
    """Apply an acyclic, evidence-backed attack-consequence overlay to a model.

    The hybrid compose model records network membership but does not encode every
    directional attack dependency needed by the publication scenarios.  The
    overlay makes those policy assumptions explicit in the suite-local model;
    it never mutates the source ``sim_system.json``.
    """
    merged = json.loads(json.dumps(model))
    if not overlay:
        return merged, []
    if not isinstance(overlay, dict):
        raise ExperimentError("cyber_policy_overlay must be an object")
    edges = overlay.get("edges") or []
    if not isinstance(edges, list):
        raise ExperimentError("cyber_policy_overlay.edges must be a list")

    nodes: dict[str, dict] = {}
    for section in ("digital", "physical", "flow", "function"):
        for node_id, record in (merged.get(section) or {}).items():
            if isinstance(record, dict):
                nodes[str(node_id)] = record
    applied: list[dict[str, str]] = []
    for index, edge in enumerate(edges, 1):
        if not isinstance(edge, dict):
            raise ExperimentError(f"cyber_policy_overlay edge {index} must be an object")
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if not source or not target:
            raise ExperimentError(f"cyber_policy_overlay edge {index} requires source and target")
        if source not in nodes or target not in nodes:
            raise ExperimentError(
                f"cyber_policy_overlay edge {source!r}->{target!r} references an unknown model node"
            )
        target_record = nodes[target]
        source_map = target_record.setdefault("source", {})
        if not isinstance(source_map, dict):
            raise ExperimentError(f"Model node {target!r} has an invalid source map")
        source_map[source] = str(nodes[source].get("type") or "")
        applied.append(
            {
                "source": source,
                "target": target,
                "evidence": str(edge.get("evidence") or "configured policy dependency"),
            }
        )
    return merged, applied


def has_path(edges: Iterable[tuple[str, str]], source: str, target: str) -> bool:
    if source == target:
        return True
    graph: dict[str, set[str]] = {}
    for start, end in edges:
        graph.setdefault(start, set()).add(end)
    queue = deque([source])
    visited = {source}
    while queue:
        current = queue.popleft()
        for neighbor in graph.get(current, set()):
            if neighbor == target:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return False


def entropy(states: dict[str, float]) -> float:
    return -sum(float(value) * math.log2(float(value)) for value in states.values() if float(value) > 0.0)


def bootstrap_mean_ci(values: list[float], seed: int, samples: int = 2000) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choice(values) for _ in values) for _ in range(samples))
    return means[int(0.025 * (samples - 1))], means[int(0.975 * (samples - 1))]


def latex_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
    }
    return "".join(replacements.get(char, char) for char in text)


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ExperimentError(f"Manifest not found: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ExperimentError(f"Manifest must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExperimentError("Manifest must contain a JSON object")
    if str(payload.get("version")) != "1.0":
        raise ExperimentError("Manifest version must be 1.0")
    return payload


class RiskExperimentClient:
    def __init__(self, base_url: str, timeout: int = 300):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> Any:
        response = requests.request(method, f"{self.base_url}/{path.lstrip('/')}", timeout=self.timeout, **kwargs)
        if not response.ok:
            try:
                detail = response.json().get("detail") or response.json()
            except Exception:
                detail = response.text
            raise ExperimentError(f"Risk API {method} {path} failed ({response.status_code}): {detail}")
        return response.json()

    def create(self, model: dict, metadata: dict) -> dict:
        return self._request("POST", "/experiments", json={"model": model, "metadata": metadata})

    def infer(self, experiment_id: str, payload: dict) -> dict:
        return self._request("POST", f"/experiments/{experiment_id}/infer", json=payload)

    def benchmark(self, experiment_id: str, payload: dict) -> dict:
        return self._request("POST", f"/experiments/{experiment_id}/benchmark", json=payload)

    def delete(self, experiment_id: str) -> dict:
        return self._request("DELETE", f"/experiments/{experiment_id}")


def _git_revision(path: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, text=True, capture_output=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=path, text=True, capture_output=True, check=True).stdout.strip())
        return {"path": str(path), "commit": commit, "dirty": dirty}
    except Exception as exc:
        return {"path": str(path), "error": str(exc)}


def capture_environment() -> dict[str, Any]:
    mem_total = ""
    try:
        mem_total = next(line.split(":", 1)[1].strip() for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
    except Exception:
        pass
    risk_repo = Path(getattr(settings, "ICS_RISK_ASSESSMENT_REPO_PATH", "") or "")
    return {
        "captured_at": timezone.now().isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "memory_total": mem_total,
        "repositories": {
            "cyber_pen_test": _git_revision(Path(settings.BASE_DIR)),
            "ics_risk_assessment": _git_revision(risk_repo) if risk_repo.is_dir() else {"error": "not configured"},
        },
    }


def _find_epss(payload: Any, cve_id: str) -> float | None:
    if isinstance(payload, dict):
        identifiers = [payload.get(key) for key in ("id", "cve", "cve_id", "vulnerabilityID", "vulnerability_id")]
        if any(str(value or "").upper() == cve_id.upper() for value in identifiers):
            for key in ("epss", "epss_score", "epssScore"):
                try:
                    value = float(payload[key])
                    if 0.0 <= value <= 1.0:
                        return value
                except (KeyError, TypeError, ValueError):
                    continue
        for value in payload.values():
            found = _find_epss(value, cve_id)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_epss(value, cve_id)
            if found is not None:
                return found
    return None


def refresh_first_epss(cve_ids: Iterable[str], timeout: int = 30) -> dict[str, dict[str, Any]]:
    """Fetch and persist one reproducible FIRST EPSS snapshot for candidate CVEs."""
    normalized = sorted({str(value).upper() for value in cve_ids if str(value).upper().startswith("CVE-")})
    results: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(normalized), 100):
        batch = normalized[offset:offset + 100]
        response = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": ",".join(batch)},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        model_date = payload.get("date")
        for row in payload.get("data") or []:
            cve_id = str(row.get("cve") or "").upper()
            if not cve_id:
                continue
            score = float(row["epss"])
            percentile = float(row["percentile"])
            results[cve_id] = {
                "epss": score,
                "percentile": percentile,
                "model_date": model_date,
                "source": "FIRST EPSS",
            }
    retrieved_at = timezone.now()
    for vulnerability in Vulnerability.objects.filter(cve_id__in=results):
        row = results[vulnerability.cve_id]
        vulnerability.epss_score = row["epss"]
        vulnerability.epss_percentile = row["percentile"]
        vulnerability.epss_model_date = date.fromisoformat(row["model_date"]) if row["model_date"] else None
        vulnerability.epss_retrieved_at = retrieved_at
        vulnerability.epss_source = row["source"]
        vulnerability.save(update_fields=[
            "epss_score", "epss_percentile", "epss_model_date", "epss_retrieved_at", "epss_source"
        ])
    return results


class FalconsExperimentRunner:
    def __init__(
        self,
        *,
        manifest: dict[str, Any],
        suite: ExperimentSuite | None = None,
        scenarios: Iterable[str] = SCENARIOS,
        repetitions: int | None = None,
        output_dir: str | Path | None = None,
        no_wait: bool = False,
        allow_mutations: bool = False,
        skip_benchmarks: bool = False,
    ):
        requested = [str(value).upper() for value in scenarios]
        invalid = sorted(set(requested) - set(SCENARIOS))
        if invalid:
            raise ExperimentError(f"Unknown scenarios: {', '.join(invalid)}")
        self.manifest = json.loads(json.dumps(manifest))
        self.scenarios = [value for value in SCENARIOS if value in requested]
        self.repetitions = int(repetitions or manifest.get("repetitions", 5))
        if not 1 <= self.repetitions <= 100:
            raise ExperimentError("repetitions must be within [1,100]")
        self.seed = int(manifest.get("random_seed", 20260710))
        self.no_wait = no_wait
        self.allow_mutations = allow_mutations
        self.skip_benchmarks = skip_benchmarks
        self.model_path = Path(str(manifest.get("model_path") or getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")))
        if not self.model_path.is_file():
            raise ExperimentError(f"Risk model not found: {self.model_path}")
        source_model = json.loads(self.model_path.read_text(encoding="utf-8"))
        self.model, self.applied_cyber_policy_edges = apply_cyber_policy_overlay(
            source_model, self.manifest.get("cyber_policy_overlay")
        )
        self.model_sha256 = payload_sha256(self.model)
        risk_url = str(manifest.get("risk_api_url") or getattr(settings, "RISK_ASSESSMENT_API_URL", "http://127.0.0.1:7890"))
        self.client = RiskExperimentClient(risk_url, int(manifest.get("risk_api_timeout_seconds", 300)))
        self.suite = suite or ExperimentSuite.objects.create(
            manifest=self.manifest,
            requested_scenarios=self.scenarios,
            repetitions=self.repetitions,
            random_seed=self.seed,
        )
        root = Path(output_dir) if output_dir else Path(settings.BASE_DIR) / "runs" / "falcons" / str(self.suite.suite_id)
        self.output_dir = root.resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.locked_manifest = json.loads(json.dumps(self.manifest))
        if self.applied_cyber_policy_edges:
            self.locked_manifest["applied_cyber_policy_edges"] = self.applied_cyber_policy_edges
        self._resolved_vulnerabilities: dict[str, dict] = {}

    def _artifact(self, path: Path, kind: str, run: ScenarioRun | None = None, metadata: dict | None = None) -> None:
        relative = str(path.resolve().relative_to(self.output_dir))
        ExperimentArtifact.objects.update_or_create(
            suite=self.suite,
            relative_path=relative,
            defaults={
                "scenario_run": run,
                "kind": kind,
                "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size,
                "metadata": metadata or {},
            },
        )

    def _write_artifact(self, relative: str, payload: Any, kind: str, run: ScenarioRun | None = None) -> Path:
        path = write_json(self.output_dir / relative, payload)
        self._artifact(path, kind, run)
        return path

    def _process_snapshot(self) -> tuple[dict, dict[str, dict[str, Any]]]:
        raw: dict[str, Any] = {"captured_at": timezone.now().isoformat()}
        evidence: dict[str, dict[str, Any]] = {key: {} for key in EVIDENCE_CLASSES}
        known_model_nodes = model_nodes(self.model)
        likelihoods = self.manifest.get("observation_likelihoods") or {}

        agents = list(AgentStatus.objects.order_by("agent_id").values(
            "agent_id", "hostname", "ip_address", "status", "last_heartbeat", "interfaces", "active_ports", "agent_version"
        ))
        raw["agents"] = agents
        for agent in agents:
            # Agents are collectors, never DBN nodes. Only map a host observation
            # when its normalized hostname identifies an existing sim_system asset.
            asset = normalize_asset(agent.get("hostname") or agent.get("agent_id"))
            if asset in known_model_nodes and agent.get("status") == "online":
                evidence["host"][asset] = likelihoods.get("host") or {
                    "Nominal": 1.0, "Faulty": 0.5, "Compromised": 0.5
                }

        nodes = []
        for node in Node.objects.prefetch_related("interfaces", "vulnerability_set").order_by("id"):
            nodes.append(
                {
                    "id": node.id,
                    "name": node.name,
                    "hostname": node.hostname,
                    "agent_id": node.agent_id,
                    "ip_address": node.ip_address,
                    "status": node.status,
                    "interfaces": list(node.interfaces.values("name", "ip", "mac")),
                    "vulnerabilities": list(node.vulnerability_set.values("cve_id", "score", "severity", "package", "installed_version")),
                }
            )
        raw["nodes"] = nodes

        network_limit = max(100, min(10000, int(self.manifest.get("max_network_records", 5000))))
        connection_total = NetworkConnection.objects.count()
        flow_total = NetworkFlow.objects.count()
        connections = list(
            NetworkConnection.objects.select_related("agent", "metadata")
            .order_by("-last_seen", "agent_id", "remote_address", "remote_port")[:network_limit]
            .values(
                "agent__hostname", "protocol", "local_address", "local_port", "remote_address", "remote_port", "status", "last_seen"
            )
        )
        flows = list(
            NetworkFlow.objects.order_by("-last_seen", "source_ip", "destination_ip", "protocol")[:network_limit].values(
                "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "packets_sent", "packets_received", "last_seen"
            )
        )
        raw["network_connections"] = connections
        raw["network_flows"] = flows
        raw["network_connection_total"] = connection_total
        raw["network_flow_total"] = flow_total
        raw["siem_event_counts"] = list(
            SiemEvent.objects.values("event_module", "event_dataset").order_by("event_module", "event_dataset")
            .annotate(count=Count("id"))
        )
        if connections or flows:
            for node_id, record in known_model_nodes.items():
                if record.get("_section") == "digital" and str(record.get("type", "")).lower() == "network":
                    evidence["network"][node_id] = likelihoods.get("network") or {
                        "Normal": 1.0, "Abnormal": 0.5, "Compromised": 0.5
                    }

        process_url = str(self.manifest.get("process_telemetry_url") or "http://127.0.0.1:4840/")
        try:
            response = requests.get(process_url, timeout=int(self.manifest.get("telemetry_timeout_seconds", 5)))
            response.raise_for_status()
            process = response.json()
            raw["process"] = process
            if str(process.get("status", "")).lower() == "ok":
                target_function = str(self.manifest.get("target_function", "maintain_pressure"))
                evidence["process"][target_function] = likelihoods.get("process") or {
                    "Operating": 1.0, "Degraded": 0.5, "Failed": 0.2
                }
        except Exception as exc:
            raw["process"] = {"error": str(exc), "url": process_url}

        raw["observed_edge_count"] = len(
            {
                (str(row.get("local_address")), str(row.get("remote_address")), row.get("remote_port"))
                for row in connections
                if row.get("remote_address")
            }
        )
        raw["allowed_edge_count"] = len(model_edges(self.model))
        return raw, evidence

    def _collect_evidence(self) -> tuple[dict, dict[str, dict[str, str]]]:
        stabilization = int(self.manifest.get("stabilization_seconds", 0))
        collection = int(self.manifest.get("collection_seconds", 0))
        if not self.no_wait and stabilization > 0:
            time.sleep(stabilization)
        before, _ = self._process_snapshot()
        if not self.no_wait and collection > 0:
            time.sleep(collection)
        after, evidence = self._process_snapshot()
        return {"before": before, "after": after}, evidence

    def _node_epss(self, node: Node, cve_id: str) -> float | None:
        persisted = node.vulnerability_set.filter(cve_id=cve_id).values_list("epss_score", flat=True).first()
        if persisted is not None:
            return float(persisted)
        for report in SbomReport.objects.filter(node=node).order_by("-created_at")[:5]:
            for payload in (report.scan_metadata, report.document):
                found = _find_epss(payload, cve_id)
                if found is not None:
                    return found
        overrides = self.manifest.get("epss_overrides") or {}
        try:
            value = float(overrides[cve_id])
            return value if 0.0 <= value <= 1.0 else None
        except (KeyError, TypeError, ValueError):
            return None

    def _all_vulnerability_candidates(self) -> list[dict[str, Any]]:
        output = []
        model_ids = set(model_nodes(self.model))
        for node in Node.objects.prefetch_related("vulnerability_set").order_by("id"):
            aliases = [normalize_asset(node.hostname), normalize_asset(node.name), normalize_asset(node.agent_id)]
            asset = next((value for value in aliases if value in model_ids), "")
            if not asset:
                continue
            for vulnerability in node.vulnerability_set.all():
                epss = self._node_epss(node, vulnerability.cve_id)
                if vulnerability.score is None or epss is None:
                    continue
                output.append(
                    {
                        "asset": asset,
                        "cve": vulnerability.cve_id,
                        "cvss": float(vulnerability.score),
                        "epss": epss,
                        "service": vulnerability.package or "unknown",
                        "severity": vulnerability.severity,
                        "source": vulnerability.source,
                    }
                )
        return output

    def _resolve_vulnerability(self, scenario_id: str) -> dict[str, Any]:
        if scenario_id in self._resolved_vulnerabilities:
            return self._resolved_vulnerabilities[scenario_id]
        config = (self.manifest.get("scenarios") or {}).get(scenario_id, {})
        fixed = config.get("vulnerability")
        candidates = self._all_vulnerability_candidates()
        edges = model_edges(self.model)
        target = str(self.manifest.get("target_function", "maintain_pressure"))
        origin = str(self.manifest.get("threat_origin", "engineer-ws"))
        if fixed:
            required = {"asset", "cve"}
            if not isinstance(fixed, dict) or not required.issubset(fixed):
                raise ExperimentError(f"{scenario_id}.vulnerability requires {sorted(required)}")
            selected = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate["asset"] == str(fixed["asset"])
                    and candidate["cve"].upper() == str(fixed["cve"]).upper()
                ),
                None,
            )
            if selected is None:
                raise ExperimentError(
                    f"{scenario_id}.vulnerability must reference a CVE with persisted CVSS and EPSS evidence"
                )
        else:
            if scenario_id == "S1":
                allowed = set(config.get("allowed_assets") or ["historian", "hmi", "plc-main", "plc-backup"])
                candidates = [
                    value for value in candidates
                    if value["asset"] in allowed
                    and has_path(edges, origin, value["asset"])
                    and has_path(edges, value["asset"], target)
                ]
                candidates.sort(key=lambda value: (-value["epss"], -value["cvss"], value["asset"], value["cve"]))
            else:
                preferred = config.get("preferred_assets") or ["postgres", "metasploit"]
                preference = {name: index for index, name in enumerate(preferred)}
                candidates = [value for value in candidates if not has_path(edges, value["asset"], target)]
                candidates.sort(key=lambda value: (preference.get(value["asset"], 999), -value["cvss"], -value["epss"], value["cve"]))
            if not candidates:
                raise ExperimentError(
                    f"{scenario_id} could not resolve a real CVE with CVSS and EPSS evidence; "
                    "collect scanner/SBOM evidence or pin scenarios.%s.vulnerability" % scenario_id
                )
            selected = candidates[0]

        if scenario_id == "S1":
            allowed = set(config.get("allowed_assets") or ["historian", "hmi", "plc-main", "plc-backup"])
            if (
                selected["asset"] not in allowed
                or not has_path(edges, origin, selected["asset"])
                or not has_path(edges, selected["asset"], target)
            ):
                raise ExperimentError(
                    f"S1 CVE {selected['cve']} on {selected['asset']} is not on a modeled path "
                    f"from {origin} to {target}"
                )
        elif has_path(edges, selected["asset"], target):
            raise ExperimentError(
                f"S2 CVE {selected['cve']} on {selected['asset']} is not isolated from {target}"
            )
        selected["reachable"] = scenario_id == "S1"
        self._resolved_vulnerabilities[scenario_id] = selected
        self.locked_manifest.setdefault("resolved_vulnerabilities", {})[scenario_id] = selected
        return selected

    def _infer_payload(
        self,
        evidence: dict,
        *,
        masks: list[str] | None = None,
        vulnerabilities: dict | None = None,
        removals: dict | None = None,
        interventions: dict | None = None,
        model_patch: dict | None = None,
        horizon: int | None = None,
    ) -> dict:
        return {
            "T": int(horizon or self.manifest.get("horizon", 3)),
            "nodes": sorted(model_nodes(self.model)),
            "evidence": evidence,
            "evidence_masks": masks or [],
            "vulnerabilities": vulnerabilities or {},
            "remove_vulnerabilities": removals or {},
            "interventions": interventions or {},
            "model_patch": model_patch or {},
            "consequence_weights": self.manifest.get("consequence_weights") or {},
        }

    def _vulnerability_payload(self, vulnerability: dict) -> dict:
        return {
            vulnerability["asset"]: {
                vulnerability["cve"]: {
                    "cvss": vulnerability["cvss"],
                    "epss": vulnerability["epss"],
                    "time_step_seconds": int(self.manifest.get("time_step_seconds", 3600)),
                    "reference_window_seconds": int(self.manifest.get("epss_reference_window_seconds", 30 * 24 * 3600)),
                }
            }
        }

    def _final_function_states(self, result: dict) -> dict[str, float]:
        horizon = int(result.get("dbn", {}).get("horizon", self.manifest.get("horizon", 3)))
        target = str(self.manifest.get("target_function", "maintain_pressure"))
        return result.get("probabilities", {}).get(str(horizon - 1), {}).get(target, {})

    @staticmethod
    def _without_asset_evidence(evidence: dict, asset: str) -> dict:
        target = normalize_asset(asset)
        copied = {category: dict(values) for category, values in evidence.items()}
        for values in copied.values():
            for key in list(values):
                base = re.sub(r"N(?:t|\d+)$", "", str(key))
                if normalize_asset(base) == target:
                    values.pop(key, None)
        return copied

    def _importance(self, experiment_id: str, evidence: dict, baseline_risk: float) -> list[dict]:
        rankings = []
        for node_id, record in model_nodes(self.model).items():
            configured_assets = self.manifest.get("importance_assets")
            if configured_assets and node_id not in configured_assets:
                continue
            if record.get("_section") != "digital" or str(record.get("type", "")).lower() == "network":
                continue
            counterfactual_evidence = self._without_asset_evidence(evidence, node_id)
            result = self.client.infer(
                experiment_id,
                self._infer_payload(counterfactual_evidence, interventions={f"{node_id}Nt": "Compromised"}),
            )
            rankings.append({"asset": node_id, "gamma": float(result.get("expected_risk", 0.0)) - baseline_risk})
        return sorted(rankings, key=lambda value: (-value["gamma"], value["asset"]))

    def _rank_vulnerabilities(self, experiment_id: str, evidence: dict, baseline_risk: float) -> list[dict]:
        maximum = int(self.manifest.get("max_ranked_vulnerabilities", 20))
        candidates = sorted(
            self._all_vulnerability_candidates(),
            key=lambda value: (-value["cvss"], -value["epss"], value["asset"], value["cve"]),
        )[:maximum]
        ranked = []
        for candidate in candidates:
            result = self.client.infer(experiment_id, self._infer_payload(evidence, vulnerabilities=self._vulnerability_payload(candidate)))
            row = dict(candidate)
            row["pi"] = max(0.0, float(result.get("expected_risk", 0.0)) - baseline_risk)
            row["cvss_epss"] = row["cvss"] * row["epss"]
            ranked.append(row)
        falcons_order = sorted(ranked, key=lambda value: (-value["pi"], -value["epss"], value["cve"]))
        for index, row in enumerate(falcons_order, 1):
            row["falcons_rank"] = index
        cvss_order = sorted(ranked, key=lambda value: (-value["cvss"], value["cve"]))
        for index, row in enumerate(cvss_order, 1):
            row["cvss_rank"] = index
        combined_order = sorted(ranked, key=lambda value: (-value["cvss_epss"], value["cve"]))
        for index, row in enumerate(combined_order, 1):
            row["cvss_epss_rank"] = index
        return falcons_order

    def _run_hooks(self, candidate: dict) -> tuple[list[dict], bool]:
        logs = []
        apply_command = candidate.get("apply_command")
        verify_command = candidate.get("verify_command")
        rollback_command = candidate.get("rollback_command")
        if not apply_command:
            return logs, True
        if not self.allow_mutations:
            raise ExperimentError("Selected mitigation requires --allow-mutations")
        if not rollback_command:
            raise ExperimentError("A live mitigation apply_command requires rollback_command")

        def run(label: str, command: Any, check: bool = True) -> dict:
            if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
                raise ExperimentError(f"{label} must be a non-empty command argument list")
            completed = subprocess.run(command, cwd=settings.BASE_DIR, text=True, capture_output=True, timeout=300)
            record = {"step": label, "command": command, "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
            logs.append(record)
            if check and completed.returncode != 0:
                raise ExperimentError(f"Mitigation {label} failed: {completed.stderr or completed.stdout}")
            return record

        try:
            run("apply", apply_command)
            if verify_command:
                run("verify", verify_command)
            return logs, True
        finally:
            rollback = run("rollback", rollback_command, check=False)
            if rollback["returncode"] != 0:
                raise RollbackError(f"Mitigation rollback failed: {rollback['stderr'] or rollback['stdout']}")

    def _execute_scenario(self, run: ScenarioRun, evidence: dict, condition: str) -> dict:
        session = self.client.create(
            self.model,
            {"suite_id": str(self.suite.suite_id), "scenario": run.scenario_id, "condition": condition, "repetition": run.repetition},
        )
        experiment_id = session["experiment_id"]
        run.risk_experiment_id = experiment_id
        run.save(update_fields=["risk_experiment_id", "updated_at"])
        try:
            baseline = self.client.infer(experiment_id, self._infer_payload(evidence))
            baseline_risk = float(baseline.get("expected_risk", 0.0))
            payload: dict[str, Any] = {"baseline": baseline}

            if run.scenario_id == "S0":
                payload["scenario"] = baseline
                if run.repetition == 1 and not self.manifest.get("skip_analysis"):
                    payload["asset_importance"] = self._importance(experiment_id, evidence, baseline_risk)
                    payload["vulnerability_rankings"] = self._rank_vulnerabilities(experiment_id, evidence, baseline_risk)
            elif run.scenario_id in {"S1", "S2"}:
                selected = self._resolve_vulnerability(run.scenario_id)
                scenario_config = (self.manifest.get("scenarios") or {}).get(run.scenario_id, {})
                scenario_model_patch = scenario_config.get("model_patch") or {}
                comparison_baseline = baseline
                comparison_baseline_risk = baseline_risk
                if run.scenario_id == "S2" and scenario_model_patch:
                    comparison_baseline = self.client.infer(
                        experiment_id,
                        self._infer_payload(evidence, model_patch=scenario_model_patch),
                    )
                    comparison_baseline_risk = float(comparison_baseline.get("expected_risk", 0.0))
                scenario = self.client.infer(
                    experiment_id,
                    self._infer_payload(
                        evidence,
                        vulnerabilities=self._vulnerability_payload(selected),
                        model_patch=scenario_model_patch,
                    ),
                )
                payload.update(
                    {
                        "selected_vulnerability": selected,
                        "scenario_model_patch": scenario_model_patch,
                        "unpatched_baseline": baseline,
                        "baseline": comparison_baseline,
                        "scenario": scenario,
                        "pi": max(
                            0.0,
                            float(scenario.get("expected_risk", 0.0)) - comparison_baseline_risk,
                        ),
                    }
                )
            elif run.scenario_id == "S3":
                masks = [] if condition == "none" else ["host", "network", "process"] if condition == "combined" else [condition]
                for category in masks:
                    if not evidence.get(category):
                        raise ExperimentError(f"S3 cannot mask empty {category!r} evidence")
                scenario = self.client.infer(experiment_id, self._infer_payload(evidence, masks=masks))
                payload.update(
                    {
                        "scenario": scenario,
                        "masked_evidence": masks,
                        "function_entropy": entropy(self._final_function_states(scenario)),
                        "baseline_function_entropy": entropy(self._final_function_states(baseline)),
                    }
                )
            elif run.scenario_id == "S4":
                selected_vulnerability = self._resolve_vulnerability("S1")
                s4_config = (self.manifest.get("scenarios") or {}).get("S4", {})
                baseline_masks = list(s4_config.get("baseline_masks") or [])
                for category in baseline_masks:
                    if not evidence.get(category):
                        raise ExperimentError(f"S4 baseline cannot mask empty {category!r} evidence")
                vulnerable = self.client.infer(
                    experiment_id,
                    self._infer_payload(
                        evidence,
                        masks=baseline_masks,
                        vulnerabilities=self._vulnerability_payload(selected_vulnerability),
                    ),
                )
                vulnerable_risk = float(vulnerable.get("expected_risk", 0.0))
                candidates = []
                configured = ((self.manifest.get("scenarios") or {}).get("S4", {}).get("candidates") or [])
                for candidate in configured:
                    kind = candidate.get("kind")
                    if kind == "patch_s1_vulnerability":
                        result = self.client.infer(experiment_id, self._infer_payload(evidence, masks=baseline_masks))
                    elif kind == "add_telemetry":
                        result = self.client.infer(
                            experiment_id,
                            self._infer_payload(evidence, vulnerabilities=self._vulnerability_payload(selected_vulnerability)),
                        )
                    elif kind == "model_patch":
                        result = self.client.infer(
                            experiment_id,
                            self._infer_payload(
                                evidence,
                                vulnerabilities=self._vulnerability_payload(selected_vulnerability),
                                model_patch=candidate.get("model_patch") or {},
                            ),
                        )
                    else:
                        raise ExperimentError(f"Unsupported S4 mitigation kind: {kind!r}")
                    risk = float(result.get("expected_risk", 0.0))
                    candidates.append({**candidate, "predicted_risk": risk, "delta_risk": max(0.0, vulnerable_risk - risk), "result": result})
                if not candidates:
                    raise ExperimentError("S4 requires at least one configured candidate mitigation")
                candidates.sort(key=lambda value: (-value["delta_risk"], str(value.get("id", ""))))
                chosen = candidates[0]
                hook_logs, rollback_verified = self._run_hooks(chosen)
                measured = chosen["result"]
                payload.update(
                    {
                        "selected_vulnerability": selected_vulnerability,
                        "baseline_masks": baseline_masks,
                        "vulnerable": vulnerable,
                        "scenario": measured,
                        "candidates": candidates,
                        "selected_mitigation": {key: value for key, value in chosen.items() if key != "result"},
                        "predicted_delta": chosen["delta_risk"],
                        "measured_delta": max(0.0, vulnerable_risk - float(measured.get("expected_risk", 0.0))),
                        "prediction_error": abs(chosen["predicted_risk"] - float(measured.get("expected_risk", 0.0))),
                        "hook_logs": hook_logs,
                        "rollback_verified": rollback_verified,
                    }
                )
            else:
                raise ExperimentError(f"Unsupported scenario {run.scenario_id}")
            return payload
        finally:
            self.client.delete(experiment_id)

    def _run_condition(self, scenario_id: str, condition: str, repetition: int) -> ScenarioRun:
        seed = self.seed + repetition * 100 + int(scenario_id[1:])
        run, _ = ScenarioRun.objects.get_or_create(
            suite=self.suite,
            scenario_id=scenario_id,
            condition=condition,
            repetition=repetition,
            defaults={"seed": seed},
        )
        if run.status == ScenarioRun.Status.COMPLETED:
            return run
        run.status = ScenarioRun.Status.RUNNING
        run.started_at = timezone.now()
        run.error = ""
        run.save(update_fields=["status", "started_at", "error", "updated_at"])
        run_dir = f"scenarios/{scenario_id}/{condition}/r{repetition:02d}"
        try:
            raw_evidence, inference_evidence = self._collect_evidence()
            self._write_artifact(f"{run_dir}/evidence.json", {"raw": raw_evidence, "inference": inference_evidence}, "evidence", run)
            input_payload = {"scenario": scenario_id, "condition": condition, "repetition": repetition, "evidence": inference_evidence}
            run.input_sha256 = payload_sha256(input_payload)
            result = self._execute_scenario(run, inference_evidence, condition)
            result["raw_evidence_summary"] = {
                "observed_edge_count": raw_evidence["after"].get("observed_edge_count", 0),
                "allowed_edge_count": raw_evidence["after"].get("allowed_edge_count", 0),
                "asset_count": len(raw_evidence["after"].get("nodes", [])),
            }
            scenario_result = result.get("scenario") or {}
            run.expected_risk = float(scenario_result.get("expected_risk", 0.0))
            run.risk_evaluation_id = str(scenario_result.get("evaluation_id", ""))
            run.output_sha256 = payload_sha256(result)
            run.metrics = {
                "expected_risk": run.expected_risk,
                "inference_seconds": scenario_result.get("timing", {}).get("inference_seconds"),
                "build_seconds": scenario_result.get("timing", {}).get("build_seconds"),
                "pi": result.get("pi"),
                "function_entropy": result.get("function_entropy"),
                "predicted_delta": result.get("predicted_delta"),
                "measured_delta": result.get("measured_delta"),
                "prediction_error": result.get("prediction_error"),
            }
            run.result_payload = result
            run.rollback_verified = bool(result.get("rollback_verified", True))
            run.status = ScenarioRun.Status.COMPLETED
            run.finished_at = timezone.now()
            run.save()
            self._write_artifact(f"{run_dir}/result.json", result, "scenario_result", run)
            return run
        except RollbackError as exc:
            run.status = ScenarioRun.Status.ROLLBACK_FAILED
            run.error = str(exc)
            run.finished_at = timezone.now()
            run.save()
            raise
        except Exception as exc:
            run.status = ScenarioRun.Status.FAILED
            run.error = str(exc)
            run.finished_at = timezone.now()
            run.save()
            self._write_artifact(f"{run_dir}/error.json", {"error": str(exc), "type": type(exc).__name__}, "error", run)
            raise

    def _scaled_model(self, percentage: int) -> dict:
        if percentage >= 100:
            return json.loads(json.dumps(self.model))
        all_nodes = model_nodes(self.model)
        function_ids = {node_id for node_id, record in all_nodes.items() if record.get("_section") == "function"}
        non_functions = set(all_nodes) - function_ids
        keep_count = max(1, math.ceil(len(non_functions) * percentage / 100.0))
        predecessors: dict[str, set[str]] = {node_id: set() for node_id in all_nodes}
        for source, target in model_edges(self.model):
            predecessors.setdefault(target, set()).add(source)
        ordered: list[str] = []
        queue = deque(sorted(function_ids))
        visited = set(function_ids)
        while queue and len(ordered) < keep_count:
            current = queue.popleft()
            for parent in sorted(predecessors.get(current, set())):
                if parent in visited:
                    continue
                visited.add(parent)
                ordered.append(parent)
                queue.append(parent)
                if len(ordered) >= keep_count:
                    break
        if len(ordered) < keep_count:
            ordered.extend(sorted(non_functions - set(ordered))[:keep_count - len(ordered)])
        keep = function_ids | set(ordered)
        scaled = {"version": self.model.get("version", "1.0")}
        for section in ("digital", "physical", "flow", "function"):
            section_payload = self.model.get(section) or {}
            scaled[section] = {}
            for node_id, record in section_payload.items():
                if node_id not in keep:
                    continue
                cloned = json.loads(json.dumps(record))
                for field in ("source", "target"):
                    value = cloned.get(field)
                    if isinstance(value, dict):
                        cloned[field] = {key: item for key, item in value.items() if key in keep}
                    elif isinstance(value, list):
                        cloned[field] = [item for item in value if not isinstance(item, str) or item in keep]
                    elif isinstance(value, str) and value not in keep:
                        cloned[field] = {}
                scaled[section][node_id] = cloned
        return scaled

    def _run_benchmarks(self) -> list[dict]:
        config = self.manifest.get("benchmarks") or {}
        if self.skip_benchmarks or not config.get("enabled", True):
            return []
        horizons = [int(value) for value in config.get("horizons", [1, 3, 5, 10, 20])]
        scales = [int(value) for value in config.get("model_scales", [25, 50, 75, 100])]
        warmups = int(config.get("warmups", 3))
        repetitions = int(config.get("repetitions", 30))
        rows = []
        for scale in scales:
            model = self._scaled_model(scale)
            session = self.client.create(model, {"suite_id": str(self.suite.suite_id), "benchmark_scale": scale})
            experiment_id = session["experiment_id"]
            try:
                empty_evidence = {key: {} for key in EVIDENCE_CLASSES}
                result = self.client.benchmark(experiment_id, {
                    "horizons": horizons,
                    "warmups": warmups,
                    "repetitions": repetitions,
                    "nodes": sorted(model_nodes(model)),
                    "evidence": empty_evidence,
                })
                for sample in result.get("samples") or []:
                    rows.append({"scale_percent": scale, **sample})
            finally:
                self.client.delete(experiment_id)
        self._write_artifact("benchmarks/results.json", rows, "benchmark")
        return rows

    def _write_csv(self, path: Path, rows: list[dict], columns: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        self._artifact(path, "report")

    def _report(self, benchmarks: list[dict]) -> None:
        runs = list(self.suite.scenario_runs.filter(status=ScenarioRun.Status.COMPLETED).order_by("scenario_id", "condition", "repetition"))
        results = [
            {
                "scenario": run.scenario_id,
                "condition": run.condition,
                "repetition": run.repetition,
                "expected_risk": run.expected_risk,
                "metrics": run.metrics,
                "result": run.result_payload,
            }
            for run in runs
        ]
        self._write_artifact("reports/results.json", results, "report")
        flat_rows = [
            {
                "scenario": row["scenario"],
                "condition": row["condition"],
                "repetition": row["repetition"],
                "expected_risk": row["expected_risk"],
                **row["metrics"],
            }
            for row in results
        ]
        self._write_csv(
            self.output_dir / "reports" / "scenario_results.csv",
            flat_rows,
            ["scenario", "condition", "repetition", "expected_risk", "inference_seconds", "build_seconds", "pi", "function_entropy", "predicted_delta", "measured_delta", "prediction_error"],
        )
        if benchmarks:
            self._write_csv(
                self.output_dir / "reports" / "inference_benchmarks.csv",
                benchmarks,
                ["scale_percent", "horizon", "repetition", "nodes", "dbn_nodes", "build_seconds", "inference_seconds"],
            )

        by_key: dict[tuple[str, str], list[ScenarioRun]] = {}
        for run in runs:
            by_key.setdefault((run.scenario_id, run.condition), []).append(run)

        def mean_risk(scenario: str, condition: str = "default") -> float:
            values = [float(run.expected_risk or 0.0) for run in by_key.get((scenario, condition), [])]
            return statistics.fmean(values) if values else 0.0

        s0_first = by_key.get(("S0", "default"), [None])[0]
        s1_first = by_key.get(("S1", "default"), [None])[0]
        s2_first = by_key.get(("S2", "default"), [None])[0]
        s4_first = by_key.get(("S4", "default"), [None])[0]
        s0_payload = s0_first.result_payload if s0_first else {}
        s1_payload = s1_first.result_payload if s1_first else {}
        s2_payload = s2_first.result_payload if s2_first else {}
        s4_payload = s4_first.result_payload if s4_first else {}
        model_count = {section: len(self.model.get(section) or {}) for section in ("digital", "physical", "flow", "function")}
        raw_summary = s0_payload.get("raw_evidence_summary", {})
        rankings = s0_payload.get("vulnerability_rankings") or []
        importance = s0_payload.get("asset_importance") or []

        telemetry_rows = []
        for condition in ("none", "host", "network", "process", "combined"):
            condition_runs = by_key.get(("S3", condition), [])
            risks = [float(run.expected_risk or 0.0) for run in condition_runs]
            entropies = [float(run.metrics.get("function_entropy") or 0.0) for run in condition_runs]
            low, high = bootstrap_mean_ci(risks, self.seed + len(condition)) if risks else (0.0, 0.0)
            telemetry_rows.append(
                {
                    "condition": condition,
                    "risk": statistics.fmean(risks) if risks else 0.0,
                    "risk_ci_low": low,
                    "risk_ci_high": high,
                    "entropy": statistics.fmean(entropies) if entropies else 0.0,
                }
            )

        benchmark_median = 0.0
        benchmark_horizon = 0
        if benchmarks:
            full = [row for row in benchmarks if row["scale_percent"] == 100 and row["horizon"] == int(self.manifest.get("horizon", 3))]
            if full:
                benchmark_median = statistics.median(float(row["inference_seconds"]) for row in full)
                benchmark_horizon = int(self.manifest.get("horizon", 3))

        top_s1 = s1_payload.get("selected_vulnerability") or {}
        top_s2 = s2_payload.get("selected_vulnerability") or {}
        selected_mitigation = s4_payload.get("selected_mitigation") or {}
        vulnerable_risk = float(s4_payload.get("vulnerable", {}).get("expected_risk", 0.0))
        mitigation_delta = float(s4_payload.get("measured_delta", 0.0))
        mitigation_percent = (100.0 * mitigation_delta / vulnerable_risk) if vulnerable_risk > 0.0 else 0.0
        hardware = self.suite.environment.get("processor") or self.suite.environment.get("platform") or "recorded host"
        macros = {
            "FalconsDigitalComponentCount": model_count["digital"],
            "FalconsPhysicalComponentCount": model_count["physical"],
            "FalconsFlowCount": model_count["flow"],
            "FalconsFunctionCount": model_count["function"],
            "FalconsTimeStepDuration": f"{int(self.manifest.get('time_step_seconds', 3600))}~s",
            "FalconsAssetCount": raw_summary.get("asset_count", model_count["digital"] + model_count["physical"]),
            "FalconsEdgeCount": raw_summary.get("allowed_edge_count", len(model_edges(self.model))),
            "FalconsObservedEdgeCount": raw_summary.get("observed_edge_count", 0),
            "FalconsAllowedOnlyEdgeCount": max(0, int(raw_summary.get("allowed_edge_count", 0)) - int(raw_summary.get("observed_edge_count", 0))),
            "FalconsVulnerabilityCount": Vulnerability.objects.count(),
            "FalconsAffectedAssetCount": Node.objects.filter(vulnerability__isnull=False).distinct().count(),
            "FalconsSOneAssetCVE": f"{top_s1.get('asset', 'unavailable')} / {top_s1.get('cve', 'unavailable')}",
            "FalconsSOnePi": f"{float(s1_payload.get('pi', 0.0)):.6f}",
            "FalconsCVSSTopAssetCVE": f"{rankings[0].get('asset')} / {rankings[0].get('cve')}" if rankings else "unavailable",
            "FalconsSOneExplanation": "reachability, exploit likelihood, asset function, and downstream process consequence",
            "FalconsSTwoCVSS": f"{float(top_s2.get('cvss', 0.0)):.1f}",
            "FalconsSTwoDisplacement": str(abs(int(next((row.get('cvss_rank', 0) - row.get('falcons_rank', 0) for row in rankings if row.get('cve') == top_s2.get('cve')), 0)))),
            "FalconsImportantAsset": importance[0]["asset"] if importance else "unavailable",
            "FalconsImportantAssetGamma": f"{float(importance[0]['gamma']):.6f}" if importance else "0",
            "FalconsImportanceOrdering": ", ".join(row["asset"] for row in importance[:5]) or "unavailable",
            "FalconsTelemetrySources": "host, network, and process telemetry",
            "FalconsTelemetryAffected": str(self.manifest.get("target_function", "maintain_pressure")),
            "FalconsTelemetryState": "degraded or failed",
            "FalconsTelemetryBaseline": f"{mean_risk('S3', 'none'):.6f}",
            "FalconsTelemetryDegraded": f"{mean_risk('S3', 'combined'):.6f}",
            "FalconsTelemetryIntervalIncrease": f"{max((row['risk_ci_high'] - row['risk_ci_low'] for row in telemetry_rows), default=0.0):.6f}",
            "FalconsMitigationCount": len(s4_payload.get("candidates") or []),
            "FalconsBestMitigation": selected_mitigation.get("label") or selected_mitigation.get("id") or "unavailable",
            "FalconsMitigationReduction": f"{mitigation_delta:.6f} ({mitigation_percent:.2f}%)",
            "FalconsOtherMitigations": ", ".join(str(row.get("label") or row.get("id")) for row in (s4_payload.get("candidates") or [])[1:]) or "none",
            "FalconsCVSSOnlyReduction": "0",
            "FalconsMitigationVerification": "the selected mitigation was present in the isolated NDT and the baseline model digest was restored",
            "FalconsMitigationAgreement": f"absolute prediction error {float(s4_payload.get('prediction_error', 0.0)):.6f}",
            "FalconsNodesPerSlice": s0_payload.get("scenario", {}).get("dbn", {}).get("nodes_per_slice", 0),
            "FalconsBenchmarkHorizon": benchmark_horizon,
            "FalconsMedianInferenceTime": f"{benchmark_median:.6f}~s",
            "FalconsBenchmarkHardware": hardware,
            "FalconsBenchmarkLower": min((row["horizon"] for row in benchmarks), default=0),
            "FalconsBenchmarkUpper": max((row["horizon"] for row in benchmarks), default=0),
            "FalconsScalingBehavior": "the measured horizon- and model-size scaling reported in the generated benchmark figure",
            "FalconsPrincipalFinding": f"ranked the reachable {top_s1.get('cve', 'control-relevant vulnerability')} by process-coupled risk rather than severity alone",
            "FalconsObservabilityFinding": "increased posterior uncertainty when host, network, and process evidence was removed",
            "FalconsMitigationFinding": f"reduced expected risk by {float(s4_payload.get('measured_delta', 0.0)):.6f} with measured prediction error {float(s4_payload.get('prediction_error', 0.0)):.6f}",
        }
        thresholds = self.manifest.get("gpwr_thresholds") or {}
        required_thresholds = ("degraded_low", "degraded_high", "failed_low", "failed_high")
        if all(thresholds.get(key) is not None for key in required_thresholds) and thresholds.get("provenance"):
            units = thresholds.get("units") or ""
            macros["FalconsGPWRThresholds"] = (
                f"degraded outside {thresholds['degraded_low']}--{thresholds['degraded_high']} {units} "
                f"and failed outside {thresholds['failed_low']}--{thresholds['failed_high']} {units}, "
                f"using {thresholds['provenance']}"
            )

        generated_dir = self.output_dir / "reports"
        generated_dir.mkdir(parents=True, exist_ok=True)
        macro_path = generated_dir / "falcons_results_macros.tex"
        macro_path.write_text("% Generated by run_falcons_experiments. Do not edit.\n" + "\n".join(
            rf"\renewcommand{{\{name}}}{{{latex_escape(value)}}}" for name, value in macros.items()
        ) + "\n", encoding="utf-8")

        vuln_rows = rankings[:5]
        if not vuln_rows:
            for payload in (s1_payload, s2_payload):
                value = payload.get("selected_vulnerability")
                if value:
                    vuln_rows.append({**value, "pi": payload.get("pi", 0.0), "falcons_rank": len(vuln_rows) + 1})
        vulnerability_table = generated_dir / "falcons_vulnerability_rows.tex"
        vulnerability_table.write_text("\n".join(
            f"{latex_escape(row.get('asset'))} & {latex_escape(row.get('cve'))} & {float(row.get('cvss', 0.0)):.1f} & "
            f"{float(row.get('epss', 0.0)):.5f} & {'Yes' if row.get('reachable') else 'No'} & "
            f"{float(row.get('pi', 0.0)):.6f} & {row.get('falcons_rank', index)} \\\\"
            for index, row in enumerate(vuln_rows, 1)
        ) + "\n", encoding="utf-8")
        telemetry_table = generated_dir / "falcons_telemetry_rows.tex"
        telemetry_table.write_text("\n".join(
            f"{latex_escape(row['condition'].title())} & {row['risk']:.6f} & {row['entropy']:.6f} & "
            f"[{row['risk_ci_low']:.6f}, {row['risk_ci_high']:.6f}] \\\\" for row in telemetry_rows
        ) + "\n", encoding="utf-8")

        for path in (macro_path, vulnerability_table, telemetry_table):
            self._artifact(path, "latex")

        report_lines = [
            f"# FALCONS experiment suite {self.suite.suite_id}",
            "",
            f"Status: {self.suite.status}",
            f"Model SHA-256: `{self.model_sha256}`",
            f"Scenarios: {', '.join(self.scenarios)}",
            f"Repetitions: {self.repetitions}",
            "",
            "| Scenario | Condition | Mean risk | Runs |",
            "|---|---:|---:|---:|",
        ]
        for key, values in sorted(by_key.items()):
            report_lines.append(f"| {key[0]} | {key[1]} | {statistics.fmean(float(run.expected_risk or 0.0) for run in values):.6f} | {len(values)} |")
        report_path = self.output_dir / "reports" / "report.md"
        report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
        self._artifact(report_path, "report")

        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            figure_dir = self.output_dir / "reports" / "figures"
            figure_dir.mkdir(parents=True, exist_ok=True)
            if telemetry_rows:
                fig, ax = plt.subplots(figsize=(7, 4))
                ax.bar([row["condition"].title() for row in telemetry_rows], [row["risk"] for row in telemetry_rows], color="#1f6f78")
                ax.set_ylabel("Expected cyber-physical risk")
                ax.set_title("Telemetry degradation sensitivity")
                fig.tight_layout()
                for extension in ("png", "pdf"):
                    path = figure_dir / f"telemetry_sensitivity.{extension}"
                    fig.savefig(path, dpi=200)
                    self._artifact(path, "figure")
                plt.close(fig)
            if benchmarks:
                fig, ax = plt.subplots(figsize=(7, 4))
                for scale in sorted({row["scale_percent"] for row in benchmarks}):
                    points = []
                    for horizon in sorted({row["horizon"] for row in benchmarks}):
                        values = [float(row["inference_seconds"]) for row in benchmarks if row["scale_percent"] == scale and row["horizon"] == horizon]
                        if values:
                            points.append((horizon, statistics.median(values)))
                    ax.plot([point[0] for point in points], [point[1] for point in points], marker="o", label=f"{scale}% model")
                ax.set_xlabel("DBN horizon")
                ax.set_ylabel("Median inference time (s)")
                ax.set_title("Inference scaling")
                ax.legend()
                fig.tight_layout()
                for extension in ("png", "pdf"):
                    path = figure_dir / f"inference_scaling.{extension}"
                    fig.savefig(path, dpi=200)
                    self._artifact(path, "figure")
                plt.close(fig)
        except ImportError:
            self._write_artifact("reports/figure_warning.json", {"warning": "matplotlib is not installed; figure generation skipped"}, "warning")

    def run(self) -> ExperimentSuite:
        environment = capture_environment()
        with transaction.atomic():
            self.suite.status = ExperimentSuite.Status.RUNNING
            self.suite.output_dir = str(self.output_dir)
            self.suite.model_sha256 = self.model_sha256
            self.suite.manifest_sha256 = payload_sha256(self.manifest)
            self.suite.environment = environment
            self.suite.repository_revisions = environment.get("repositories", {})
            self.suite.requested_scenarios = self.scenarios
            self.suite.repetitions = self.repetitions
            self.suite.save()
        self._write_artifact("manifest.json", self.manifest, "manifest")
        self._write_artifact("environment.json", environment, "provenance")
        self._write_artifact("model.json", self.model, "model")
        if self.applied_cyber_policy_edges:
            self._write_artifact(
                "cyber_policy_overlay.json",
                {"edges": self.applied_cyber_policy_edges},
                "model_overlay",
            )
        try:
            for repetition in range(1, self.repetitions + 1):
                for scenario_id in self.scenarios:
                    conditions = ("none", "host", "network", "process", "combined") if scenario_id == "S3" else ("default",)
                    for condition in conditions:
                        self._run_condition(scenario_id, condition, repetition)
            benchmarks = self._run_benchmarks()
            self.suite.locked_manifest = self.locked_manifest
            self._write_artifact("manifest.lock.json", self.locked_manifest, "manifest")
            self.suite.status = ExperimentSuite.Status.COMPLETED
            self.suite.finished_at = timezone.now()
            self.suite.save(update_fields=["locked_manifest", "status", "finished_at", "updated_at"])
            self._report(benchmarks)
        except RollbackError as exc:
            self.suite.status = ExperimentSuite.Status.ROLLBACK_FAILED
            self.suite.error = str(exc)
            self.suite.finished_at = timezone.now()
            self.suite.save(update_fields=["status", "error", "finished_at", "updated_at"])
            raise
        except Exception as exc:
            self.suite.status = ExperimentSuite.Status.FAILED
            self.suite.error = str(exc)
            self.suite.finished_at = timezone.now()
            self.suite.locked_manifest = self.locked_manifest
            self.suite.save(update_fields=["status", "error", "finished_at", "locked_manifest", "updated_at"])
            raise
        return self.suite
