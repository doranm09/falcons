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
    ScanVulnerability,
    SiemEvent,
    Vulnerability,
    AlertRule,
    Alert,
    Case,
    CaseNote,
    CaseEvidence,
    CampaignRun,
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
import socket
import subprocess
import requests
from django.http import JsonResponse, FileResponse, Http404, HttpResponse, StreamingHttpResponse
from .tasks import (
    scan_network_task,
    launch_openvas_scan_task,
    nmap_discovery_task,
    parse_and_save_vulnerabilities,
    scan_sbom_vulnerabilities_task,
    run_ot_campaign_task,
)
from .openvas_client import openvas_session, get_task_status, get_report_id, download_report
from celery.result import AsyncResult
from .models import Link
from .risk_assessment import build_cyber_data_for_risk_nodes, summarize_risk_results
from .utils import dijkstra, list_interfaces
from .sbom import (
    detect_sbom_format,
    extract_cyber_template_table_rows,
    extract_os_summary_from_sbom,
    extract_packages_from_sbom,
    extract_vulnerability_table_rows_from_models,
    extract_vulnerability_table_rows,
    extract_vulnerabilities_from_sbom,
    extract_sbom_table_rows,
    compute_payload_hash,
)
from .minimega import build_minimega_script, build_digital_twin_manifest
from django.views.decorators.http import require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.timezone import now
from django.utils import timezone
from typing import Optional
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import os
import shutil
from collections import defaultdict
from django.conf import settings
from django.db import transaction
from django.db.models import Count
from ipaddress import ip_network
from pathlib import Path
import time
from datetime import timedelta
from functools import wraps
from typing import Optional
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
from .pid_drawio import (
    build_timestamp_prefix,
    convert_drawio_to_sim_system,
    store_drawio_upload,
    upload_sim_system,
)
from .gvmd import fetch_gvmd_findings_for_ips


def _node_asset_ips(node: Node) -> set[str]:
    ips = set()
    primary_ip = str(getattr(node, "ip_address", "") or "").strip()
    if primary_ip:
        ips.add(primary_ip)
    for iface in getattr(node, "interfaces", []).all():
        iface_ip = str(getattr(iface, "ip", "") or "").strip()
        if iface_ip:
            ips.add(iface_ip)
    return ips


def _hostname_for_node(node: Optional[Node], fallback_ip: str = "") -> str:
    if node:
        hostname = str(getattr(node, "hostname", "") or "").strip()
        if hostname:
            return hostname
        candidate = str(getattr(node, "name", "") or "").strip()
        if candidate and candidate != str(fallback_ip or "").strip():
            return candidate
    return ""


def _latest_nodes_by_asset_ip(nodes):
    latest_node_by_ip = {}
    for node in nodes:
        for ip_text in _node_asset_ips(node):
            if ip_text and ip_text not in latest_node_by_ip:
                latest_node_by_ip[ip_text] = node
    return latest_node_by_ip
from knowledge_extraction.drawio import DrawioParseError
from .pid_system import (
    build_system_elements,
    load_sim_system_file,
    resolve_sim_system_path,
)
from .pid_network import (
    expected_cyber_nodes,
    summarize_expected_nodes,
    validate_expected_nodes,
)
from .pid_testbed import build_testbed_from_sim_system

SNIFFER_BASE_URL = 'http://localhost:5050'
RISK_ASSESSMENT_TIMEOUT = 15
SIEM_WRITE_ROLES = (SiemUserRole.Role.ADMIN, SiemUserRole.Role.ANALYST)


def _sbom_severity_rank(value: str) -> int:
    ranks = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "negligible": 1,
        "unknown": 0,
        "": 0,
    }
    return ranks.get(str(value or "").strip().lower(), 0)


PURDUE_TOPOLOGY_LAYERS = [
    {"slug": "L4", "label": "Level 4 / Enterprise IT", "accent": "primary"},
    {"slug": "L3.5", "label": "Level 3.5 / DMZ & Firewalls", "accent": "warning"},
    {"slug": "L3", "label": "Level 3 / Operations", "accent": "info"},
    {"slug": "L2", "label": "Level 2 / Supervisory", "accent": "success"},
    {"slug": "L1", "label": "Level 1 / Control", "accent": "secondary"},
    {"slug": "L0", "label": "Level 0 / Process", "accent": "dark"},
]

IAEA_TESTBED_STATIC_TOPOLOGY = [
    {"hostname": "database", "label": "database", "ip_address": "10.4.50.20", "layer": "L4", "role_slug": "database", "role_label": "Database", "icon": "bi-database-fill", "segment_label": "Enterprise LAN"},
    {"hostname": "metasploit", "label": "metasploit", "ip_address": "10.4.50.10", "layer": "L4", "role_slug": "offensive", "role_label": "Offensive Host", "icon": "bi-bug-fill", "segment_label": "Enterprise LAN"},
    {"hostname": "postgres", "label": "postgres", "ip_address": "10.4.50.41", "layer": "L4", "role_slug": "database", "role_label": "Database", "icon": "bi-database-fill", "segment_label": "Enterprise LAN"},
    {"hostname": "historian-db", "label": "historian-db", "ip_address": "10.4.50.30", "layer": "L4", "role_slug": "database", "role_label": "Database", "icon": "bi-database-fill", "segment_label": "Enterprise LAN"},
    {"hostname": "firewall-2", "label": "firewall-2", "ip_address": "10.3.50.254", "layer": "L3.5", "role_slug": "firewall", "role_label": "Firewall", "icon": "bi-shield-lock-fill", "segment_label": "Operations LAN"},
    {"hostname": "firewall-1", "label": "firewall-1", "ip_address": "10.2.50.254", "layer": "L3.5", "role_slug": "firewall", "role_label": "Firewall", "icon": "bi-shield-lock-fill", "segment_label": "Supervisory LAN"},
    {"hostname": "historian", "label": "historian", "ip_address": "10.2.50.31", "layer": "L3", "role_slug": "server", "role_label": "Server", "icon": "bi-server", "segment_label": "Operations LAN"},
    {"hostname": "hmi", "label": "hmi", "ip_address": "10.2.50.10", "layer": "L2", "role_slug": "supervisory", "role_label": "Supervisory", "icon": "bi-display-fill", "segment_label": "Supervisory LAN"},
    {"hostname": "ignition", "label": "ignition", "ip_address": "10.2.50.40", "layer": "L2", "role_slug": "supervisory", "role_label": "Supervisory", "icon": "bi-display-fill", "segment_label": "Supervisory LAN"},
    {"hostname": "engineer-ws", "label": "engineer-ws", "ip_address": "10.2.50.20", "layer": "L2", "role_slug": "workstation", "role_label": "Workstation", "icon": "bi-laptop-fill", "segment_label": "Supervisory LAN"},
    {"hostname": "l2-jump", "label": "l2-jump", "ip_address": "10.2.50.30", "layer": "L2", "role_slug": "workstation", "role_label": "Workstation", "icon": "bi-laptop-fill", "segment_label": "Supervisory LAN"},
    {"hostname": "firewall-0", "label": "firewall-0", "ip_address": "10.1.13.253", "layer": "L1", "role_slug": "firewall", "role_label": "Firewall", "icon": "bi-shield-lock-fill", "segment_label": "Main Control Cell"},
    {"hostname": "firewall-main-cell", "label": "firewall-main-cell", "ip_address": "10.1.13.252", "layer": "L1", "role_slug": "firewall", "role_label": "Firewall", "icon": "bi-shield-lock-fill", "segment_label": "Main Control Cell"},
    {"hostname": "firewall-backup-cell", "label": "firewall-backup-cell", "ip_address": "10.2.23.252", "layer": "L1", "role_slug": "firewall", "role_label": "Firewall", "icon": "bi-shield-lock-fill", "segment_label": "Backup Control Cell"},
    {"hostname": "plc-backup", "label": "plc-backup", "ip_address": "10.2.23.10", "layer": "L1", "role_slug": "controller", "role_label": "Controller", "icon": "bi-cpu-fill", "segment_label": "Backup Control Cell"},
    {"hostname": "vc-hv455a", "label": "vc-hv455a", "ip_address": "10.3.13.1", "layer": "L0", "role_slug": "actuator", "role_label": "Actuator", "icon": "bi-sliders", "segment_label": "Main Process Cell"},
    {"hostname": "vc-pv455b", "label": "vc-pv455b", "ip_address": "10.3.13.2", "layer": "L0", "role_slug": "actuator", "role_label": "Actuator", "icon": "bi-sliders", "segment_label": "Main Process Cell"},
    {"hostname": "vc-pv455c", "label": "vc-pv455c", "ip_address": "10.3.13.3", "layer": "L0", "role_slug": "actuator", "role_label": "Actuator", "icon": "bi-sliders", "segment_label": "Main Process Cell"},
    {"hostname": "heat-ctrl", "label": "heat-ctrl", "ip_address": "10.3.13.5", "layer": "L0", "role_slug": "actuator", "role_label": "Actuator", "icon": "bi-sliders", "segment_label": "Main Process Cell"},
    {"hostname": "pt-455", "label": "pt-455", "ip_address": "10.3.13.11", "layer": "L0", "role_slug": "sensor", "role_label": "Sensor", "icon": "bi-speedometer2", "segment_label": "Main Process Cell"},
    {"hostname": "pt-456", "label": "pt-456", "ip_address": "10.3.13.12", "layer": "L0", "role_slug": "sensor", "role_label": "Sensor", "icon": "bi-speedometer2", "segment_label": "Main Process Cell"},
    {"hostname": "pt-457", "label": "pt-457", "ip_address": "10.3.13.13", "layer": "L0", "role_slug": "sensor", "role_label": "Sensor", "icon": "bi-speedometer2", "segment_label": "Main Process Cell"},
    {"hostname": "pt-458", "label": "pt-458", "ip_address": "10.4.23.14", "layer": "L0", "role_slug": "sensor", "role_label": "Sensor", "icon": "bi-speedometer2", "segment_label": "Backup Process Cell"},
]


def _topology_identity_text(*parts) -> str:
    for part in parts:
        text = str(part or "").strip()
        if text:
            return text
    return ""


def _infer_topology_role(name: str = "", hostname: str = "", ip_address: str = "", description: str = "") -> tuple[str, str, str]:
    text = " ".join([str(name or ""), str(hostname or ""), str(description or "")]).lower()
    if any(token in text for token in ["firewall", "gateway"]):
        return "firewall", "Firewall", "bi-shield-lock-fill"
    if any(token in text for token in ["metasploit", "attacker", "kali", "red-team"]):
        return "offensive", "Offensive Host", "bi-bug-fill"
    if any(token in text for token in ["database", "postgres", "db", "historian-db", "influx"]):
        return "database", "Database", "bi-database-fill"
    if any(token in text for token in ["historian", "opc", "collector", "server"]):
        return "server", "Server", "bi-server"
    if any(token in text for token in ["engineer", "eng-ws", "workstation", "jump", "desktop", "laptop"]):
        return "workstation", "Workstation", "bi-laptop-fill"
    if any(token in text for token in ["hmi", "ignition", "scada", "supervisory"]):
        return "supervisory", "Supervisory", "bi-display-fill"
    if any(token in text for token in ["plc", "controller", "rtu", "ied", "dcs"]):
        return "controller", "Controller", "bi-cpu-fill"
    if any(token in text for token in ["valve", "vc-", "hv", "pv", "cv"]):
        return "actuator", "Actuator", "bi-sliders"
    if any(token in text for token in ["pt-", "lt-", "tt-", "ft-", "sensor", "transmitter"]):
        return "sensor", "Sensor", "bi-speedometer2"
    if "10.4.50." in ip_address:
        return "enterprise", "Enterprise", "bi-building"
    return "asset", "Asset", "bi-hdd-network-fill"


def _infer_purdue_layer(name: str = "", hostname: str = "", ip_address: str = "", description: str = "") -> str:
    text = " ".join([str(name or ""), str(hostname or ""), str(description or "")]).upper()
    ip_text = str(ip_address or "").strip()
    if "HISTORIAN" in text and "DB" not in text and "DATABASE" not in text:
        return "L3"
    if any(token in text for token in ["FIREWALL", "DMZ", "GATEWAY"]):
        return "L3.5"
    if ip_text.startswith("10.4.50."):
        return "L4"
    if ip_text.startswith("10.3.50."):
        return "L3"
    if ip_text.startswith("10.2.50."):
        return "L2"
    if any(ip_text.startswith(prefix) for prefix in ["10.1.13.", "10.2.23.", "10.0.13.", "10.0.23."]):
        return "L1"
    if any(ip_text.startswith(prefix) for prefix in ["10.3.13.", "10.4.23."]):
        return "L0"
    if any(token in text for token in ["ERP", "MES", "CORP", "ENTERPRISE", "BUSINESS", "IT", "OFFICE", "METASPLOIT", "DATABASE", "POSTGRES"]):
        return "L4"
    if any(token in text for token in ["HISTORIAN", "OPC"]):
        return "L3"
    if any(token in text for token in ["HMI", "IGNITION", "ENGINEER", "JUMP", "SCADA", "SUPERVISOR"]):
        return "L2"
    if any(token in text for token in ["PLC", "RTU", "IED", "DCS", "CONTROLLER", "CTRL"]):
        return "L1"
    if any(token in text for token in ["SENSOR", "VALVE", "PUMP", "MOTOR", "HEATER", "HV", "PV", "CV", "PT", "LT", "TT", "FT", "PORV"]):
        return "L0"
    return "L2"


def _topology_segment_label(ip_address: str = "") -> str:
    ip_text = str(ip_address or "").strip()
    segment_map = {
        "10.4.50.": "Enterprise LAN",
        "10.3.50.": "Operations LAN",
        "10.2.50.": "Supervisory LAN",
        "10.1.13.": "Main Control Cell",
        "10.2.23.": "Backup Control Cell",
        "10.3.13.": "Main Process Cell",
        "10.4.23.": "Backup Process Cell",
        "10.0.13.": "Main Management",
        "10.0.23.": "Backup Management",
    }
    for prefix, label in segment_map.items():
        if ip_text.startswith(prefix):
            return label
    return "Observed Network"


def _topology_layer_meta(slug: str) -> dict:
    for layer in PURDUE_TOPOLOGY_LAYERS:
        if layer["slug"] == slug:
            return layer
    return {"slug": slug, "label": slug, "accent": "secondary"}


IAEA_TOPOLOGY_BY_IP = {item["ip_address"]: item for item in IAEA_TESTBED_STATIC_TOPOLOGY}
IAEA_TOPOLOGY_BY_HOSTNAME = {item["hostname"]: item for item in IAEA_TESTBED_STATIC_TOPOLOGY}


def _iaea_topology_override(hostname: str = "", name: str = "", ip_address: str = "") -> dict | None:
    hostname = str(hostname or "").strip().lower()
    name = str(name or "").strip().lower()
    ip_address = str(ip_address or "").strip()
    if ip_address and ip_address in IAEA_TOPOLOGY_BY_IP:
        return IAEA_TOPOLOGY_BY_IP[ip_address]
    if hostname and hostname in IAEA_TOPOLOGY_BY_HOSTNAME:
        return IAEA_TOPOLOGY_BY_HOSTNAME[hostname]
    if name and name in IAEA_TOPOLOGY_BY_HOSTNAME:
        return IAEA_TOPOLOGY_BY_HOSTNAME[name]
    return None


def _is_iaea_testbed_active(node_candidates, agents) -> bool:
    known_ranges = (
        "10.4.50.",
        "10.3.50.",
        "10.2.50.",
        "10.1.13.",
        "10.2.23.",
        "10.3.13.",
        "10.4.23.",
        "10.0.13.",
        "10.0.23.",
    )
    for obj in list(node_candidates) + list(agents):
        ip_text = str(getattr(obj, "ip_address", "") or "").strip()
        hostname = str(getattr(obj, "hostname", "") or "").strip().lower()
        name = str(getattr(obj, "name", "") or "").strip().lower()
        if any(ip_text.startswith(prefix) for prefix in known_ranges):
            return True
        if hostname in IAEA_TOPOLOGY_BY_HOSTNAME or name in IAEA_TOPOLOGY_BY_HOSTNAME:
            return True
    return False


def _normalize_host_identity_text(value: str = "") -> str:
    return str(value or "").strip()


def _rekey_agent_identity(old_agent_id: str, new_agent_id: str) -> None:
    old_agent_id = _normalize_host_identity_text(old_agent_id)
    new_agent_id = _normalize_host_identity_text(new_agent_id)
    if not old_agent_id or not new_agent_id or old_agent_id == new_agent_id:
        return

    AgentCommand.objects.filter(agent_id=old_agent_id).update(agent_id=new_agent_id)
    CommandResult.objects.filter(agent_id=old_agent_id).update(agent_id=new_agent_id)
    SbomReport.objects.filter(agent_id=old_agent_id).update(agent_id=new_agent_id)


def _claim_existing_agent_identity(agent_id: str, hostname: str, ip_address: str):
    agent_id = _normalize_host_identity_text(agent_id)
    hostname = _normalize_host_identity_text(hostname)
    ip_address = _normalize_host_identity_text(ip_address)
    if not agent_id:
        return None

    existing = AgentStatus.objects.filter(agent_id=agent_id).first()
    if existing:
        return existing

    candidate_qs = AgentStatus.objects.exclude(agent_id=agent_id)
    if hostname and ip_address:
        candidate_qs = candidate_qs.filter(hostname__iexact=hostname, ip_address=ip_address)
    elif ip_address:
        candidate_qs = candidate_qs.filter(ip_address=ip_address)
    elif hostname:
        candidate_qs = candidate_qs.filter(hostname__iexact=hostname)
    else:
        return None

    candidate = candidate_qs.order_by("-last_heartbeat", "-id").first()
    if not candidate:
        return None

    old_agent_id = candidate.agent_id
    _rekey_agent_identity(old_agent_id, agent_id)
    candidate.agent_id = agent_id
    candidate.save(update_fields=["agent_id"])
    return candidate


def _claim_existing_node_identity(agent_id: str, hostname: str, ip_address: str):
    agent_id = _normalize_host_identity_text(agent_id)
    hostname = _normalize_host_identity_text(hostname)
    ip_address = _normalize_host_identity_text(ip_address)
    if not agent_id:
        return None

    existing = Node.objects.filter(agent_id=agent_id).first()
    if existing:
        return existing

    candidate_qs = Node.objects.filter(scan_run__isnull=True).exclude(agent_id=agent_id)
    if hostname and ip_address:
        candidate_qs = candidate_qs.filter(hostname__iexact=hostname, ip_address=ip_address)
    elif ip_address:
        candidate_qs = candidate_qs.filter(ip_address=ip_address)
    elif hostname:
        candidate_qs = candidate_qs.filter(hostname__iexact=hostname)
    else:
        return None

    candidate = candidate_qs.order_by("-last_heartbeat", "-id").first()
    if not candidate:
        return None

    candidate.agent_id = agent_id
    candidate.save(update_fields=["agent_id"])
    return candidate


def _sort_sbom_vulnerability_rows(rows):
    return sorted(
        rows,
        key=lambda row: (
            -_sbom_severity_rank(row.get("severity", "")),
            -(float(row.get("score") or 0) if str(row.get("score") or "").strip() else 0),
            str(row.get("cve_id") or ""),
        ),
    )


def _build_sbom_vulnerability_tabs(vulnerability_rows, report, scanner_tools):
    tabs = [
        {
            "slug": "all",
            "label": "All Findings",
            "rows": _sort_sbom_vulnerability_rows(vulnerability_rows),
            "count": len(vulnerability_rows),
            "status": "ok" if vulnerability_rows else "",
            "error": "",
        }
    ]
    if not report:
        return tabs

    scan_metadata = report.scan_metadata if isinstance(report.scan_metadata, dict) else {}
    runs = scan_metadata.get("scanner_runs") if isinstance(scan_metadata.get("scanner_runs"), list) else []
    findings_by_scanner = (
        scan_metadata.get("findings_by_scanner")
        if isinstance(scan_metadata.get("findings_by_scanner"), dict)
        else {}
    )
    run_by_name = {
        str(run.get("scanner") or "").strip().lower(): run
        for run in runs
        if isinstance(run, dict) and str(run.get("scanner") or "").strip()
    }

    for scanner in ("grype", "trivy"):
        run = run_by_name.get(scanner, {})
        rows = findings_by_scanner.get(scanner)
        normalized_rows = _sort_sbom_vulnerability_rows(rows if isinstance(rows, list) else [])
        if not normalized_rows and not run and scanner not in scanner_tools:
            continue
        tabs.append(
            {
                "slug": scanner,
                "label": scanner.title(),
                "rows": normalized_rows,
                "count": len(normalized_rows),
                "status": str(run.get("status") or ("not run" if not normalized_rows else "ok")),
                "error": str(run.get("error") or ""),
            }
        )
    return tabs


def _build_agent_sbom_vulnerability_context(node, sbom_reports):
    latest_report = sbom_reports[0] if sbom_reports else None
    vulnerability_rows = []
    source_label = ""

    if latest_report:
        vulnerability_rows = extract_vulnerability_table_rows(latest_report.document)
        source_label = "latest SBOM report"

    if not vulnerability_rows and node:
        vulnerability_rows = extract_vulnerability_table_rows_from_models(
            node.vulnerability_set.all()
        )
        if vulnerability_rows:
            source_label = "persisted vulnerability catalog"

    vulnerability_rows = _sort_sbom_vulnerability_rows(vulnerability_rows)
    return {
        "rows": vulnerability_rows,
        "total_rows": len(vulnerability_rows),
        "source_label": source_label,
    }
SIEM_ADMIN_ROLES = (SiemUserRole.Role.ADMIN,)
GPWR_DEFAULT_HOST = os.environ.get("GPWR_HOST", "128.61.144.101")
GPWR_DEFAULT_PORT = int(os.environ.get("GPWR_PORT", "8082"))
GPWR_SUBSYSTEM_META = {
    "rcs": {"zone": "Reactor Coolant System", "level": "L1/L2"},
    "mfw": {"zone": "Main Feedwater", "level": "L1/L2"},
    "mrs": {"zone": "Moisture Reheat System", "level": "L1/L2"},
    "cws": {"zone": "Circulating Water System", "level": "L1/L2"},
}
GPWR_DEFAULT_SCAN_CIDR = os.environ.get("GPWR_SCAN_CIDR", "172.20.0.0/28")
GPWR_DEFAULT_RISK_TARGETS = os.environ.get("GPWR_RISK_TARGETS", "172.20.0.2-12")
GPWR_DEFAULT_RISK_PORTS = os.environ.get("GPWR_RISK_PORTS", "102,502,1883,2404,4840,44818")
GPWR_SUBSYSTEM_CATALOG = os.environ.get(
    "GPWR_SUBSYSTEM_CATALOG",
    str(Path(settings.BASE_DIR) / "configs" / "gpwr_subsystems_full.json"),
)
OT_QEMU_PROFILES = {
    "rcs": {
        "device_type": "Safety PLC / Reactor Control",
        "architecture": "x86_64",
        "launch_mode": "kvm",
        "fidelity": "high",
    },
    "mrs": {
        "device_type": "Process Controller",
        "architecture": "armv7",
        "launch_mode": "qemu",
        "fidelity": "high",
    },
    "mfw": {
        "device_type": "Feedwater PLC",
        "architecture": "x86_64",
        "launch_mode": "kvm",
        "fidelity": "medium-high",
    },
    "cws": {
        "device_type": "Cooling Water RTU",
        "architecture": "mips",
        "launch_mode": "qemu",
        "fidelity": "high",
    },
    "unknown": {
        "device_type": "Generic OT Endpoint",
        "architecture": "x86_64",
        "launch_mode": "kvm",
        "fidelity": "medium",
    },
}


def _load_gpwr_subsystem_catalog() -> list[dict]:
    path = Path(GPWR_SUBSYSTEM_CATALOG)
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    subsystems = payload.get("subsystems", [])
    if not isinstance(subsystems, list):
        return []
    out = []
    for item in subsystems:
        if not isinstance(item, dict):
            continue
        name = str(item.get("subsystem", "")).strip().lower()
        if not name:
            continue
        out.append(
            {
                "subsystem": name,
                "record_count": int(item.get("record_count", 0) or 0),
                "value_tag_count": int(item.get("value_tag_count", 0) or 0),
                "purdue_zone": str(item.get("purdue_zone", "Basic Control")),
                "purdue_level": str(item.get("purdue_level", "L1")),
                "variables": item.get("variables", []) if isinstance(item.get("variables"), list) else [],
            }
        )
    return out


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


def _gpwr_send_command(command: str, host: str, port: int, timeout: float = 5.0) -> str:
    if not command or "\x00" in command:
        raise ValueError("invalid GPWR command")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((command + "\x00").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\x00" in data:
                break
    raw = b"".join(chunks)
    if b"\x00" in raw:
        raw = raw.split(b"\x00", 1)[0]
    return raw.decode("utf-8", errors="replace").strip()


def _refresh_agent_statuses():
    """Refresh persisted agent status flags without changing heartbeat timestamps."""
    agents = AgentStatus.objects.all().order_by("-last_heartbeat")
    for agent in agents:
        agent.update_status()
    return AgentStatus.objects.all().order_by("-last_heartbeat")

def home(request):
    scan_history = ScanRun.objects.order_by("-timestamp")[:8]
    running_scans = ScanRun.objects.filter(status="RUNNING").count()
    pending_scans = ScanRun.objects.filter(status="PENDING").count()

    return render(request, "dashboard/network_monitoring.html", {
        "scan_history": scan_history,
        "running_scans": running_scans,
        "pending_scans": pending_scans,
        "timestamp": now().timestamp(),
    })


def network_scans(request):
    scan_history = ScanRun.objects.all().order_by('-timestamp')[:20]
    campaign_history = CampaignRun.objects.select_related("openvas_scan").all()[:20]
    agents = AgentStatus.objects.all().order_by("hostname")
    return render(request, 'dashboard/network_scans.html', {
        'scan_history': scan_history,
        'campaign_history': campaign_history,
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
                hostname=agent.hostname or "",
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

    scans = list(ScanRun.objects.all().order_by("-timestamp"))
    scan_networks = []
    for scan in scans:
        try:
            network = ip_network(str(scan.cidr or "").strip(), strict=False)
        except ValueError:
            continue
        scan_networks.append((scan, network))

    latest_scan_for_ip_cache = {}
    agent_hostname_by_ip = {
        str(agent.ip_address): str(agent.hostname or "").strip()
        for agent in AgentStatus.objects.exclude(ip_address__isnull=True).exclude(hostname="")
    }
    nodes = list(
        Node.objects.exclude(ip_address__isnull=True)
        .select_related("scan_run")
        .prefetch_related("vulnerability_set")
        .order_by("-id")
    )
    best_hostname_by_ip = {}
    for node in nodes:
        ip_text = str(node.ip_address or "")
        if not ip_text:
            continue
        hostname = str(node.hostname or "").strip()
        if not hostname:
            candidate = str(node.name or "").strip()
            if candidate and candidate != ip_text:
                hostname = candidate
        if not hostname:
            hostname = str(agent_hostname_by_ip.get(ip_text) or "").strip()
        if ip_text not in best_hostname_by_ip or (not best_hostname_by_ip[ip_text] and hostname):
            best_hostname_by_ip[ip_text] = hostname

    def _lookup_latest_scan_for_ip(ip_text):
        cached = latest_scan_for_ip_cache.get(ip_text, False)
        if cached is not False:
            return cached
        try:
            ip_value = ipaddress.ip_address(str(ip_text or "").strip())
        except ValueError:
            latest_scan_for_ip_cache[ip_text] = None
            return None
        for scan, network in scan_networks:
            if ip_value in network:
                latest_scan_for_ip_cache[ip_text] = scan
                return scan
        latest_scan_for_ip_cache[ip_text] = None
        return None

    def _merge_inventory_row(inventory, *, host_ip, cve_id, source_type, scan=None, hostname="", name="", package="",
                             installed_version="", fixed_version="", cvss_score=None, severity="",
                             description="", link_url="", references="", source_url=""):
        key = (str(host_ip or ""), str(cve_id or ""))
        row = inventory.setdefault(
            key,
            {
                "host_ip": str(host_ip or ""),
                "hostname": "",
                "cve_id": str(cve_id or ""),
                "names": set(),
                "packages": set(),
                "installed_versions": set(),
                "fixed_versions": set(),
                "source_types": set(),
                "scan_ids": set(),
                "first_seen": None,
                "latest_seen": None,
                "latest_scan_id": None,
                "latest_scan_type": "",
                "latest_scan_cidr": "",
                "report_url": "",
                "cvss_score": None,
                "severity": "",
                "description": "",
                "link_url": "",
                "references": "",
                "source_url": "",
            },
        )

        normalized_hostname = str(hostname or "").strip()
        if normalized_hostname and normalized_hostname != row["host_ip"] and not row["hostname"]:
            row["hostname"] = normalized_hostname
        if name:
            row["names"].add(str(name))
        if package:
            row["packages"].add(str(package))
        if installed_version:
            row["installed_versions"].add(str(installed_version))
        if fixed_version:
            row["fixed_versions"].add(str(fixed_version))
        if source_type:
            row["source_types"].add(str(source_type))
        if references and not row["references"]:
            row["references"] = str(references)
        if source_url and not row["source_url"]:
            row["source_url"] = str(source_url)
        if link_url and not row["link_url"]:
            row["link_url"] = str(link_url)
        if description and len(str(description)) > len(row["description"]):
            row["description"] = str(description)

        current_score = row["cvss_score"]
        try:
            incoming_score = float(cvss_score)
        except (TypeError, ValueError):
            incoming_score = None
        if incoming_score is not None and (current_score is None or incoming_score > float(current_score)):
            row["cvss_score"] = incoming_score

        incoming_severity = str(severity or "")
        if _sbom_severity_rank(incoming_severity) > _sbom_severity_rank(row["severity"]):
            row["severity"] = incoming_severity

        if not scan:
            return

        row["scan_ids"].add(scan.id)
        if row["first_seen"] is None or scan.timestamp < row["first_seen"]:
            row["first_seen"] = scan.timestamp
        if row["latest_seen"] is None or scan.timestamp > row["latest_seen"]:
            row["latest_seen"] = scan.timestamp
            row["latest_scan_id"] = scan.id
            row["latest_scan_type"] = scan.scan_type
            row["latest_scan_cidr"] = scan.cidr
            row["report_url"] = reverse("dashboard:vuln-detail", args=[scan.id])

    inventory = {}

    scan_vulns = (
        ScanVulnerability.objects.select_related("scan_run")
        .all()
        .order_by("-scan_run__timestamp", "-cvss_score", "host_ip", "cve_id")
    )
    for vuln in scan_vulns:
        _merge_inventory_row(
            inventory,
            host_ip=vuln.host_ip,
            hostname=best_hostname_by_ip.get(str(vuln.host_ip), ""),
            cve_id=vuln.cve_id,
            source_type="Network Scan",
            scan=vuln.scan_run,
            name=vuln.name,
            cvss_score=vuln.cvss_score,
            severity=vuln.severity,
            description=vuln.description,
            link_url=f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}" if str(vuln.cve_id or "").startswith("CVE-") else "",
        )

    for node in nodes:
        ip_text = str(node.ip_address or "")
        if not ip_text:
            continue
        node_scan = node.scan_run or _lookup_latest_scan_for_ip(ip_text)
        node_hostname = str(node.hostname or "").strip() or best_hostname_by_ip.get(ip_text, "")
        for vuln in node.vulnerability_set.all():
            references = str(vuln.references or "")
            source_url = str(vuln.source or "")
            if str(vuln.cve_id or "").startswith("CVE-"):
                link_url = f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
            elif references:
                link_url = references.split(",")[0].strip()
            else:
                link_url = source_url
            _merge_inventory_row(
                inventory,
                host_ip=ip_text,
                hostname=node_hostname,
                cve_id=vuln.cve_id,
                source_type="SBOM",
                scan=node_scan,
                name=vuln.package or vuln.cve_id,
                package=vuln.package,
                installed_version=vuln.installed_version,
                fixed_version=vuln.fixed_version,
                cvss_score=vuln.score,
                severity=vuln.severity,
                description=vuln.description,
                link_url=link_url,
                references=references,
                source_url=source_url,
            )

    source_order = {"Network Scan": 0, "SBOM": 1}
    rows = []
    host_groups = {}
    represented_scan_ids = set()
    network_backed_rows = 0
    sbom_backed_rows = 0
    unique_hosts = set()
    named_hosts = set()
    critical_rows = 0
    high_rows = 0
    exploitable_rows = 0
    latest_seen = None
    for row in inventory.values():
        sources = sorted(row["source_types"], key=lambda value: (source_order.get(value, 99), value))
        if "Network Scan" in row["source_types"]:
            network_backed_rows += 1
        if "SBOM" in row["source_types"]:
            sbom_backed_rows += 1
        if row["host_ip"]:
            unique_hosts.add(row["host_ip"])
        if row["hostname"]:
            named_hosts.add(row["hostname"])
        if str(row.get("severity") or "").lower() == "critical":
            critical_rows += 1
        elif str(row.get("severity") or "").lower() == "high":
            high_rows += 1
        try:
            if float(row.get("cvss_score") or 0) >= 7.0:
                exploitable_rows += 1
        except (TypeError, ValueError):
            pass
        represented_scan_ids.update(row["scan_ids"])
        if row.get("latest_seen") and (latest_seen is None or row["latest_seen"] > latest_seen):
            latest_seen = row["latest_seen"]
        row["sources"] = sources
        row["name"] = ", ".join(sorted(row["names"])) if row["names"] else (row["cve_id"] or "-")
        row["package"] = ", ".join(sorted(row["packages"])) if row["packages"] else "-"
        row["installed_version"] = ", ".join(sorted(row["installed_versions"])) if row["installed_versions"] else "-"
        row["fixed_version"] = ", ".join(sorted(row["fixed_versions"])) if row["fixed_versions"] else "-"
        row["scan_count"] = len(row["scan_ids"])
        rows.append(row)

        host_key = row["host_ip"] or "unknown-host"
        host_group = host_groups.setdefault(
            host_key,
            {
                "host_ip": row["host_ip"],
                "hostname": row["hostname"],
                "finding_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "sbom_count": 0,
                "network_count": 0,
                "latest_seen": None,
                "latest_scan_type": "",
                "latest_scan_cidr": "",
                "report_url": "",
                "sources": set(),
                "packages": set(),
                "artifact_links": {},
                "findings": [],
            },
        )
        host_group["finding_count"] += 1
        if row["hostname"] and not host_group["hostname"]:
            host_group["hostname"] = row["hostname"]
        if "SBOM" in row["source_types"]:
            host_group["sbom_count"] += 1
        if "Network Scan" in row["source_types"]:
            host_group["network_count"] += 1
        host_group["sources"].update(row["sources"])
        if row["package"] and row["package"] != "-":
            host_group["packages"].update(part.strip() for part in row["package"].split(",") if part.strip())
        severity_name = str(row.get("severity") or "").lower()
        if severity_name == "critical":
            host_group["critical_count"] += 1
        elif severity_name == "high":
            host_group["high_count"] += 1
        if row.get("latest_seen") and (host_group["latest_seen"] is None or row["latest_seen"] > host_group["latest_seen"]):
            host_group["latest_seen"] = row["latest_seen"]
            host_group["latest_scan_type"] = row.get("latest_scan_type", "")
            host_group["latest_scan_cidr"] = row.get("latest_scan_cidr", "")
            host_group["report_url"] = row.get("report_url", "")
        if row.get("report_url"):
            host_group["artifact_links"][f"report:{row['report_url']}"] = {
                "label": f"Scan report {row.get('latest_scan_type', '').upper()} {row.get('latest_scan_cidr', '')}".strip(),
                "url": row["report_url"],
                "kind": "Report",
            }
        if row.get("link_url"):
            host_group["artifact_links"][f"artifact:{row['link_url']}"] = {
                "label": row.get("cve_id") or row.get("name") or row["link_url"],
                "url": row["link_url"],
                "kind": "Reference",
            }
        host_group["findings"].append(
            {
                "cve_id": row.get("cve_id", ""),
                "severity": row.get("severity", ""),
                "cvss_score": row.get("cvss_score"),
                "source_labels": list(row.get("sources", [])),
                "report_url": row.get("report_url", ""),
                "link_url": row.get("link_url", ""),
                "name": row.get("name", ""),
            }
        )

    rows.sort(
        key=lambda row: (
            -_sbom_severity_rank(row.get("severity", "")),
            -(float(row.get("cvss_score") or 0) if row.get("cvss_score") is not None else 0),
            -(row.get("latest_seen").timestamp() if row.get("latest_seen") else 0),
            str(row.get("host_ip") or ""),
            str(row.get("cve_id") or ""),
        )
    )

    host_cards = []
    for host_group in host_groups.values():
        host_group["sources"] = sorted(host_group["sources"], key=lambda value: (source_order.get(value, 99), value))
        host_group["packages"] = sorted(host_group["packages"])[:6]
        host_group["artifacts"] = list(host_group["artifact_links"].values())[:6]
        host_group["findings"].sort(
            key=lambda finding: (
                -_sbom_severity_rank(finding.get("severity", "")),
                -(float(finding.get("cvss_score") or 0) if finding.get("cvss_score") is not None else 0),
                str(finding.get("cve_id") or ""),
            )
        )
        host_group["top_findings"] = host_group["findings"][:4]
        host_cards.append(host_group)

    host_cards.sort(
        key=lambda group: (
            -group["critical_count"],
            -group["high_count"],
            -group["finding_count"],
            -(group["latest_seen"].timestamp() if group["latest_seen"] else 0),
            str(group["host_ip"] or ""),
        )
    )

    return render(
        request,
        "dashboard/history.html",
        {
            "inventory": rows,
            "host_cards": host_cards,
            "summary": {
                "total_entries": len(rows),
                "unique_hosts": len(unique_hosts),
                "named_hosts": len(named_hosts),
                "critical_rows": critical_rows,
                "high_rows": high_rows,
                "exploitable_rows": exploitable_rows,
                "network_backed_rows": network_backed_rows,
                "sbom_backed_rows": sbom_backed_rows,
                "represented_scans": len(represented_scan_ids),
                "latest_seen": latest_seen,
            },
        },
    )


def history_redirect(request):
    return redirect("dashboard:vulnerabilities")

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
        "hostname": node.hostname,
        "ip_address": node.ip_address,
        "status": node.status,
        "description": node.description,
        "last_heartbeat": node.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if node.last_heartbeat else "Never",
        "agent_id": node.agent_id,
        "purdue_level": _infer_purdue_layer(node.name, node.hostname, str(node.ip_address), node.description),
        "role": _infer_topology_role(node.name, node.hostname, str(node.ip_address), node.description)[1],
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

    purdue_level = _infer_purdue_layer(node.name, node.hostname, str(node.ip_address), node.description)
    role_slug, role_label, role_icon = _infer_topology_role(node.name, node.hostname, str(node.ip_address), node.description)
    asset_ips = sorted(_node_asset_ips(node))
    imported_network_findings = list(
        ScanVulnerability.objects.filter(host_ip__in=asset_ips)
        .select_related("scan_run")
        .order_by("-cvss_score", "-timestamp", "cve_id")
    )
    gvmd_findings = fetch_gvmd_findings_for_ips(asset_ips)
    sbom_finding_count = node.vulnerability_set.count()
    recent_report_scans = list(
        ScanRun.objects.filter(vulnerabilities__host_ip__in=asset_ips)
        .distinct()
        .order_by("-timestamp")[:5]
    )
    if not recent_report_scans and node.scan_run_id:
        recent_report_scans = [node.scan_run]

    context_rollup = {
        "display_name": _topology_identity_text(node.hostname, node.name, node.ip_address),
        "purdue_level": purdue_level,
        "segment_label": _topology_segment_label(str(node.ip_address)),
        "role_slug": role_slug,
        "role_label": role_label,
        "role_icon": role_icon,
        "scan_finding_count": 0,
        "sbom_finding_count": sbom_finding_count,
        "interface_count": node.interfaces.count(),
        "library_count": len(node.installed_libraries or []),
        "active_port_count": len(node.active_ports or []),
        "recent_reports": recent_report_scans,
    }

    network_finding_rows = []
    seen_network_keys = set()
    for finding in imported_network_findings:
        row_key = (str(finding.host_ip), str(finding.cve_id))
        if row_key in seen_network_keys:
            continue
        seen_network_keys.add(row_key)
        cve_id = str(finding.cve_id or "")
        network_finding_rows.append(
            {
                "host_ip": str(finding.host_ip),
                "cve_id": cve_id,
                "name": str(finding.name or ""),
                "severity": str(finding.severity or ""),
                "cvss_score": finding.cvss_score,
                "description": str(finding.description or ""),
                "scan_id": finding.scan_run_id,
                "scan_timestamp": getattr(finding.scan_run, "timestamp", None),
                "report_url": reverse("dashboard:vuln-detail", args=[finding.scan_run_id]) if finding.scan_run_id else "",
                "link_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else "",
                "source_label": "Imported",
                "report_label": f"Django report #{finding.scan_run_id}" if finding.scan_run_id else "",
            }
        )

    for finding in gvmd_findings:
        row_key = (str(finding.get("host_ip") or ""), str(finding.get("cve_id") or ""))
        if row_key in seen_network_keys:
            continue
        seen_network_keys.add(row_key)
        network_finding_rows.append(
            {
                "host_ip": str(finding.get("host_ip") or ""),
                "cve_id": str(finding.get("cve_id") or ""),
                "name": str(finding.get("name") or ""),
                "severity": str(finding.get("severity") or ""),
                "cvss_score": finding.get("cvss_score"),
                "description": str(finding.get("description") or ""),
                "scan_id": None,
                "scan_timestamp": None,
                "report_url": "",
                "link_url": str(finding.get("link_url") or ""),
                "source_label": "GVMD",
                "report_label": str(finding.get("task_name") or finding.get("task_uuid") or finding.get("report_uuid") or finding.get("nvt_oid") or ""),
                "report_uuid": str(finding.get("report_uuid") or ""),
                "nvt_oid": str(finding.get("nvt_oid") or ""),
            }
        )

    context_rollup["scan_finding_count"] = len(network_finding_rows)

    return render(request, 'dashboard/node_detail.html', {
        'node': node,
        'interfaces': node.interfaces.all(),
        'agent_status': agent_status,
        'network_metadata': network_metadata,
        'rollup': context_rollup,
        'network_findings': network_finding_rows,
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


def _serialize_campaign_run(run):
    openvas_task_id = ""
    if run.openvas_scan_id and run.openvas_scan:
        openvas_task_id = run.openvas_scan.openvas_task_id or ""

    report_url = (
        reverse("dashboard:vuln-detail", args=[run.openvas_scan_id])
        if run.openvas_scan_id
        else ""
    )
    openvas_ui_url = getattr(settings, "OPENVAS_UI_URL", "http://127.0.0.1:9392")
    payload = run.result_payload if isinstance(run.result_payload, dict) else {}
    log_lines = payload.get("log_lines") if isinstance(payload, dict) else []
    if not isinstance(log_lines, list):
        log_lines = []
    return {
        "id": run.id,
        "started_at": run.started_at.strftime('%Y-%m-%d %H:%M:%S'),
        "cidr": run.cidr,
        "status": run.status,
        "scan_method": run.scan_method,
        "duration_seconds": run.duration_seconds,
        "steps_completed": run.steps_completed,
        "total_steps": run.total_steps,
        "discovered_hosts_count": run.discovered_hosts_count,
        "vulnerability_count": run.vulnerability_count,
        "error_count": run.error_count,
        "error_details": run.error_details or "",
        "step": run.current_step or "",
        "message": run.step_message or "",
        "openvas_scan_id": run.openvas_scan_id,
        "openvas_task_id": openvas_task_id,
        "openvas_report_id": run.openvas_report_id or "",
        "openvas_ui_url": openvas_ui_url,
        "report_url": report_url,
        "task_id": run.celery_task_id or "",
        "log_lines": [str(line) for line in log_lines[-200:]],
    }


@require_GET
def ot_campaign_history(request):
    runs = CampaignRun.objects.select_related("openvas_scan").all()[:20]
    return JsonResponse({"history": [_serialize_campaign_run(run) for run in runs]})


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

    with transaction.atomic():
        _claim_existing_agent_identity(agent_id, hostname, ip)
        _claim_existing_node_identity(agent_id, hostname, ip)

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
                "hostname": hostname or "",
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

    scan_sbom_vulnerabilities_task.delay(agent_id=agent_id, report_id=report.id)

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
                    "package": vuln.get("package") or "",
                    "installed_version": vuln.get("installed_version") or "",
                    "fixed_version": vuln.get("fixed_version") or "",
                    "source": vuln.get("source") or "",
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
                if vuln.get("package") and vuln_obj.package != vuln.get("package"):
                    vuln_obj.package = vuln.get("package")
                    updated = True
                if vuln.get("installed_version") and vuln_obj.installed_version != vuln.get("installed_version"):
                    vuln_obj.installed_version = vuln.get("installed_version")
                    updated = True
                if vuln.get("fixed_version") and vuln_obj.fixed_version != vuln.get("fixed_version"):
                    vuln_obj.fixed_version = vuln.get("fixed_version")
                    updated = True
                if vuln.get("source") and vuln_obj.source != vuln.get("source"):
                    vuln_obj.source = vuln.get("source")
                    updated = True
                if vuln.get("references") and vuln_obj.references != vuln.get("references"):
                    vuln_obj.references = vuln.get("references")
                    updated = True
                if updated:
                    vuln_obj.last_modified = now()
                    vuln_obj.save(update_fields=["description", "severity", "score", "package", "installed_version", "fixed_version", "source", "references", "last_modified"])
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
    # OT lab mode: when token enforcement is enabled but no token is configured,
    # allow ingest to prevent silent outage of telemetry pipelines.
    if not token:
        return True
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


def _parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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
    fmt = (request.GET.get("format") or "table").lower()
    report = SbomReport.objects.filter(agent_id=agent_id).order_by("-created_at").first()
    node = report.node if report else None
    fallback_packages = []
    if not node:
        try:
            node = Node.objects.get(agent_id=agent_id)
        except Node.DoesNotExist:
            node = None
    if not report:
        if not node or not node.installed_libraries:
            return JsonResponse({"error": "SBOM not found"}, status=404)
        fallback_packages = list(node.installed_libraries or [])

    if fmt in {"html", "table"}:
        scanner_tools = [tool for tool in ("trivy", "grype") if shutil.which(tool)]
        if report:
            rows = extract_sbom_table_rows(report.document)
            vulnerability_rows = extract_vulnerability_table_rows(report.document)
            if not vulnerability_rows and node:
                vulnerability_rows = extract_vulnerability_table_rows_from_models(
                    node.vulnerability_set.all()
                )
            source_label = "SBOM report"
            os_summary = report.os_summary
            collected_at = report.created_at
            format_name = report.format
        else:
            rows = extract_cyber_template_table_rows(node.installed_libraries if node else [])
            vulnerability_rows = extract_vulnerability_table_rows_from_models(
                node.vulnerability_set.all() if node else []
            )
            source_label = "cyber template data"
            os_summary = node.os_info if node else ""
            collected_at = node.last_heartbeat if node else None
            format_name = "cyber"
        vulnerability_rows = _sort_sbom_vulnerability_rows(vulnerability_rows)
        vulnerability_tabs = _build_sbom_vulnerability_tabs(vulnerability_rows, report, scanner_tools)
        return render(request, "dashboard/agent_sbom_table.html", {
            "report": report,
            "agent_id": agent_id,
            "source_label": source_label,
            "os_summary": os_summary,
            "collected_at": collected_at,
            "format_name": format_name,
            "scanner_tools": scanner_tools,
            "scanner_status": " + ".join(scanner_tools).title() if scanner_tools else "Unavailable",
            "rows": rows,
            "total_rows": len(rows),
            "vulnerability_rows": vulnerability_rows,
            "vulnerability_total_rows": len(vulnerability_rows),
            "vulnerability_tabs": vulnerability_tabs,
        })

    if fmt == "csv":
        packages = extract_packages_from_sbom(report.document) if report else fallback_packages
        timestamp = report.created_at if report else (node.last_heartbeat if node and node.last_heartbeat else now())
        filename = f"sbom_{agent_id}_{timestamp:%Y%m%d_%H%M%S}.csv"
        lines = ["package"]
        lines.extend(packages)
        response = HttpResponse("\n".join(lines), content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    if report:
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
    else:
        data = {
            "agent_id": agent_id,
            "created_at": node.last_heartbeat.isoformat() if node and node.last_heartbeat else "",
            "format": "cyber",
            "bom_format": "",
            "spec_version": "",
            "package_count": len(fallback_packages),
            "os_summary": node.os_info if node else "",
            "document": {
                "packages": fallback_packages,
                "source": "cyber template data",
            },
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
    agents = _refresh_agent_statuses()
    total_agents = agents.count()
    online_agents = agents.filter(status='online').count()
    offline_agents = agents.filter(status='offline').count()

    # Get recent command results
    recent_results = CommandResult.objects.all().order_by('-timestamp')[:20]

    # Get pending commands
    pending_commands = AgentCommand.objects.filter(acknowledged=False).order_by('-created')[:10]

    return render(request, 'dashboard/agent_monitoring.html', {
        'agents': agents,
        'recent_results': recent_results,
        'pending_commands': pending_commands,
        'total_agents': total_agents,
        'online_agents': online_agents,
        'offline_agents': offline_agents,
    })


@require_GET
def agent_status_api(request):
    """API endpoint for real-time agent status updates."""
    agents = _refresh_agent_statuses()

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


@require_http_methods(["POST"])
def delete_agent(request, agent_id=None):
    """Delete a specific agent and its agent-scoped history from the dashboard."""
    if not agent_id:
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            payload = {}
        agent_id = (payload.get("agent_id") or "").strip()

    if not agent_id:
        return JsonResponse({"error": "agent_id is required"}, status=400)

    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    with transaction.atomic():
        command_result_count, _ = CommandResult.objects.filter(agent_id=agent_id).delete()
        agent_command_count, _ = AgentCommand.objects.filter(agent_id=agent_id).delete()
        sbom_report_count, _ = SbomReport.objects.filter(agent_id=agent_id).delete()
        deleted_node_record_count, _ = Node.objects.filter(agent_id=agent_id).delete()
        deleted_agent_record_count, _ = AgentStatus.objects.filter(agent_id=agent_id).delete()

    return JsonResponse({
        "status": "agent_deleted",
        "agent_id": agent_id,
        "deleted_agent_records": deleted_agent_record_count,
        "deleted_nodes": deleted_node_record_count,
        "deleted_command_results": command_result_count,
        "deleted_commands": agent_command_count,
        "deleted_sbom_reports": sbom_report_count,
    })

@require_http_methods(["POST"])
def delete_offline_agents(request):
    """Delete all offline agents and their agent-scoped history from the dashboard."""
    agents = _refresh_agent_statuses()
    offline_agents = [agent for agent in agents if agent.status == "offline"]

    if not offline_agents:
        return JsonResponse({
            "status": "no_offline_agents",
            "deleted_agents": 0,
            "deleted_agent_ids": [],
        })

    offline_agent_ids = [agent.agent_id for agent in offline_agents]

    with transaction.atomic():
        command_result_count, _ = CommandResult.objects.filter(agent_id__in=offline_agent_ids).delete()
        agent_command_count, _ = AgentCommand.objects.filter(agent_id__in=offline_agent_ids).delete()
        sbom_report_count, _ = SbomReport.objects.filter(agent_id__in=offline_agent_ids).delete()
        deleted_node_record_count, _ = Node.objects.filter(agent_id__in=offline_agent_ids).delete()
        deleted_agent_record_count, _ = AgentStatus.objects.filter(agent_id__in=offline_agent_ids).delete()

    return JsonResponse({
        "status": "offline_agents_deleted",
        "deleted_agents": len(offline_agent_ids),
        "deleted_agent_records": deleted_agent_record_count,
        "deleted_nodes": deleted_node_record_count,
        "deleted_agent_ids": offline_agent_ids,
        "deleted_command_results": command_result_count,
        "deleted_commands": agent_command_count,
        "deleted_sbom_reports": sbom_report_count,
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
    sbom_reports = list(SbomReport.objects.filter(agent_id=agent_id).order_by('-created_at')[:5])
    sbom_vulnerability_context = _build_agent_sbom_vulnerability_context(node, sbom_reports)

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
        'sbom_vulnerability_rows': sbom_vulnerability_context["rows"],
        'sbom_vulnerability_total_rows': sbom_vulnerability_context["total_rows"],
        'sbom_vulnerability_source': sbom_vulnerability_context["source_label"],
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
    sbom_reports = list(SbomReport.objects.filter(agent_id=agent_id).order_by('-created_at')[:5])
    sbom_vulnerability_context = _build_agent_sbom_vulnerability_context(node, sbom_reports)

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
        'sbom_reports': sbom_reports,
        'sbom_vulnerability_rows': sbom_vulnerability_context["rows"],
        'sbom_vulnerability_total_rows': sbom_vulnerability_context["total_rows"],
        'sbom_vulnerability_source': sbom_vulnerability_context["source_label"],
        'network_analysis': {
            'metadata_records': network_metadata,
            'connection_stats': connection_stats,
            'interface_stats_history': interface_stats_over_time[:20],  # Last 20 interface readings
        },
        'cyber_template_analysis': cyber_template_analysis,
        'heartbeat_analysis': heartbeat_analysis,
        'summary_stats': summary_stats,
    })


def _build_consolidated_scan_vulnerabilities(scan):
    from .models import ScanVulnerability

    entries = []
    counts = {"network_scan": 0, "sbom": 0}

    def _entry_sort_key(entry):
        score = entry.get("cvss_score")
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = -1.0
        return (
            -_sbom_severity_rank(entry.get("severity", "")),
            -numeric_score,
            str(entry.get("host_ip") or ""),
            str(entry.get("cve_id") or ""),
        )

    def _link_for_entry(cve_id, references, source_url):
        if cve_id and str(cve_id).startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if references:
            return str(references).split(",")[0].strip()
        if source_url:
            return source_url
        return ""

    scan_vulns = list(ScanVulnerability.objects.filter(scan_run=scan).order_by("-cvss_score", "-timestamp", "host_ip", "cve_id"))
    scan_host_ips = {str(vuln.host_ip) for vuln in scan_vulns if vuln.host_ip}
    seen_keys = set()

    network = None
    try:
        network = ip_network(str(scan.cidr or "").strip(), strict=False)
    except ValueError:
        network = None

    candidate_nodes = []
    for node in Node.objects.exclude(ip_address__isnull=True).prefetch_related("vulnerability_set", "interfaces").order_by("-id"):
        asset_ips = _node_asset_ips(node)
        if not asset_ips:
            continue
        in_scope = bool(node.scan_run_id == scan.id or asset_ips.intersection(scan_host_ips))
        if not in_scope and network is not None:
            for ip_text in asset_ips:
                try:
                    if ipaddress.ip_address(ip_text) in network:
                        in_scope = True
                        break
                except ValueError:
                    continue
        if in_scope:
            candidate_nodes.append(node)

    latest_node_by_ip = _latest_nodes_by_asset_ip(candidate_nodes)

    agent_hostname_by_ip = {
        str(agent.ip_address): str(agent.hostname or "").strip()
        for agent in AgentStatus.objects.exclude(ip_address__isnull=True).exclude(hostname="")
    }

    def _hostname_for_ip(ip_text):
        node = latest_node_by_ip.get(str(ip_text or ""))
        if node:
            candidate = _hostname_for_node(node, fallback_ip=str(ip_text or ""))
            if candidate:
                return candidate
        return str(agent_hostname_by_ip.get(str(ip_text or ""), "") or "").strip()

    for vuln in scan_vulns:
        key = ("network_scan", str(vuln.host_ip), str(vuln.cve_id))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        counts["network_scan"] += 1
        entries.append(
            {
                "host_ip": str(vuln.host_ip),
                "hostname": _hostname_for_ip(vuln.host_ip),
                "source_type": "Network Scan",
                "cve_id": str(vuln.cve_id),
                "name": str(vuln.name or ""),
                "package": "",
                "installed_version": "",
                "fixed_version": "",
                "cvss_score": vuln.cvss_score,
                "severity": str(vuln.severity or ""),
                "description": str(vuln.description or ""),
                "references": "",
                "source_url": "",
                "link_url": _link_for_entry(vuln.cve_id, "", ""),
            }
        )

    seen_sbom_nodes = set()
    for ip_text, node in latest_node_by_ip.items():
        if node.id in seen_sbom_nodes:
            continue
        seen_sbom_nodes.add(node.id)
        for vuln in node.vulnerability_set.all():
            key = ("sbom", ip_text, str(vuln.cve_id))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            counts["sbom"] += 1
            references = str(vuln.references or "")
            source_url = str(vuln.source or "")
            entries.append(
                {
                    "host_ip": ip_text,
                    "hostname": _hostname_for_ip(ip_text),
                    "source_type": "SBOM",
                    "cve_id": str(vuln.cve_id or ""),
                    "name": str(vuln.package or vuln.cve_id or ""),
                    "package": str(vuln.package or ""),
                    "installed_version": str(vuln.installed_version or ""),
                    "fixed_version": str(vuln.fixed_version or ""),
                    "cvss_score": vuln.score,
                    "severity": str(vuln.severity or ""),
                    "description": str(vuln.description or ""),
                    "references": references,
                    "source_url": source_url,
                    "link_url": _link_for_entry(vuln.cve_id, references, source_url),
                }
            )

    entries.sort(key=_entry_sort_key)
    return entries, counts


def vulnerability_detail(request, scan_id):
    scan = get_object_or_404(ScanRun, id=scan_id)
    vulns, source_counts = _build_consolidated_scan_vulnerabilities(scan)
    return render(request, "dashboard/vulnerabilities.html", {
        "scan": scan,
        "vulnerabilities": vulns,
        "source_counts": source_counts,
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


@csrf_exempt
@require_http_methods(["POST"])
def start_ot_campaign(request):
    """
    Launch an orchestrated OT campaign:
    discovery -> optional agent scan queue -> optional OpenVAS -> optional Sliver automation.
    """
    if request.content_type and "application/json" in request.content_type:
        try:
            payload = json.loads(request.body or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)
    else:
        payload = request.POST

    cidr = str(payload.get("cidr", "")).strip()
    if not cidr:
        return JsonResponse({"error": "cidr is required"}, status=400)
    try:
        ip_network(cidr, strict=False)
    except ValueError:
        return JsonResponse({"error": f"invalid CIDR: {cidr}"}, status=400)

    scan_method = str(payload.get("scan_method", "nmap")).strip().lower() or "nmap"
    if scan_method not in {"ping", "nmap"}:
        return JsonResponse({"error": "scan_method must be one of: ping, nmap"}, status=400)

    max_hosts = payload.get("max_hosts")
    max_hosts = int(max_hosts) if str(max_hosts or "").strip().isdigit() else None

    openvas_timeout = payload.get("openvas_timeout_seconds")
    if str(openvas_timeout or "").strip().isdigit():
        openvas_timeout = max(15, min(1800, int(openvas_timeout)))
    else:
        openvas_timeout = 180

    run_openvas = _parse_bool(payload.get("run_openvas"), default=True)
    collect_loot = _parse_bool(payload.get("collect_loot"), default=True)
    openvas_config = str(payload.get("gvmd_config", "full_and_fast")).strip() or "full_and_fast"
    selected_agent_id = str(payload.get("agent_id", "")).strip() or None
    selected_sliver_session_id = str(payload.get("sliver_session_id", "")).strip()
    selected_sliver_command = str(payload.get("sliver_command", "whoami")).strip() or "whoami"

    campaign_run = CampaignRun.objects.create(
        requested_by=request.user if getattr(request, "user", None) and request.user.is_authenticated else None,
        cidr=cidr,
        scan_method=scan_method,
        run_openvas=run_openvas,
        openvas_config=openvas_config,
        collect_loot=collect_loot,
        sliver_session_id=selected_sliver_session_id,
        sliver_command=selected_sliver_command,
        status=CampaignRun.Status.PENDING,
        current_step="queued",
        step_message="Queued for execution.",
    )

    try:
        task = run_ot_campaign_task.delay(
            cidr=cidr,
            scan_method=scan_method,
            agent_id=selected_agent_id,
            max_hosts=max_hosts,
            run_openvas=run_openvas,
            openvas_config=openvas_config,
            openvas_timeout_seconds=openvas_timeout,
            sliver_session_id=selected_sliver_session_id,
            sliver_command=selected_sliver_command,
            collect_loot=collect_loot,
            campaign_run_id=campaign_run.id,
        )
    except Exception as exc:
        campaign_run.status = CampaignRun.Status.FAILED
        campaign_run.step_message = f"Failed to queue campaign: {exc}"
        campaign_run.error_count = 1
        campaign_run.error_details = str(exc)
        campaign_run.finished_at = now()
        campaign_run.duration_seconds = 0
        campaign_run.save(
            update_fields=[
                "status",
                "step_message",
                "error_count",
                "error_details",
                "finished_at",
                "duration_seconds",
                "updated_at",
            ]
        )
        return JsonResponse({"error": f"failed to queue campaign: {exc}"}, status=500)

    campaign_run.celery_task_id = task.id
    campaign_run.status = CampaignRun.Status.RUNNING
    campaign_run.step_message = "Task accepted by worker."
    campaign_run.save(update_fields=["celery_task_id", "status", "step_message", "updated_at"])

    return JsonResponse(
        {
            "task_id": task.id,
            "campaign_run_id": campaign_run.id,
            "cidr": cidr,
            "scan_method": scan_method,
        },
        status=202,
    )


@require_GET
def ot_campaign_status(request, task_id):
    result = AsyncResult(str(task_id))
    payload = {"state": result.state}
    run = CampaignRun.objects.filter(celery_task_id=str(task_id)).order_by("-id").first()

    if isinstance(result.info, dict):
        payload.update(result.info)
    elif result.info and result.state not in {"PENDING", "SUCCESS"}:
        payload["message"] = str(result.info)

    if result.ready():
        if isinstance(result.result, Exception):
            payload["result"] = {"status": "failed", "error": str(result.result)}
        else:
            payload["result"] = result.result

    if run:
        payload["campaign_run_id"] = run.id
        payload["campaign_status"] = run.status
        payload["campaign"] = _serialize_campaign_run(run)

    return JsonResponse(payload)


# -----------------------------
# Agent Download and Distribution
# -----------------------------
@require_GET
def agent_download_page(request):
    """Page for downloading the host agent software."""
    from host_agent import AGENT_VERSION, AGENT_NAME
    from django.urls import reverse

    # Get the latest agent information
    latest_agents = AgentStatus.objects.filter(
        agent_version__isnull=False
    ).order_by('-last_version_check')[:5]

    return render(request, 'dashboard/agent_download.html', {
        'agent_version': AGENT_VERSION,
        'agent_name': AGENT_NAME,
        'latest_agents': latest_agents,
        'download_url': reverse("dashboard:download_host_agent")
    })


@require_http_methods(["GET", "HEAD"])
def download_host_agent(request):
    """Download the host agent as a ZIP file using FileResponse for efficient streaming."""
    import zipfile
    import tempfile

    print(f"[DEBUG] Download request from {request.META.get('REMOTE_ADDR', 'unknown')}")

    # Use a writable temp location inside the container.
    zips_dir = Path(tempfile.gettempdir()) / "cyber_agent_zips"
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

    # Gqet interface statistics
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


@require_GET
def gpwr_operations_page(request):
    return render(
        request,
        "dashboard/gpwr_operations.html",
        {
            "default_host": GPWR_DEFAULT_HOST,
            "default_port": GPWR_DEFAULT_PORT,
            "default_scan_cidr": GPWR_DEFAULT_SCAN_CIDR,
            "default_risk_targets": GPWR_DEFAULT_RISK_TARGETS,
            "default_risk_ports": GPWR_DEFAULT_RISK_PORTS,
        },
    )


@csrf_exempt
@require_http_methods(["POST"])
def gpwr_read_api(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    vars_value = str(payload.get("vars", "")).strip()
    if not vars_value:
        return JsonResponse({"error": "vars is required (space/comma separated)"}, status=400)

    var_list = [v.strip() for v in vars_value.replace(",", " ").split() if v.strip()]
    if not var_list:
        return JsonResponse({"error": "No valid variables provided"}, status=400)

    host = str(payload.get("host", GPWR_DEFAULT_HOST)).strip() or GPWR_DEFAULT_HOST
    port = int(payload.get("port", GPWR_DEFAULT_PORT))
    timeout = float(payload.get("timeout", 5.0))

    try:
        response = _gpwr_send_command("getcsv " + " ".join(var_list), host=host, port=port, timeout=timeout)
        values = response.split(",") if response else []
        parsed = []
        for idx, name in enumerate(var_list):
            value = values[idx] if idx < len(values) else ""
            parsed.append({"name": name, "value": value})
        return JsonResponse(
            {
                "status": "ok",
                "host": host,
                "port": port,
                "command": "getcsv " + " ".join(var_list),
                "raw_response": response,
                "metrics": parsed,
                "timestamp": timezone.now().isoformat(),
            }
        )
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=502)


@csrf_exempt
@require_http_methods(["POST"])
def gpwr_write_api(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    assignments = str(payload.get("set", "")).strip()
    if not assignments:
        return JsonResponse({"error": "set is required (e.g., tag=value tag2=value2)"}, status=400)

    host = str(payload.get("host", GPWR_DEFAULT_HOST)).strip() or GPWR_DEFAULT_HOST
    port = int(payload.get("port", GPWR_DEFAULT_PORT))
    timeout = float(payload.get("timeout", 5.0))
    command = "set " + assignments

    try:
        response = _gpwr_send_command(command, host=host, port=port, timeout=timeout)
        return JsonResponse(
            {
                "status": "ok",
                "host": host,
                "port": port,
                "command": command,
                "raw_response": response,
                "timestamp": timezone.now().isoformat(),
            }
        )
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=502)


@csrf_exempt
@require_http_methods(["POST"])
def gpwr_profile_api(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        payload = {}

    host = str(payload.get("host", GPWR_DEFAULT_HOST)).strip() or GPWR_DEFAULT_HOST
    port = int(payload.get("port", GPWR_DEFAULT_PORT))
    timeout = float(payload.get("timeout", 5.0))

    try:
        response = _gpwr_send_command("profile", host=host, port=port, timeout=timeout)
        return JsonResponse(
            {
                "status": "ok",
                "host": host,
                "port": port,
                "command": "profile",
                "raw_response": response,
                "timestamp": timezone.now().isoformat(),
            }
        )
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=502)


@require_GET
def gpwr_live_telemetry_api(request):
    limit = min(max(int(request.GET.get("limit", "20")), 1), 200)
    qs = SiemEvent.objects.filter(event_type="gpwr.telemetry").order_by("-timestamp")[:limit]

    rows = []
    for event in qs:
        raw = event.raw if isinstance(event.raw, dict) else {}
        raw_l1 = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
        raw_l2 = raw_l1.get("raw") if isinstance(raw_l1.get("raw"), dict) else {}

        metrics = {}
        for candidate in (raw.get("metrics"), raw_l1.get("metrics"), raw_l2.get("metrics")):
            if isinstance(candidate, dict) and candidate:
                metrics = candidate
                break

        labels = {}
        for candidate in (raw.get("labels"), raw_l1.get("labels"), raw_l2.get("labels")):
            if isinstance(candidate, dict):
                labels.update(candidate)

        subsystem = (
            labels.get("subsystem")
            or raw.get("subsystem")
            or raw_l1.get("subsystem")
            or raw_l2.get("subsystem")
            or ""
        )
        worker = (
            labels.get("worker")
            or raw.get("worker_id")
            or raw_l1.get("worker_id")
            or raw_l2.get("worker_id")
            or ""
        )
        source_obj = raw_l2.get("source") if isinstance(raw_l2.get("source"), dict) else {}

        purdue = {}
        for candidate in (raw.get("purdue"), raw_l1.get("purdue"), raw_l2.get("purdue")):
            if isinstance(candidate, dict):
                purdue = candidate
                break

        subsystem_key = str(subsystem).lower()
        subsystem_meta = GPWR_SUBSYSTEM_META.get(subsystem_key, {})
        purdue_level = str(purdue.get("asset_level", "")).strip() or subsystem_meta.get("level", "")
        purdue_zone = str(purdue.get("asset_zone", "")).strip() or subsystem_meta.get("zone", "")

        device = (
            event.asset_id
            or raw.get("agent_id")
            or raw_l1.get("agent_id")
            or raw_l2.get("agent_id")
            or ""
        )
        client_id = raw_l2.get("client_id") or raw_l1.get("client_id") or ""

        rows.append(
            {
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "asset_ip": event.asset_ip,
                "asset_id": event.asset_id,
                "device": device,
                "client_id": client_id,
                "subsystem": subsystem,
                "worker": str(worker) if worker != "" else "",
                "source_host": source_obj.get("host", ""),
                "source_port": source_obj.get("port", ""),
                "metrics": metrics,
                "current_values": metrics,
                "metric_count": len(metrics) if isinstance(metrics, dict) else 0,
                "purdue": purdue,
                "purdue_level": purdue_level,
                "purdue_zone": purdue_zone,
                "summary": event.summary,
            }
        )

    return JsonResponse(
        {
            "status": "ok",
            "count": len(rows),
            "results": rows,
            "server_time": timezone.now().isoformat(),
        }
    )


def _extract_gpwr_nested_payload(raw_payload: dict) -> dict:
    raw = raw_payload if isinstance(raw_payload, dict) else {}
    raw_l1 = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
    raw_l2 = raw_l1.get("raw") if isinstance(raw_l1.get("raw"), dict) else {}

    metrics = {}
    for candidate in (raw.get("metrics"), raw_l1.get("metrics"), raw_l2.get("metrics")):
        if isinstance(candidate, dict) and candidate:
            metrics = candidate
            break

    labels = {}
    for candidate in (raw.get("labels"), raw_l1.get("labels"), raw_l2.get("labels")):
        if isinstance(candidate, dict):
            labels.update(candidate)

    subsystem = (
        labels.get("subsystem")
        or raw.get("subsystem")
        or raw_l1.get("subsystem")
        or raw_l2.get("subsystem")
        or ""
    )
    worker = (
        labels.get("worker")
        or raw.get("worker_id")
        or raw_l1.get("worker_id")
        or raw_l2.get("worker_id")
        or ""
    )
    source_obj = raw_l2.get("source") if isinstance(raw_l2.get("source"), dict) else {}
    client_id = raw_l2.get("client_id") or raw_l1.get("client_id") or ""
    return {
        "metrics": metrics,
        "labels": labels,
        "subsystem": str(subsystem).lower(),
        "worker": str(worker) if worker != "" else "",
        "source_host": source_obj.get("host", ""),
        "source_port": source_obj.get("port", ""),
        "client_id": client_id,
    }


@csrf_exempt
@require_http_methods(["POST"])
def gpwr_workflow_baseline_api(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        payload = {}

    cidr = str(payload.get("cidr", GPWR_DEFAULT_SCAN_CIDR)).strip() or GPWR_DEFAULT_SCAN_CIDR
    method = str(payload.get("method", "nmap")).strip().lower()
    scan_sync = bool(payload.get("scan_sync", True))
    if method not in {"nmap", "ping"}:
        return JsonResponse({"error": "method must be nmap or ping"}, status=400)

    scan = ScanRun.objects.create(cidr=cidr, status="RUNNING", scan_type=method)
    try:
        if method == "nmap":
            if scan_sync:
                result = nmap_discovery_task(cidr, scan.id)
                scan.refresh_from_db()
                return JsonResponse(
                    {
                        "status": "ok",
                        "mode": "sync",
                        "method": method,
                        "scan_id": scan.id,
                        "cidr": cidr,
                        "result_summary": str(result),
                        "nodes_discovered": scan.nodes.count(),
                    }
                )
            task = nmap_discovery_task.delay(cidr, scan.id)
        else:
            if scan_sync:
                result = scan_network_task(cidr, scan.id)
                scan.refresh_from_db()
                return JsonResponse(
                    {
                        "status": "ok",
                        "mode": "sync",
                        "method": method,
                        "scan_id": scan.id,
                        "cidr": cidr,
                        "result_summary": str(result),
                        "nodes_discovered": scan.nodes.count(),
                    }
                )
            task = scan_network_task.delay(cidr, scan.id)
    except Exception as exc:
        scan.status = "FAILED"
        scan.result_summary = str(exc)
        scan.save(update_fields=["status", "result_summary"])
        return JsonResponse({"error": str(exc)}, status=500)

    return JsonResponse(
        {
            "status": "ok",
            "mode": "async",
            "method": method,
            "scan_id": scan.id,
            "cidr": cidr,
            "task_id": str(task.id),
        }
    )


@require_GET
def gpwr_workflow_enumerate_api(request):
    scan_id = request.GET.get("scan_id")
    if scan_id:
        try:
            scan = ScanRun.objects.get(id=int(scan_id))
        except Exception:
            return JsonResponse({"error": "scan_id not found"}, status=404)
    else:
        scan = ScanRun.objects.order_by("-timestamp").first()

    if not scan:
        return JsonResponse({"error": "no scan available"}, status=404)

    assets = []
    for node in scan.nodes.all().order_by("ip_address"):
        assets.append(
            {
                "id": node.id,
                "name": node.name,
                "ip": node.ip_address,
                "status": node.status,
                "active_ports": node.active_ports or [],
            }
        )

    subsystem_state = {}
    recent = SiemEvent.objects.filter(event_type="gpwr.telemetry").order_by("-timestamp")[:200]
    for event in recent:
        parsed = _extract_gpwr_nested_payload(event.raw if isinstance(event.raw, dict) else {})
        subsystem = parsed.get("subsystem") or "unknown"
        if subsystem not in subsystem_state:
            subsystem_state[subsystem] = {
                "subsystem": subsystem,
                "last_timestamp": event.timestamp.isoformat(),
                "asset_ip": event.asset_ip,
                "zone": GPWR_SUBSYSTEM_META.get(subsystem, {}).get("zone", "Unknown"),
                "purdue_level": GPWR_SUBSYSTEM_META.get(subsystem, {}).get("level", "L1/L2"),
                "workers": set(),
                "clients": set(),
                "latest_values": parsed.get("metrics", {}),
            }
        if parsed.get("worker"):
            subsystem_state[subsystem]["workers"].add(parsed["worker"])
        if parsed.get("client_id"):
            subsystem_state[subsystem]["clients"].add(parsed["client_id"])

    subsystem_rows = []
    for subsystem, item in subsystem_state.items():
        profile = OT_QEMU_PROFILES.get(subsystem, OT_QEMU_PROFILES["unknown"])
        subsystem_rows.append(
            {
                "subsystem": subsystem,
                "zone": item["zone"],
                "purdue_level": item["purdue_level"],
                "asset_ip": item["asset_ip"],
                "last_timestamp": item["last_timestamp"],
                "workers": sorted(item["workers"]),
                "clients": sorted(item["clients"]),
                "latest_values": item["latest_values"],
                "qemu_profile": profile,
            }
        )

    catalog_subsystems = _load_gpwr_subsystem_catalog()
    return JsonResponse(
        {
            "status": "ok",
            "scan_id": scan.id,
            "scan_cidr": scan.cidr,
            "scan_status": scan.status,
            "asset_count": len(assets),
            "assets": assets,
            "subsystems": subsystem_rows,
            "catalog_subsystems": catalog_subsystems,
            "qemu_profiles": OT_QEMU_PROFILES,
        }
    )


@require_GET
def gpwr_subsystem_graph_api(request):
    subsystem = str(request.GET.get("subsystem", "rcs")).strip().lower()
    if not subsystem:
        subsystem = "rcs"

    recent = SiemEvent.objects.filter(event_type="gpwr.telemetry").order_by("-timestamp")[:300]
    workers = set()
    clients = set()
    latest_values = {}
    last_ts = ""
    asset_ip = ""

    for event in recent:
        parsed = _extract_gpwr_nested_payload(event.raw if isinstance(event.raw, dict) else {})
        if parsed.get("subsystem") != subsystem:
            continue
        if not last_ts:
            last_ts = event.timestamp.isoformat()
            asset_ip = event.asset_ip or ""
            latest_values = parsed.get("metrics", {}) if isinstance(parsed.get("metrics"), dict) else {}
        if parsed.get("worker"):
            workers.add(parsed["worker"])
        if parsed.get("client_id"):
            clients.add(parsed["client_id"])

    zone = GPWR_SUBSYSTEM_META.get(subsystem, {}).get("zone", "Unknown")
    level = GPWR_SUBSYSTEM_META.get(subsystem, {}).get("level", "L1/L2")
    qemu_profile = OT_QEMU_PROFILES.get(subsystem, OT_QEMU_PROFILES["unknown"])
    if zone == "Unknown":
        for item in _load_gpwr_subsystem_catalog():
            if item.get("subsystem") == subsystem:
                zone = str(item.get("purdue_zone") or zone)
                level = str(item.get("purdue_level") or level)
                break

    nodes = [
        {
            "id": f"subsystem:{subsystem}",
            "label": subsystem.upper(),
            "kind": "subsystem",
            "meta": {"zone": zone, "purdue_level": level, "asset_ip": asset_ip, "last_timestamp": last_ts},
        }
    ]
    edges = []

    for worker in sorted(workers):
        wid = f"worker:{subsystem}:{worker}"
        nodes.append({"id": wid, "label": f"worker {worker}", "kind": "worker"})
        edges.append({"source": f"subsystem:{subsystem}", "target": wid, "label": "polls"})

    for client in sorted(clients):
        cid = f"client:{client}"
        nodes.append({"id": cid, "label": client, "kind": "client"})
        edges.append({"source": f"subsystem:{subsystem}", "target": cid, "label": "endpoint"})

    for key, value in sorted(latest_values.items()):
        mid = f"metric:{key}"
        nodes.append({"id": mid, "label": f"{key}={value}", "kind": "metric"})
        edges.append({"source": f"subsystem:{subsystem}", "target": mid, "label": "value"})

    return JsonResponse(
        {
            "status": "ok",
            "subsystem": subsystem,
            "zone": zone,
            "purdue_level": level,
            "asset_ip": asset_ip,
            "last_timestamp": last_ts,
            "qemu_profile": qemu_profile,
            "nodes": nodes,
            "edges": edges,
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def gpwr_workflow_risk_api(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        payload = {}

    targets = str(payload.get("targets", GPWR_DEFAULT_RISK_TARGETS)).strip() or GPWR_DEFAULT_RISK_TARGETS
    ports = str(payload.get("ports", GPWR_DEFAULT_RISK_PORTS)).strip() or GPWR_DEFAULT_RISK_PORTS
    siem_hours = int(payload.get("siem_hours", 24) or 24)
    output = str(payload.get("output", "/tmp/ot_risk_report_web.json")).strip() or "/tmp/ot_risk_report_web.json"

    cmd = [
        "python",
        "/code/cyber_pen_test/manage.py",
        "classify_ot_risk",
        "--targets",
        targets,
        "--ports",
        ports,
        "--siem-hours",
        str(siem_hours),
        "--output",
        output,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return JsonResponse(
            {
                "error": "classify_ot_risk failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout[-1200:],
                "stderr": proc.stderr[-1200:],
            },
            status=500,
        )

    report = {}
    try:
        with open(output, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        report = {}

    tier_counts = defaultdict(int)
    for item in report.get("results", []) if isinstance(report, dict) else []:
        tier_counts[str(item.get("risk_tier", "Unknown"))] += 1

    return JsonResponse(
        {
            "status": "ok",
            "output": output,
            "result_count": len(report.get("results", [])) if isinstance(report, dict) else 0,
            "tier_counts": dict(tier_counts),
            "stdout": proc.stdout[-1200:],
            "stderr": proc.stderr[-1200:],
            "report": report,
        }
    )


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
    agents = list(AgentStatus.objects.filter(status='online').order_by('-last_heartbeat'))
    node_candidates = list(Node.objects.exclude(ip_address__isnull=True).order_by('-id'))
    iaea_testbed_active = _is_iaea_testbed_active(node_candidates, agents)

    topology_nodes = []
    edges = []
    seen_node_keys = set()
    node_by_agent_id = {str(node.agent_id): node for node in node_candidates if node.agent_id}
    node_by_ip = {}
    for node in node_candidates:
        ip_text = str(node.ip_address or "").strip()
        if ip_text and ip_text not in node_by_ip:
            node_by_ip[ip_text] = node
    layer_map = {layer["slug"]: {"slug": layer["slug"], "label": layer["label"], "accent": layer["accent"], "nodes": []} for layer in PURDUE_TOPOLOGY_LAYERS}
    layer_order = {layer["slug"]: index for index, layer in enumerate(PURDUE_TOPOLOGY_LAYERS)}

    def _append_topology_node(node_obj=None, agent_obj=None):
        ip_text = ""
        if node_obj and node_obj.ip_address:
            ip_text = str(node_obj.ip_address)
        elif agent_obj and agent_obj.ip_address:
            ip_text = str(agent_obj.ip_address)
        key = str(node_obj.id) if node_obj else str(agent_obj.agent_id if agent_obj else ip_text)
        if key in seen_node_keys:
            return
        seen_node_keys.add(key)

        name = _topology_identity_text(getattr(node_obj, "name", ""), getattr(agent_obj, "hostname", ""))
        hostname = _topology_identity_text(getattr(node_obj, "hostname", ""), getattr(agent_obj, "hostname", ""), name)
        override = _iaea_topology_override(hostname, name, ip_text) if iaea_testbed_active else None
        if override:
            layer = override["layer"]
            role_slug = override["role_slug"]
            role_label = override["role_label"]
            role_icon = override["icon"]
            label = override["label"]
            segment_label = override["segment_label"]
        else:
            layer = _infer_purdue_layer(name, hostname, ip_text, getattr(node_obj, "description", ""))
            role_slug, role_label, role_icon = _infer_topology_role(name, hostname, ip_text, getattr(node_obj, "description", ""))
            label = _topology_identity_text(hostname, name, ip_text)
            segment_label = _topology_segment_label(ip_text)
        node_url = reverse("dashboard:node_detail_page", args=[node_obj.id]) if node_obj else ""
        payload = {
            "id": str(getattr(node_obj, "id", "") or getattr(agent_obj, "agent_id", "") or ip_text),
            "node_id": getattr(node_obj, "id", None),
            "label": label,
            "hostname": hostname,
            "name": name,
            "ip_address": ip_text,
            "type": "node" if node_obj else "agent",
            "status": getattr(agent_obj, "status", getattr(node_obj, "status", "unknown")) or "unknown",
            "os_type": getattr(agent_obj, "os_type", ""),
            "last_heartbeat": (
                getattr(agent_obj, "last_heartbeat", None).strftime('%Y-%m-%d %H:%M:%S')
                if getattr(agent_obj, "last_heartbeat", None) else
                (getattr(node_obj, "last_heartbeat", None).strftime('%Y-%m-%d %H:%M:%S') if getattr(node_obj, "last_heartbeat", None) else 'Never')
            ),
            "purdue_level": layer,
            "purdue_label": _topology_layer_meta(layer)["label"],
            "segment_label": segment_label,
            "role": role_slug,
            "role_label": role_label,
            "icon": role_icon,
            "node_url": node_url,
            "agent_id": getattr(agent_obj, "agent_id", getattr(node_obj, "agent_id", "")),
            "vulnerability_count": (
                ScanVulnerability.objects.filter(host_ip=ip_text).count() if ip_text else 0
            ) + (node_obj.vulnerability_set.count() if node_obj else 0),
        }
        topology_nodes.append(payload)
        layer_map.setdefault(layer, {"slug": layer, "label": _topology_layer_meta(layer)["label"], "accent": _topology_layer_meta(layer)["accent"], "nodes": []})
        layer_map[layer]["nodes"].append(payload)

    for node in node_candidates:
        _append_topology_node(node_obj=node, agent_obj=None)
    for agent in agents:
        _append_topology_node(node_obj=node_by_agent_id.get(str(agent.agent_id)) or node_by_ip.get(str(agent.ip_address)), agent_obj=agent)
    if iaea_testbed_active:
        for static_node in IAEA_TESTBED_STATIC_TOPOLOGY:
            if static_node["ip_address"] in node_by_ip:
                continue
            if static_node["ip_address"] in {item["ip_address"] for item in topology_nodes}:
                continue
            layer = static_node["layer"]
            payload = {
                "id": f"static:{static_node['hostname']}",
                "node_id": None,
                "label": static_node["label"],
                "hostname": static_node["hostname"],
                "name": static_node["label"],
                "ip_address": static_node["ip_address"],
                "type": "static",
                "status": "modeled",
                "os_type": "",
                "last_heartbeat": "N/A",
                "purdue_level": layer,
                "purdue_label": _topology_layer_meta(layer)["label"],
                "segment_label": static_node["segment_label"],
                "role": static_node["role_slug"],
                "role_label": static_node["role_label"],
                "icon": static_node["icon"],
                "node_url": "",
                "agent_id": "",
                "vulnerability_count": 0,
            }
            topology_nodes.append(payload)
            layer_map.setdefault(layer, {"slug": layer, "label": _topology_layer_meta(layer)["label"], "accent": _topology_layer_meta(layer)["accent"], "nodes": []})
            layer_map[layer]["nodes"].append(payload)

    nodes = sorted(topology_nodes, key=lambda item: (layer_order.get(item["purdue_level"], 99), item["label"]))

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

    layers = []
    for layer in PURDUE_TOPOLOGY_LAYERS:
        layer_payload = layer_map.get(layer["slug"], {"nodes": []})
        layers.append({
            "slug": layer["slug"],
            "label": layer["label"],
            "accent": layer["accent"],
            "nodes": sorted(layer_payload.get("nodes", []), key=lambda item: item["label"]),
        })

    return JsonResponse({
        'nodes': nodes,
        'edges': edges,
        'layers': layers,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


def risk_assessment_page(request):
    return render(
        request,
        'dashboard/risk_assessment.html',
        {
            "risk_pid_target_path": getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", ""),
        },
    )


@require_http_methods(["POST"])
def risk_assessment_pid_upload(request):
    upload = request.FILES.get("drawio_file")
    if upload is None:
        return JsonResponse({"error": "drawio_file is required."}, status=400)

    output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
    output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
    prefix = build_timestamp_prefix()

    try:
        xml_path = store_drawio_upload(upload, output_dir, prefix)
        sim_system, sim_path = convert_drawio_to_sim_system(xml_path, output_dir, prefix)
    except DrawioParseError as exc:
        return JsonResponse({"error": f"Invalid draw.io XML: {exc}"}, status=400)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    upload_requested = str(request.POST.get("upload_target", "")).lower() in ("1", "true", "yes", "on")
    run_validation = str(request.POST.get("run_validation", "")).lower() in ("1", "true", "yes", "on")
    scan_method = (request.POST.get("scan") or "").lower()
    scan_sync = str(request.POST.get("scan_sync") or "").lower() in ("1", "true", "yes", "on")
    run_openvas = str(request.POST.get("openvas") or "").lower() in ("1", "true", "yes", "on")
    create_twin = str(request.POST.get("create_twin") or "").lower() in ("1", "true", "yes", "on")
    scan_run_id = request.POST.get("scan_run_id")
    if scan_run_id:
        try:
            scan_run_id = int(scan_run_id)
        except (TypeError, ValueError):
            return JsonResponse({"error": "scan_run_id must be an integer."}, status=400)
    else:
        scan_run_id = None
    upload_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
    upload_url = getattr(settings, "RISK_ASSESSMENT_UPLOAD_URL", "")
    upload_token = getattr(settings, "RISK_ASSESSMENT_UPLOAD_TOKEN", "")
    upload_result = {
        "attempted": upload_requested,
        "success": False,
        "path": None,
        "error": None,
        "posted": False,
        "post_error": None,
    }

    if upload_requested:
        if upload_path_value:
            try:
                uploaded_path = upload_sim_system(sim_path, Path(upload_path_value))
                upload_result["success"] = True
                upload_result["path"] = _relative_to_base(uploaded_path)
            except Exception as exc:
                upload_result["error"] = str(exc)
        else:
            upload_result["error"] = "RISK_ASSESSMENT_SIM_SYSTEM_PATH not configured."

        if upload_url:
            try:
                headers = {}
                if upload_token:
                    headers["Authorization"] = f"Bearer {upload_token}"
                response = requests.post(upload_url, json=sim_system, headers=headers, timeout=RISK_ASSESSMENT_TIMEOUT)
                response.raise_for_status()
                upload_result["posted"] = True
            except Exception as exc:
                upload_result["post_error"] = str(exc)

    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    connections = sim_system.get("connections", []) if isinstance(sim_system, dict) else []

    validation_result = None
    if run_validation:
        validation_result = _pid_validation_pipeline(
            sim_system=sim_system,
            scan_method=scan_method,
            scan_sync=scan_sync,
            run_openvas=run_openvas,
            create_twin=create_twin,
            scan_run_id=scan_run_id,
        )

    return JsonResponse(
        {
            "variables_count": len(variables),
            "connections_count": len(connections),
            "drawio_path": _relative_to_base(xml_path),
            "sim_system_path": _relative_to_base(sim_path),
            "upload": upload_result,
            "validation": {
                "summary": validation_result[0],
                "validation": validation_result[1],
                "discovery_scans": validation_result[2],
                "openvas_scans": validation_result[3],
                "digital_twin": validation_result[4],
            } if validation_result else None,
        }
    )


@require_GET
def risk_assessment_pid_system_api(request):
    source = request.GET.get("source", "auto")
    include_network = request.GET.get("include_network", "1").lower() not in ("0", "false", "no")

    output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
    output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
    target_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
    target_path = Path(target_path_value) if target_path_value else None

    sim_path, resolved_source = resolve_sim_system_path(source, output_dir, target_path)
    if not sim_path:
        return JsonResponse({"error": "No sim_system.json found."}, status=404)

    try:
        sim_system = load_sim_system_file(sim_path)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    elements, meta = build_system_elements(sim_system, include_network=include_network)
    meta.update(
        {
            "source": resolved_source,
            "file": _relative_to_base(sim_path),
            "include_network": include_network,
        }
    )

    return JsonResponse({"elements": elements, "meta": meta})


@require_GET
def risk_assessment_pid_nodes_api(request):
    source = request.GET.get("source", "auto")
    output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
    output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
    target_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
    target_path = Path(target_path_value) if target_path_value else None

    sim_path, resolved_source = resolve_sim_system_path(source, output_dir, target_path)
    if not sim_path:
        return JsonResponse({"error": "No sim_system.json found."}, status=404)

    try:
        sim_system = load_sim_system_file(sim_path)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
    nodes = []
    for var_id, info in variables.items():
        info = info if isinstance(info, dict) else {}
        nodes.append({
            "id": str(var_id),
            "type": info.get("type") or "unknown",
            "module": info.get("module") or "",
            "domain": info.get("domain") or "",
        })

    return JsonResponse({"source": resolved_source, "nodes": nodes})


@require_http_methods(["POST"])
def risk_assessment_pid_validate(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    source = payload.get("source", "auto")
    scan_method = (payload.get("scan") or "").lower()
    scan_sync = bool(payload.get("scan_sync"))
    run_openvas = bool(payload.get("openvas"))
    create_twin = bool(payload.get("create_twin"))
    scan_run_id = payload.get("scan_run_id")

    if scan_run_id is not None:
        try:
            scan_run_id = int(scan_run_id)
        except (TypeError, ValueError):
            return JsonResponse({'error': 'scan_run_id must be an integer.'}, status=400)

    output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
    output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
    target_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
    target_path = Path(target_path_value) if target_path_value else None

    sim_path, resolved_source = resolve_sim_system_path(source, output_dir, target_path)
    if not sim_path:
        return JsonResponse({"error": "No sim_system.json found."}, status=404)

    try:
        sim_system = load_sim_system_file(sim_path)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    summary, validation, scan_results, openvas_results, twin_result = _pid_validation_pipeline(
        sim_system=sim_system,
        scan_method=scan_method,
        scan_sync=scan_sync,
        run_openvas=run_openvas,
        create_twin=create_twin,
        scan_run_id=scan_run_id,
    )

    return JsonResponse({
        "source": resolved_source,
        "sim_system_path": _relative_to_base(sim_path),
        "summary": summary,
        "validation": validation,
        "discovery_scans": scan_results,
        "openvas_scans": openvas_results,
        "digital_twin": twin_result,
    })


@require_http_methods(["POST"])
def risk_assessment_pid_testbed(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    source = payload.get("source", "auto")
    output_dir = payload.get("output_dir")
    output_dir = Path(output_dir) if output_dir else Path(settings.BASE_DIR) / "out" / "pid_drawio"

    output_dir_value = getattr(settings, "PID_DRAWIO_OUTPUT_DIR", None)
    default_output_dir = Path(output_dir_value) if output_dir_value else Path(settings.BASE_DIR) / "out" / "pid_drawio"
    target_path_value = getattr(settings, "RISK_ASSESSMENT_SIM_SYSTEM_PATH", "")
    target_path = Path(target_path_value) if target_path_value else None

    sim_path, resolved_source = resolve_sim_system_path(source, default_output_dir, target_path)
    if not sim_path:
        return JsonResponse({"error": "No sim_system.json found."}, status=404)

    try:
        sim_system = load_sim_system_file(sim_path)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    files = build_testbed_from_sim_system(sim_system, output_dir)
    return JsonResponse({
        "source": resolved_source,
        "sim_system_path": _relative_to_base(sim_path),
        "compose_path": _relative_to_base(files.compose_path),
        "inventory_path": _relative_to_base(files.inventory_path),
    })


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
def risk_assessment_evidence_api(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    evidence = payload.get("evidence", {})
    nodes = payload.get("nodes", None)
    t_value = payload.get("T", None)

    if not isinstance(evidence, dict):
        return JsonResponse({'error': 'evidence must be an object.'}, status=400)

    if nodes is not None and not isinstance(nodes, list):
        return JsonResponse({'error': 'nodes must be a list of node names.'}, status=400)

    if t_value is not None:
        try:
            t_value = int(t_value)
        except (TypeError, ValueError):
            return JsonResponse({'error': 'T must be an integer.'}, status=400)

    try:
        response = _risk_call(
            requests.post,
            '/evidence',
            json={
                "T": t_value if t_value is not None else 3,
                "evidence": evidence,
                "nodes": nodes,
            },
        )
        return JsonResponse(response.json())
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=502)


@require_http_methods(["POST"])
def risk_assessment_probability_api(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    t_value = payload.get("T", None)
    if t_value is not None:
        try:
            t_value = int(t_value)
        except (TypeError, ValueError):
            return JsonResponse({'error': 'T must be an integer.'}, status=400)

    cyber_data = payload.get("cyber_data")
    if cyber_data is None and payload.get("scanned_nodes") is not None:
        cyber_data = payload

    if not isinstance(cyber_data, dict):
        return JsonResponse({'error': 'cyber_data must be provided for /probability.'}, status=400)

    try:
        response = _risk_call(
            requests.post,
            '/probability',
            json=cyber_data,
            params={"T": t_value} if t_value is not None else None,
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


def _pid_validation_pipeline(
    sim_system: dict,
    scan_method: str,
    scan_sync: bool,
    run_openvas: bool,
    create_twin: bool,
    scan_run_id: Optional[int],
) -> tuple[dict, dict, list, list, Optional[dict]]:
    expected_nodes = expected_cyber_nodes(sim_system)
    summary = summarize_expected_nodes(expected_nodes)

    nodes_qs = Node.objects.all()
    if scan_run_id:
        nodes_qs = nodes_qs.filter(scan_run_id=scan_run_id)
    discovered_ips = list(nodes_qs.values_list("ip_address", flat=True))
    interface_ips = list(NodeInterface.objects.filter(node__in=nodes_qs).values_list("ip", flat=True))

    validation = validate_expected_nodes(expected_nodes, [*discovered_ips, *interface_ips])

    scan_results = []
    if scan_method in {"ping", "nmap"}:
        vlan_cidrs = []
        for cidr_list in summary.get("vlan_cidrs", {}).values():
            vlan_cidrs.extend(cidr_list)
        vlan_cidrs = sorted(set(vlan_cidrs))
        for cidr in vlan_cidrs:
            if scan_method == "nmap":
                result = nmap_discovery_task(cidr) if scan_sync else nmap_discovery_task.delay(cidr)
            else:
                result = scan_network_task(cidr) if scan_sync else scan_network_task.delay(cidr)
            scan_results.append({"cidr": cidr, "method": scan_method, "result": str(result)})

    openvas_results = []
    if run_openvas:
        vlan_cidrs = []
        for cidr_list in summary.get("vlan_cidrs", {}).values():
            vlan_cidrs.extend(cidr_list)
        vlan_cidrs = sorted(set(vlan_cidrs))
        for cidr in vlan_cidrs:
            result = launch_openvas_scan_task.delay(cidr)
            openvas_results.append({"cidr": cidr, "result": str(result)})

    twin_result = None
    if create_twin:
        variables = sim_system.get("variables", {}) if isinstance(sim_system, dict) else {}
        connections = sim_system.get("connections", []) if isinstance(sim_system, dict) else []
        ip_by_id = {node.node_id: node.ip for node in expected_nodes if node.ip}

        node_by_id = {}
        link_count = 0
        with transaction.atomic():
            scan = ScanRun.objects.create(
                cidr="pid",
                status="COMPLETE",
                scan_type="pid",
                result_summary="Digital twin generated from PID sim_system.json",
            )
            for var_id, info in variables.items():
                info = info if isinstance(info, dict) else {}
                if var_id not in ip_by_id:
                    continue
                ip_addr = ip_by_id[var_id]
                name = str(info.get("name") or var_id)
                description_parts = []
                if info.get("purdue_level"):
                    description_parts.append(f"Purdue: {info.get('purdue_level')}")
                if info.get("vlan"):
                    description_parts.append(f"VLAN: {info.get('vlan')}")
                if info.get("redundancy_group"):
                    description_parts.append(f"Redundancy: {info.get('redundancy_group')}")
                node = Node.objects.create(
                    scan_run=scan,
                    ip_address=ip_addr,
                    name=name,
                    status="online",
                    description=" | ".join(description_parts),
                )
                node_by_id[str(var_id)] = node

            for conn in connections:
                if not isinstance(conn, dict):
                    continue
                source = str(conn.get("source"))
                target = str(conn.get("target"))
                if source in node_by_id and target in node_by_id:
                    Link.objects.create(
                        scan_run=scan,
                        source=node_by_id[source],
                        destination=node_by_id[target],
                        weight=1.0,
                    )
                    link_count += 1

        twin_result = {"scan_id": scan.id, "nodes": len(node_by_id), "links": link_count}

    return summary, validation, scan_results, openvas_results, twin_result


def _relative_to_base(path: Path) -> str:
    try:
        return str(path.relative_to(settings.BASE_DIR))
    except Exception:
        return str(path)
