from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import json
import requests
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import timezone


class OpensearchError(RuntimeError):
    pass


@dataclass
class OpensearchConfig:
    url: str
    index_prefix: str
    username: str = ""
    password: str = ""
    verify_tls: bool = True


def _get_config() -> Optional[OpensearchConfig]:
    if not getattr(settings, "OPENSEARCH_ENABLED", False):
        return None
    url = getattr(settings, "OPENSEARCH_URL", "")
    if not url:
        return None
    return OpensearchConfig(
        url=url.rstrip("/"),
        index_prefix=getattr(settings, "OPENSEARCH_INDEX_PREFIX", "siem-events"),
        username=getattr(settings, "OPENSEARCH_USER", ""),
        password=getattr(settings, "OPENSEARCH_PASS", ""),
        verify_tls=getattr(settings, "OPENSEARCH_VERIFY_TLS", True),
    )


def _get_settings_config() -> Optional[OpensearchConfig]:
    url = getattr(settings, "OPENSEARCH_URL", "")
    if not url:
        return None
    return OpensearchConfig(
        url=url.rstrip("/"),
        index_prefix=getattr(settings, "OPENSEARCH_INDEX_PREFIX", "siem-events"),
        username=getattr(settings, "OPENSEARCH_USER", ""),
        password=getattr(settings, "OPENSEARCH_PASS", ""),
        verify_tls=getattr(settings, "OPENSEARCH_VERIFY_TLS", True),
    )


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        ts = value
    else:
        ts = timezone.now()
        if isinstance(value, str):
            try:
                ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                ts = timezone.now()
    if timezone.is_naive(ts):
        ts = timezone.make_aware(ts, timezone=timezone.utc)
    return ts


def build_index_name(prefix: str, timestamp: Any) -> str:
    ts = _parse_timestamp(timestamp)
    return f"{prefix}-{ts:%Y.%m.%d}"


def _obj(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _port_value(*values: Any) -> Any:
    for value in values:
        if value in (None, ""):
            continue
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= port <= 65535:
            return port
    return None


def build_bulk_payload(events: Iterable[Dict[str, Any]], prefix: str) -> str:
    lines: List[str] = []
    for event in events:
        index_name = build_index_name(prefix, event.get("timestamp"))
        action = {"index": {"_index": index_name}}
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        raw_event = _obj(raw.get("event"))
        raw_observer = _obj(raw.get("observer"))
        raw_source = _obj(raw.get("source"))
        raw_destination = _obj(raw.get("destination"))
        raw_network = _obj(raw.get("network"))
        ingress_interface = _obj(_obj(raw_observer.get("ingress")).get("interface"))
        event_module = event.get("event_module") or raw.get("event_module") or raw_event.get("module")
        event_dataset = event.get("event_dataset") or raw.get("event_dataset") or raw_event.get("dataset")
        observer_name = event.get("observer_name") or raw.get("observer_name") or raw_observer.get("name")
        event_source = event.get("source")
        source_ip = (
            event.get("source_ip")
            or raw.get("src_ip")
            or raw.get("source_ip")
            or raw_source.get("ip")
            or raw.get("id_orig_h")
            or raw.get("id.orig_h")
        )
        source_port = _port_value(
            event.get("source_port"),
            raw.get("src_port"),
            raw.get("source_port"),
            raw_source.get("port"),
            raw.get("id_orig_p"),
            raw.get("id.orig_p"),
        )
        destination_ip = (
            event.get("destination_ip")
            or raw.get("dest_ip")
            or raw.get("destination_ip")
            or raw_destination.get("ip")
            or raw.get("id_resp_h")
            or raw.get("id.resp_h")
        )
        destination_port = _port_value(
            event.get("destination_port"),
            raw.get("dest_port"),
            raw.get("destination_port"),
            raw_destination.get("port"),
            raw.get("id_resp_p"),
            raw.get("id.resp_p"),
        )
        network_community_id = (
            event.get("network_community_id")
            or raw.get("network_community_id")
            or raw_network.get("community_id")
        )
        related_ips = [
            value
            for value in [event.get("asset_ip"), source_ip, destination_ip]
            if value not in (None, "")
        ]
        related_ips = list(dict.fromkeys(related_ips))
        document = {
            "@timestamp": _parse_timestamp(event.get("timestamp")).isoformat(),
            "event_type": event.get("event_type"),
            "event_source": event_source,
            "event_module": event_module,
            "event_dataset": event_dataset,
            "observer_name": observer_name,
            "severity": event.get("severity"),
            "asset_id": event.get("asset_id"),
            "asset_ip": event.get("asset_ip"),
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "network_community_id": network_community_id,
            "event": {
                "module": event_module,
                "dataset": event_dataset,
            },
            "observer": {
                "name": observer_name,
                "type": raw_observer.get("type"),
                "ingress": {
                    "interface": {
                        "name": ingress_interface.get("name"),
                    }
                },
            },
            "source": {
                "ip": source_ip,
                "port": source_port,
            },
            "destination": {
                "ip": destination_ip,
                "port": destination_port,
            },
            "network": {
                "community_id": network_community_id,
                "transport": raw_network.get("transport"),
            },
            "related": {
                "ip": related_ips,
            },
            "summary": event.get("summary"),
            "raw": event.get("raw"),
            "ingested_at": timezone.now().isoformat(),
        }
        lines.append(json.dumps(action))
        lines.append(json.dumps(document, cls=DjangoJSONEncoder))
    return "\n".join(lines) + "\n"


def bulk_index_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    config = _get_config()
    if not config:
        return {"enabled": False, "indexed": 0}

    payload = build_bulk_payload(events, config.index_prefix)
    if not payload.strip():
        return {"enabled": True, "indexed": 0}

    headers = {"Content-Type": "application/x-ndjson"}
    auth = (config.username, config.password) if config.username else None

    response = requests.post(
        f"{config.url}/_bulk",
        data=payload,
        headers=headers,
        auth=auth,
        verify=config.verify_tls,
        timeout=10,
    )
    if not response.ok:
        raise OpensearchError(f"OpenSearch bulk indexing failed ({response.status_code})")

    data = response.json()
    if data.get("errors"):
        raise OpensearchError("OpenSearch bulk indexing returned errors")

    return {"enabled": True, "indexed": len(events)}


def get_opensearch_overview() -> Dict[str, Any]:
    config = _get_settings_config()
    overview = {
        "enabled": bool(getattr(settings, "OPENSEARCH_ENABLED", False)),
        "configured": bool(config),
        "url": config.url if config else "",
        "dashboards_url": getattr(settings, "OPENSEARCH_DASHBOARDS_URL", "http://127.0.0.1:5601"),
        "index_prefix": getattr(settings, "OPENSEARCH_INDEX_PREFIX", "siem-events"),
        "status": "disabled" if not getattr(settings, "OPENSEARCH_ENABLED", False) else "unknown",
        "cluster_status": "",
        "node_count": 0,
        "active_primary_shards": 0,
        "unassigned_shards": 0,
        "indices": [],
        "index_count": 0,
        "document_count": 0,
        "error": "",
    }
    if not config:
        overview["status"] = "unconfigured"
        return overview

    auth = (config.username, config.password) if config.username else None
    try:
        cluster_resp = requests.get(
            f"{config.url}/_cluster/health",
            auth=auth,
            verify=config.verify_tls,
            timeout=5,
        )
        cluster_resp.raise_for_status()
        cluster = cluster_resp.json()
        overview["cluster_status"] = cluster.get("status", "")
        overview["node_count"] = cluster.get("number_of_nodes", 0)
        overview["active_primary_shards"] = cluster.get("active_primary_shards", 0)
        overview["unassigned_shards"] = cluster.get("unassigned_shards", 0)
        overview["status"] = "ok"

        indices_resp = requests.get(
            f"{config.url}/_cat/indices/{config.index_prefix}-*",
            params={"format": "json", "h": "index,health,status,docs.count,store.size"},
            auth=auth,
            verify=config.verify_tls,
            timeout=5,
        )
        if indices_resp.ok:
            indices = indices_resp.json()
            normalized_indices = [
                {
                    "index": item.get("index", ""),
                    "health": item.get("health", ""),
                    "status": item.get("status", ""),
                    "docs_count": int(item.get("docs.count") or 0),
                    "store_size": item.get("store.size", ""),
                }
                for item in indices
            ]
            overview["indices"] = normalized_indices[:10]
            overview["index_count"] = len(indices)
            overview["document_count"] = sum(item["docs_count"] for item in normalized_indices)
    except Exception as exc:
        overview["status"] = "error"
        overview["error"] = str(exc)

    return overview
