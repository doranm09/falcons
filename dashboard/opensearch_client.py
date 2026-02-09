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


def build_bulk_payload(events: Iterable[Dict[str, Any]], prefix: str) -> str:
    lines: List[str] = []
    for event in events:
        index_name = build_index_name(prefix, event.get("timestamp"))
        action = {"index": {"_index": index_name}}
        document = {
            "@timestamp": _parse_timestamp(event.get("timestamp")).isoformat(),
            "event_type": event.get("event_type"),
            "source": event.get("source"),
            "severity": event.get("severity"),
            "asset_id": event.get("asset_id"),
            "asset_ip": event.get("asset_ip"),
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
