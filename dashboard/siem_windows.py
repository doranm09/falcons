from __future__ import annotations

from typing import Any, Dict


def windows_event_to_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    provider = payload.get("provider") or payload.get("Provider") or {}
    provider_name = provider.get("name") if isinstance(provider, dict) else provider
    system = payload.get("system") or payload.get("System") or {}
    event_id = system.get("event_id") or system.get("EventID")
    computer = system.get("computer") or system.get("Computer")
    message = payload.get("message") or payload.get("Message") or ""

    return {
        "event_type": "windows.event",
        "source": "windows",
        "timestamp": payload.get("timestamp") or payload.get("TimeCreated"),
        "message": message,
        "asset_id": computer,
        "raw": payload,
        "labels": {
            "provider": provider_name,
            "event_id": event_id,
        },
    }
