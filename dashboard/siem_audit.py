from __future__ import annotations

from typing import Any, Dict, Optional

from .models import SiemAuditLog
from .siem_rbac import get_siem_role


def record_siem_audit(
    request,
    action: str,
    resource_type: str = "",
    resource_id: str = "",
    status: str = "success",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    user = getattr(request, "user", None)
    role = get_siem_role(user)
    ip_address = request.META.get("REMOTE_ADDR") if request else None
    user_agent = request.META.get("HTTP_USER_AGENT", "") if request else ""
    SiemAuditLog.objects.create(
        actor=user if getattr(user, "is_authenticated", False) else None,
        role=role,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id or ""),
        status=status,
        ip_address=ip_address,
        user_agent=user_agent[:255],
        metadata=metadata or {},
    )
