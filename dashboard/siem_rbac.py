from __future__ import annotations

from functools import wraps
from typing import Iterable, Optional

from django.conf import settings
from django.http import JsonResponse

from .models import SiemUserRole


def get_siem_role(user) -> str:
    if user is not None and getattr(user, "is_authenticated", False):
        assignment = getattr(user, "siem_role", None)
        if assignment:
            return assignment.role
        assignment = SiemUserRole.objects.filter(user=user).first()
        if assignment:
            return assignment.role
    return getattr(settings, "SIEM_DEFAULT_ROLE", SiemUserRole.Role.VIEWER)


def role_in(role: str, allowed: Iterable[str]) -> bool:
    return role in set(allowed)


def require_siem_role(
    allowed_roles: Iterable[str],
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            role = get_siem_role(request.user)
            if not role_in(role, allowed_roles):
                from .siem_audit import record_siem_audit

                record_siem_audit(
                    request,
                    action=action or view_func.__name__,
                    resource_type=resource_type or "",
                    resource_id=str(kwargs.get("hunt_id") or kwargs.get("case_id") or ""),
                    status="denied",
                    metadata={"role": role},
                )
                return JsonResponse({"error": "Forbidden"}, status=403)
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator
