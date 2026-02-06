# SIEM RBAC + Audit Logging

This feature adds role-based access control (RBAC) for SIEM write actions and an audit log.

## Roles
Available roles:
- `admin`: full access to SIEM write actions and audit log.
- `analyst`: can create/update hunts and cases, toggle rules, and ingest threat intel.
- `viewer`: read-only access to SIEM pages.

Default role (if no assignment exists): `viewer`. You can override with:
```
SIEM_DEFAULT_ROLE=viewer
```

## Assigning Roles
Create a role assignment using Django admin or shell:
```
from django.contrib.auth import get_user_model
from dashboard.models import SiemUserRole

User = get_user_model()
user = User.objects.get(username="alice")
SiemUserRole.objects.update_or_create(user=user, defaults={"role": "admin"})
```

## Audit Log
- UI: `GET /dashboard/siem/audit/`
- JSON: `GET /dashboard/siem/audit/?format=json`

Filters:
- `action`: exact action name (e.g., `siem_case_create`)
- `status`: `success`, `denied`, or `error`

## Notes
- SIEM ingest endpoints continue to rely on `SIEM_INGEST_TOKEN` for service authentication.
- Audit entries capture action, role, resource identifiers, and basic request metadata.
