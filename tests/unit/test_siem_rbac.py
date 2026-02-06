import pytest

from dashboard.models import SiemUserRole
from dashboard.siem_rbac import get_siem_role


@pytest.mark.django_db
def test_get_siem_role_defaults_to_viewer(settings, user):
    settings.SIEM_DEFAULT_ROLE = "viewer"
    assert get_siem_role(user) == "viewer"


@pytest.mark.django_db
def test_get_siem_role_assignment(user):
    SiemUserRole.objects.create(user=user, role=SiemUserRole.Role.ANALYST)
    assert get_siem_role(user) == "analyst"
