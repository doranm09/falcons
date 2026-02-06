import pytest
from django.urls import reverse

from dashboard.models import ResearchProfile


@pytest.mark.django_db
def test_research_profile_activate(siem_analyst_client):
    p1 = ResearchProfile.objects.create(
        name="Profile One",
        version="1.0",
        pipeline_version="1.0",
        ruleset_version="1.0",
        retention_days=30,
        max_batch=50,
        active=False,
    )
    p2 = ResearchProfile.objects.create(
        name="Profile Two",
        version="1.1",
        pipeline_version="1.1",
        ruleset_version="1.1",
        retention_days=60,
        max_batch=10,
        active=False,
    )

    page = siem_analyst_client.get(reverse("dashboard:siem_research_profiles_page"))
    assert page.status_code == 200

    activate_resp = siem_analyst_client.post(
        reverse("dashboard:siem_research_profile_activate", args=[p2.id])
    )
    assert activate_resp.status_code == 302

    p1.refresh_from_db()
    p2.refresh_from_db()
    assert p2.active is True
    assert p1.active is False
