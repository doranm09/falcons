import json

import pytest
from django.urls import reverse

from dashboard.models import ResearchProfile


@pytest.mark.django_db
def test_research_profile_caps_ingest_batch(siem_analyst_client):
    ResearchProfile.objects.all().update(active=False)
    profile = ResearchProfile.objects.create(
        name="Research Cap",
        version="1.0",
        pipeline_version="1.0",
        ruleset_version="1.0",
        retention_days=30,
        max_batch=1,
        active=True,
    )

    payload = [
        {
            "event_type": "zeek.conn",
            "source": "zeek",
            "timestamp": "2026-02-06T16:00:00Z",
        },
        {
            "event_type": "zeek.conn",
            "source": "zeek",
            "timestamp": "2026-02-06T16:01:00Z",
        },
    ]

    resp = siem_analyst_client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 413
    assert profile.active is True
