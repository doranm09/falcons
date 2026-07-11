import json

import pytest
from django.test import override_settings
from django.urls import reverse

from dashboard.models import SiemEvent


@pytest.mark.django_db
@override_settings(SIEM_INGEST_TOKEN="test-token")
def test_siem_ingest_requires_token(client):
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 401
    assert SiemEvent.objects.count() == 0


@pytest.mark.django_db
@override_settings(SIEM_INGEST_TOKEN="test-token")
def test_siem_ingest_accepts_token(client):
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
        "message": "connection",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
        HTTP_X_SIEM_TOKEN="test-token",
    )
    assert resp.status_code == 201
    assert resp.json()["ingested"] == 1
    assert SiemEvent.objects.count() == 1


@pytest.mark.django_db
@override_settings(SIEM_INGEST_TOKEN="", SIEM_SENSOR_TOKEN="", SIEM_INGEST_TOKEN_REQUIRED=True)
def test_siem_ingest_fails_closed_when_required_and_no_token_is_configured(client):
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 401
    assert SiemEvent.objects.count() == 0


@pytest.mark.django_db
@override_settings(SIEM_INGEST_TOKEN="", SIEM_SENSOR_TOKEN="sensor-token", SIEM_INGEST_TOKEN_REQUIRED=True)
def test_siem_ingest_accepts_sensor_token_compatibility_alias(client):
    payload = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "timestamp": "2026-02-06T12:00:00Z",
        "message": "connection",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
        HTTP_X_SIEM_TOKEN="sensor-token",
    )
    assert resp.status_code == 201
    assert resp.json()["ingested"] == 1
    assert SiemEvent.objects.count() == 1
