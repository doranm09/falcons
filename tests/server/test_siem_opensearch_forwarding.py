import json

import pytest
import responses
from django.test import override_settings
from django.urls import reverse


@pytest.mark.django_db
@responses.activate
@override_settings(
    OPENSEARCH_ENABLED=True,
    OPENSEARCH_URL="http://opensearch:9200",
    OPENSEARCH_INDEX_PREFIX="siem-events",
    OPENSEARCH_VERIFY_TLS=False,
)
def test_siem_ingest_forwards_to_opensearch(client):
    responses.add(
        responses.POST,
        "http://opensearch:9200/_bulk",
        json={"errors": False, "items": []},
        status=200,
    )

    payload = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "timestamp": "2026-02-06T12:10:00Z",
        "message": "alert",
    }
    resp = client.post(
        reverse("dashboard:siem_event_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["opensearch"]["indexed"] == 1
    assert len(responses.calls) == 1
