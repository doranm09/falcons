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
def test_pipeline_ingest_forwards_to_opensearch(siem_client):
    responses.add(
        responses.POST,
        "http://opensearch:9200/_bulk",
        json={"errors": False, "items": []},
        status=200,
    )

    payload = {
        "alert": {"signature": "ET MALWARE Example", "severity": 2},
        "src_ip": "10.1.1.14",
        "timestamp": "2026-02-06T12:12:00Z",
    }
    resp = siem_client.post(
        reverse("dashboard:siem_pipeline_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["opensearch"]["indexed"] == 1
    assert len(responses.calls) == 1
