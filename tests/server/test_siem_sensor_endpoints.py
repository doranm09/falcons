import json

import pytest
from django.urls import reverse

from dashboard.models import SiemEvent, SiemSensorStatus


@pytest.mark.django_db
def test_suricata_sensor_ingest_updates_status(siem_client):
    payload = {
        "sensor": {
            "sensor_id": "suricata-span",
            "hostname": "suricata-span",
            "interface": "eth1",
            "testbed": "iaea_rcs_demo",
        },
        "events": [
            {
                "timestamp": "2026-04-16T12:00:00Z",
                "event_type": "alert",
                "src_ip": "10.1.1.14",
                "src_port": 43000,
                "dest_ip": "10.1.1.10",
                "dest_port": 502,
                "alert": {"signature": "ET TEST Example", "severity": 2},
            }
        ],
    }
    resp = siem_client.post(
        reverse("dashboard:siem_suricata_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert SiemEvent.objects.count() == 1
    sensor = SiemSensorStatus.objects.get(sensor_id="suricata-span")
    assert sensor.sensor_type == "suricata"
    assert sensor.event_count == 1
    assert sensor.interface_names == ["eth1"]
    event = SiemEvent.objects.get()
    assert event.source_port == 43000
    assert event.destination_port == 502


@pytest.mark.django_db
def test_zeek_sensor_ingest_and_health_endpoint(siem_client):
    payload = {
        "sensor": {
            "sensor_id": "zeek-span",
            "hostname": "zeek-span",
            "interfaces": ["eth1", "eth2"],
            "testbed": "iaea_rcs_demo",
        },
        "logs": [
            {
                "ts": 1760088000,
                "uid": "C1",
                "log_type": "conn",
                "id_orig_h": "10.1.1.14",
                "id_orig_p": 43100,
                "id_resp_h": "10.1.1.10",
                "id_resp_p": 4840,
            }
        ],
    }
    ingest_resp = siem_client.post(
        reverse("dashboard:siem_zeek_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    health_resp = siem_client.get(reverse("dashboard:siem_sensor_health"))
    assert health_resp.status_code == 200
    body = health_resp.json()
    assert body["count"] == 1
    assert body["sensors"][0]["sensor_id"] == "zeek-span"
    assert body["sensors"][0]["status"] == "online"

    event = SiemEvent.objects.get()
    assert event.event_module == "zeek"
    assert event.event_dataset == "zeek.conn"
    assert event.observer_name == "zeek-span"
    assert str(event.source_ip) == "10.1.1.14"
    assert event.source_port == 43100
    assert str(event.destination_ip) == "10.1.1.10"
    assert event.destination_port == 4840


@pytest.mark.django_db
def test_zeek_sensor_ingest_accepts_dotted_zeek_keys(siem_client):
    payload = {
        "sensor": {
            "sensor_id": "zeek-span",
            "hostname": "zeek-span",
            "interfaces": ["eth1", "eth2"],
            "testbed": "iaea_rcs_demo",
        },
        "logs": [
            {
                "ts": 1760088000,
                "uid": "C2",
                "log_type": "conn",
                "id.orig_h": "10.1.1.14",
                "id.orig_p": 43200,
                "id.resp_h": "10.1.1.10",
                "id.resp_p": 502,
            }
        ],
    }
    ingest_resp = siem_client.post(
        reverse("dashboard:siem_zeek_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201

    event = SiemEvent.objects.get()
    assert event.event_module == "zeek"
    assert event.event_dataset == "zeek.conn"
    assert str(event.asset_ip) == "10.1.1.14"
    assert str(event.source_ip) == "10.1.1.14"
    assert event.source_port == 43200
    assert str(event.destination_ip) == "10.1.1.10"
    assert event.destination_port == 502


@pytest.mark.django_db
def test_zeek_sensor_ingest_keeps_link_local_ipv6_noise_for_frontend_policy(siem_client):
    payload = {
        "sensor": {
            "sensor_id": "zeek-span",
            "hostname": "zeek-span",
            "interfaces": ["eth1", "eth2"],
            "testbed": "iaea_rcs_demo",
        },
        "logs": [
            {
                "ts": 1760088000,
                "uid": "C-noise",
                "log_type": "conn",
                "id_orig_h": "fe80::2890:5ff:fe2b:8ae2",
                "id_resp_h": "ff02::fb",
            }
        ],
    }
    ingest_resp = siem_client.post(
        reverse("dashboard:siem_zeek_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest_resp.status_code == 201
    assert ingest_resp.json()["ingested"] == 1
    event = SiemEvent.objects.get()
    assert str(event.source_ip) == "fe80::2890:5ff:fe2b:8ae2"
    assert str(event.destination_ip) == "ff02::fb"


@pytest.mark.django_db
def test_suricata_sensor_ingest_keeps_link_local_ipv6_noise_for_frontend_policy(siem_client):
    payload = {
        "sensor": {
            "sensor_id": "suricata-span",
            "hostname": "suricata-span",
            "interface": "eth1",
            "testbed": "iaea_rcs_demo",
        },
        "events": [
            {
                "timestamp": "2026-04-16T12:00:00Z",
                "event_type": "flow",
                "src_ip": "fe80::2890:5ff:fe2b:8ae2",
                "dest_ip": "ff02::fb",
            }
        ],
    }
    resp = siem_client.post(
        reverse("dashboard:siem_suricata_ingest"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert resp.json()["ingested"] == 1
    event = SiemEvent.objects.get()
    assert str(event.source_ip) == "fe80::2890:5ff:fe2b:8ae2"
    assert str(event.destination_ip) == "ff02::fb"
