from dashboard.siem_suricata import transform_suricata_events
from dashboard.siem_zeek import transform_zeek_events


def test_transform_suricata_events_with_sensor_metadata():
    sensor, events = transform_suricata_events(
        {
            "sensor": {
                "sensor_id": "suricata-l1",
                "hostname": "suricata-l1",
                "interface": "eth1",
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
    )
    assert sensor["sensor_id"] == "suricata-l1"
    assert events[0]["event_type"] == "suricata.alert"
    assert events[0]["event_module"] == "suricata"
    assert events[0]["event_dataset"] == "suricata.alert"
    assert events[0]["source"] == "suricata"
    assert events[0]["message"] == "ET TEST Example"
    assert events[0]["source_ip"] == "10.1.1.14"
    assert events[0]["source_port"] == 43000
    assert events[0]["destination_ip"] == "10.1.1.10"
    assert events[0]["destination_port"] == 502
    assert events[0]["raw"]["event"]["module"] == "suricata"
    assert events[0]["raw"]["event"]["dataset"] == "suricata.alert"
    assert events[0]["raw"]["observer"]["ingress"]["interface"]["name"] == "eth1"


def test_transform_suricata_events_uses_first_sensor_interface_from_list():
    sensor, events = transform_suricata_events(
        {
            "sensor": {
                "sensor_id": "suricata-l1",
                "hostname": "suricata-l1",
                "interfaces": ["eth9", "eth10"],
            },
            "events": [
                {
                    "timestamp": "2026-04-16T12:00:00Z",
                    "event_type": "flow",
                    "src_ip": "10.1.1.14",
                    "dest_ip": "10.1.1.10",
                }
            ],
        }
    )

    assert sensor["sensor_id"] == "suricata-l1"
    assert events[0]["raw"]["observer"]["ingress"]["interface"]["name"] == "eth9"
    assert events[0]["raw"]["observer"]["interfaces"] == ["eth9", "eth10"]


def test_transform_zeek_events_maps_log_type():
    sensor, events = transform_zeek_events(
        {
            "sensor": {"sensor_id": "zeek-l1", "hostname": "zeek-l1", "interfaces": ["eth1", "eth2"]},
            "logs": [
                {
                    "ts": 1760088000,
                    "uid": "C1",
                    "log_type": "conn",
                    "id_orig_h": "10.1.1.14",
                    "id_resp_h": "10.1.1.10",
                }
            ],
        }
    )
    assert sensor["sensor_id"] == "zeek-l1"
    assert events[0]["event_type"] == "zeek.conn"
    assert events[0]["source"] == "zeek"
    assert events[0]["raw"]["event"]["dataset"] == "zeek.conn"
