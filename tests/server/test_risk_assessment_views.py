import json
from unittest.mock import Mock
from pathlib import Path

import pytest
from django.urls import reverse
from django.utils import timezone

from dashboard.models import Node, NodeInterface, RiskNodeMapping, ScanRun, ScanVulnerability, Vulnerability
from dashboard.risk_assessment import build_cyber_data_for_risk_nodes, summarize_risk_results


class MockResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("error")


@pytest.mark.django_db
def test_risk_assessment_page_access(user_client):
    response = user_client.get(reverse("dashboard:risk_assessment"))
    assert response.status_code == 200
    assert b"Current workspace for the active" in response.content
    assert b"risk-network-graph" in response.content
    assert b"/risk-assessment/network/compute/" in response.content
    assert b"PLC-Main" in response.content
    assert b"Heat-Ctrl" not in response.content
    assert b"Latest Conversion" not in response.content


@pytest.mark.django_db
def test_risk_assessment_console_page_access(user_client):
    response = user_client.get(reverse("dashboard:risk_assessment_console"))
    assert response.status_code == 200
    assert b"Risk Assessment Console" in response.content
    assert b"/upload_model" in response.content
    assert b"/post_detection" in response.content
    assert b"/get_probability" in response.content
    assert b"/risk-assessment/pid/upload/" not in response.content
    assert b"PLC-Main" in response.content
    assert b"Firewall-Main-Cell" not in response.content


@pytest.mark.django_db
def test_risk_assessment_status_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse({"status": "ok"})))

    response = user_client.get(reverse("dashboard:risk_assessment_status"))
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.django_db
def test_risk_assessment_service_info_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse({"service": "risk"})))

    response = user_client.get(reverse("dashboard:risk_assessment_service_info"))
    assert response.status_code == 200
    assert response.json()["service"] == "risk"


@pytest.mark.django_db
def test_risk_assessment_service_nodes_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    payload = {
        "nodes": {
            "PLC-1": {"states": ["Nominal", "Compromised"], "type": "controller", "category": "digital"}
        }
    }
    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse(payload)))

    response = user_client.get(reverse("dashboard:risk_assessment_service_nodes"))
    assert response.status_code == 200
    assert response.json() == payload


@pytest.mark.django_db
def test_risk_assessment_model_upload_from_local_model(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    model_payload = {
        "version": "1.0",
        "digital": {"PLC-1": {"type": "controller", "source": {}, "target": {}}},
        "physical": {},
        "flow": {},
        "function": {},
    }
    monkeypatch.setattr(
        dashboard_views,
        "_risk_local_model_payload_for_source",
        Mock(return_value=(model_payload, Path("/tmp/test_sim_system.json"))),
    )
    mock_post = Mock(return_value=MockResponse({"status": "ok"}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    response = user_client.post(
        reverse("dashboard:risk_assessment_model_upload"),
        data=json.dumps({"source": "auto"}),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert mock_post.call_args.args[0].endswith("/upload_model")


@pytest.mark.django_db
def test_risk_assessment_model_upload_from_raw_model_payload(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok"}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    response = user_client.post(
        reverse("dashboard:risk_assessment_service_upload"),
        data=json.dumps(
            {
                "version": "1.0",
                "digital": {"PLC-1": {"type": "controller", "source": {}, "target": {}}},
                "physical": {},
                "flow": {},
                "function": {},
            }
        ),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert mock_post.call_args.args[0].endswith("/upload_model")
    assert mock_post.call_args.kwargs["json"]["digital"]["PLC-1"]["type"] == "PLC"


@pytest.mark.django_db
def test_risk_assessment_nodes_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    payload = {
        "nodes": {
            "PLC-1": {"states": ["Nominal", "Compromised"], "type": "controller", "category": "digital"}
        }
    }
    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse(payload)))

    response = user_client.get(reverse("dashboard:risk_assessment_nodes"))
    assert response.status_code == 200
    assert response.json()["nodes"] == [
        {
            "id": "PLC-1",
            "name": "PLC-1",
            "states": ["Nominal", "Compromised"],
            "type": "controller",
            "category": "digital",
        }
    ]


@pytest.mark.django_db
def test_risk_assessment_service_unload_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok"}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    response = user_client.post(
        reverse("dashboard:risk_assessment_service_unload"),
        data="{}",
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert mock_post.call_args.args[0].endswith("/unload_model")


@pytest.mark.django_db
def test_risk_assessment_service_vulnerability_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok", "updated_nodes": ["PLC-1"]}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    payload = {"nodes": {"PLC-1": {"CVE-2024-0001": {"epss": 0.7}}}}
    response = user_client.post(
        reverse("dashboard:risk_assessment_service_vulnerability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["updated_nodes"] == ["PLC-1"]
    assert mock_post.call_args.args[0].endswith("/post_vulnerability")
    assert mock_post.call_args.kwargs["json"] == payload


@pytest.mark.django_db
def test_risk_assessment_service_detection_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok"}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    payload = {"nodes": {"PLC-1": {"score": 0.8}}}
    response = user_client.post(
        reverse("dashboard:risk_assessment_service_detection"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert mock_post.call_args.args[0].endswith("/post_detection")
    assert mock_post.call_args.kwargs["json"] == payload


@pytest.mark.django_db
def test_risk_assessment_service_probability_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    expected_result = {"results": {"PLC-1Nt": {"Nominal": 0.9, "Compromised": 0.1}}}
    mock_get = Mock(return_value=MockResponse(expected_result))
    monkeypatch.setattr(dashboard_views.requests, "get", mock_get)

    response = user_client.get(
        reverse("dashboard:risk_assessment_service_probability"),
        {"T": 2, "nodes": "PLC-1"},
    )

    assert response.status_code == 200
    assert response.json() == expected_result
    assert mock_get.call_args.args[0].endswith("/get_probability")
    assert mock_get.call_args.kwargs["params"]["nodes"] == "PLC-1"
    assert mock_get.call_args.kwargs["params"]["T"] == 2


@pytest.mark.django_db
def test_risk_assessment_probability_proxy(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    expected_result = {"results": {"PLC-1Nt": {"Nominal": 0.9, "Compromised": 0.1}}}
    mock_get = Mock(return_value=MockResponse(expected_result))
    monkeypatch.setattr(dashboard_views.requests, "get", mock_get)

    payload = {"T": 2, "nodes": ["PLC-1"]}
    response = user_client.post(
        reverse("dashboard:risk_assessment_probability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["results"]["PLC-1"]["normal"] == 0.9
    assert response.json()["results"]["PLC-1"]["compromised"] == 0.1
    assert mock_get.call_args.args[0].endswith("/get_probability")
    assert mock_get.call_args.kwargs["params"]["nodes"] == "PLC-1"


@pytest.mark.django_db
def test_risk_assessment_probability_proxy_current_mutations(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok"}))
    mock_get = Mock(return_value=MockResponse({"results": {"PLC-1Nt": {"Compromised": 0.42, "Nominal": 0.58}}}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)
    monkeypatch.setattr(dashboard_views.requests, "get", mock_get)

    payload = {
        "T": 3,
        "nodes": ["PLC-1"],
        "vulnerabilities": {
            "PLC-1": {
                "CVE-2024-0001": {"epss": 0.7},
            }
        },
    }
    response = user_client.post(
        reverse("dashboard:risk_assessment_probability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["results"]["PLC-1"]["compromised"] == 0.42
    assert mock_post.call_args.args[0].endswith("/post_vulnerability")
    assert mock_post.call_args.kwargs["json"]["nodes"]["PLC-1"]["CVE-2024-0001"]["epss"] == 0.7
    assert mock_get.call_args.args[0].endswith("/get_probability")


@pytest.mark.django_db
def test_risk_assessment_probability_proxy_cyber_data(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    mock_post = Mock(return_value=MockResponse({"status": "ok", "updated_nodes": ["PLC-1"]}))
    mock_get = Mock(return_value=MockResponse({"results": {"PLC-1Nt": {"Compromised": 0.42, "Nominal": 0.58}}}))
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)
    monkeypatch.setattr(dashboard_views.requests, "get", mock_get)

    payload = {
        "T": 3,
        "cyber_data": {
            "scanned_nodes": [
                {
                    "id": "PLC-1",
                    "type": "network_node",
                    "vulnerability": [{"id": "CVE-2024-0001", "epss": 0.7}],
                }
            ]
        },
    }
    response = user_client.post(
        reverse("dashboard:risk_assessment_probability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["results"]["PLC-1"]["compromised"] == 0.42
    assert mock_post.call_args.args[0].endswith("/post_vulnerability")
    assert mock_post.call_args.kwargs["json"]["nodes"]["PLC-1"]["CVE-2024-0001"]["epss"] == 0.7
    assert mock_get.call_args.args[0].endswith("/get_probability")
    assert mock_get.call_args.kwargs["params"]["nodes"] == "PLC-1"


@pytest.mark.django_db
def test_risk_assessment_probability_rejects_evidence(user_client):
    payload = {"T": 1, "evidence": {"PLC-1N0": "Compromised"}}
    response = user_client.post(
        reverse("dashboard:risk_assessment_probability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert "does not support ad hoc evidence" in response.json()["error"]


@pytest.mark.django_db
def test_risk_assessment_probability_rejects_detections(user_client):
    payload = {"T": 1, "detections": {"PLC-1": {"score": 0.8}}}
    response = user_client.post(
        reverse("dashboard:risk_assessment_probability"),
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert "does not return posterior probabilities" in response.json()["error"]


@pytest.mark.django_db
def test_build_cyber_data_for_risk_nodes_dedupes_and_maps():
    scan_run = ScanRun.objects.create(cidr="10.0.0.0/24")
    node_a = Node.objects.create(name="PLC-1", ip_address="10.0.0.10")
    node_b = Node.objects.create(name="Workstation-1", ip_address="10.0.0.20")

    RiskNodeMapping.objects.create(risk_node_id="PLC-OVERRIDE", node=node_a)
    RiskNodeMapping.objects.create(risk_node_id="WS-1", ip_address="10.0.0.20")

    vuln = Vulnerability.objects.create(
        cve_id="CVE-2024-0001",
        description="Test vuln",
        severity="High",
        score=7.5,
        published=timezone.now(),
        last_modified=timezone.now(),
    )
    vuln.nodes.add(node_a)

    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.10",
        cve_id="CVE-2024-0001",
        name="Duplicate vuln",
        severity="Critical",
        cvss_score=9.0,
    )
    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.20",
        cve_id="CVE-2024-0002",
        name="Secondary vuln",
        severity="Medium",
        cvss_score=5.0,
    )

    cyber_data, mapped = build_cyber_data_for_risk_nodes(["PLC-OVERRIDE", "WS-1"])

    assert len(mapped) == 2
    mapped_by_name = {entry["name"]: entry for entry in mapped}
    assert mapped_by_name["PLC-1"]["risk_node_id"] == "PLC-OVERRIDE"
    assert mapped_by_name["Workstation-1"]["risk_node_id"] == "WS-1"

    scanned_nodes = {entry["id"]: entry for entry in cyber_data["scanned_nodes"]}
    assert "PLC-OVERRIDE" in scanned_nodes
    assert "WS-1" in scanned_nodes

    plc_vulns = scanned_nodes["PLC-OVERRIDE"]["vulnerability"]
    assert len(plc_vulns) == 1
    assert plc_vulns[0]["id"] == "CVE-2024-0001"
    assert plc_vulns[0]["epss"] > 0.8
    assert plc_vulns[0]["sources"] == ["node", "scan"]
    assert mapped_by_name["PLC-1"]["vulnerability_count"] == 1
    assert mapped_by_name["PLC-1"]["vulnerabilities"][0]["id"] == "CVE-2024-0001"


@pytest.mark.django_db
def test_build_cyber_data_for_risk_nodes_filters_scan_vulnerabilities_by_scan_run():
    scan_a = ScanRun.objects.create(cidr="10.0.0.0/24")
    scan_b = ScanRun.objects.create(cidr="10.0.1.0/24")
    node = Node.objects.create(name="PLC-2", ip_address="10.0.0.30", scan_run=scan_a)

    RiskNodeMapping.objects.create(risk_node_id="PLC-2", node=node)

    ScanVulnerability.objects.create(
        scan_run=scan_a,
        host_ip="10.0.0.30",
        cve_id="CVE-2024-1000",
        name="Scan A vuln",
        severity="High",
        cvss_score=7.2,
    )
    ScanVulnerability.objects.create(
        scan_run=scan_b,
        host_ip="10.0.0.30",
        cve_id="CVE-2024-2000",
        name="Scan B vuln",
        severity="Critical",
        cvss_score=9.4,
    )

    cyber_data, mapped = build_cyber_data_for_risk_nodes(["PLC-2"], scan_run_id=scan_a.id)

    scanned_nodes = {entry["id"]: entry for entry in cyber_data["scanned_nodes"]}
    assert scanned_nodes["PLC-2"]["vulnerability"] == [
        {"id": "CVE-2024-1000", "epss": pytest.approx(0.72), "sources": ["scan"]}
    ]
    assert mapped[0]["vulnerability_count"] == 1
    assert mapped[0]["vulnerabilities"][0]["id"] == "CVE-2024-1000"


def test_summarize_risk_results_assigns_levels():
    mapped_nodes = [
        {"node_id": 1, "name": "PLC-1", "ip_address": "10.0.0.10", "risk_node_id": "PLC-1"},
        {"node_id": 2, "name": "Workstation-1", "ip_address": "10.0.0.20", "risk_node_id": None},
    ]
    results = {"PLC-1": {"compromised": 0.72}}

    summary = summarize_risk_results(mapped_nodes, results)
    plc = next(node for node in summary if node["name"] == "PLC-1")
    workstation = next(node for node in summary if node["name"] == "Workstation-1")

    assert plc["risk_score"] == 0.72
    assert plc["risk_level"] == "high"
    assert workstation["risk_score"] is None
    assert workstation["risk_level"] == "unknown"


@pytest.mark.django_db
def test_risk_assessment_network_compute_proxy(user_client, monkeypatch):
    scan_run = ScanRun.objects.create(cidr="10.0.0.0/24")
    Node.objects.create(name="PLC-1", ip_address="10.0.0.10")
    Node.objects.create(name="Workstation-1", ip_address="10.0.0.20")

    ScanVulnerability.objects.create(
        scan_run=scan_run,
        host_ip="10.0.0.10",
        cve_id="CVE-2024-0003",
        name="Endpoint vuln",
        severity="High",
        cvss_score=7.0,
    )

    from dashboard import views as dashboard_views

    nodes_payload = {
        "nodes": {
            "PLC-1": {"states": ["Nominal", "Compromised"], "type": "controller", "category": "digital"},
            "10.0.0.20": {"states": ["Nominal", "Faulty"], "type": "host", "category": "digital"},
        }
    }
    mock_get = Mock(
        side_effect=[
            MockResponse(nodes_payload),
            MockResponse(
                {
                    "results": {
                        "PLC-1Nt": {"Compromised": 0.83, "Nominal": 0.17},
                        "10.0.0.20Nt": {"Faulty": 0.22, "Nominal": 0.78},
                    }
                }
            ),
        ]
    )
    mock_post = Mock(return_value=MockResponse({"status": "ok", "updated_nodes": ["PLC-1"]}))
    monkeypatch.setattr(dashboard_views.requests, "get", mock_get)
    monkeypatch.setattr(dashboard_views.requests, "post", mock_post)

    response = user_client.get(reverse("dashboard:risk_assessment_network_compute"))
    assert response.status_code == 200

    body = response.json()
    assert body["risk_nodes_count"] == 2
    mapped = {entry["risk_node_id"]: entry for entry in body["mapped_nodes"]}
    assert mapped["PLC-1"]["risk_level"] == "high"
    assert mapped["10.0.0.20"]["risk_level"] == "low"
    assert mapped["PLC-1"]["vulnerability_count"] == 1
    assert mapped["PLC-1"]["vulnerabilities"][0]["id"] == "CVE-2024-0003"

    posted_payload = mock_post.call_args.kwargs["json"]
    assert mock_post.call_args.args[0].endswith("/post_vulnerability")
    assert "PLC-1" in posted_payload["nodes"]


def test_risk_local_model_payload_auto_falls_back_to_latest_prefixed_file(tmp_path, settings):
    from dashboard import views as dashboard_views

    output_dir = tmp_path / "pid_out"
    output_dir.mkdir()
    (output_dir / "20240210_sim_system.json").write_text(
        json.dumps({"version": "1.0", "digital": {}, "physical": {}, "flow": {}, "function": {}}),
        encoding="utf-8",
    )
    settings.PID_DRAWIO_OUTPUT_DIR = str(output_dir)
    settings.RISK_ASSESSMENT_SIM_SYSTEM_PATH = ""

    payload, model_path = dashboard_views._risk_local_model_payload_for_source("auto")

    assert payload == {"version": "1.0", "digital": {}, "physical": {}, "flow": {}, "function": {}}
    assert model_path == output_dir / "20240210_sim_system.json"


def test_risk_local_model_payload_auto_uses_active_fallback_output_dir(tmp_path, settings, monkeypatch):
    from dashboard import views as dashboard_views

    primary_output_dir = tmp_path / "primary"
    fallback_output_dir = tmp_path / "fallback"
    primary_output_dir.mkdir()
    fallback_output_dir.mkdir()
    (fallback_output_dir / "sim_system.json").write_text(
        json.dumps({"version": "1.0", "digital": {}, "physical": {}, "flow": {}, "function": {}}),
        encoding="utf-8",
    )

    settings.PID_DRAWIO_OUTPUT_DIR = str(primary_output_dir)
    settings.RISK_ASSESSMENT_SIM_SYSTEM_PATH = ""
    monkeypatch.setattr(
        dashboard_views,
        "_pid_drawio_output_dir_candidates",
        lambda: [primary_output_dir, fallback_output_dir],
    )

    payload, model_path = dashboard_views._risk_local_model_payload_for_source("auto")

    assert payload == {"version": "1.0", "digital": {}, "physical": {}, "flow": {}, "function": {}}
    assert model_path == fallback_output_dir / "sim_system.json"


def test_resolve_sim_system_path_auto_falls_back_to_prefixed_latest_file(tmp_path):
    from dashboard.pid_system import resolve_sim_system_path

    output_dir = tmp_path / "pid_out"
    output_dir.mkdir()
    (output_dir / "20240210_sim_system.json").write_text(
        json.dumps({"version": "1.0", "digital": {}, "physical": {}, "flow": {}, "function": {}}),
        encoding="utf-8",
    )

    resolved_path, resolved_source = resolve_sim_system_path("auto", output_dir, None)

    assert resolved_path == output_dir / "20240210_sim_system.json"
    assert resolved_source == "latest"


@pytest.mark.django_db
def test_risk_assessment_mappings_get(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    Node.objects.create(
        name="PLC-1",
        ip_address="10.1.0.10",
        os_info="Linux",
        platform_info="x86_64",
        cpu_count=4,
        memory_total=8 * 1024 * 1024 * 1024,
        active_ports=[22, 443],
        mac_addresses=["aa:bb:cc:dd:ee:ff"],
    )
    Node.objects.create(name="Workstation-1", ip_address="10.1.0.20")

    RiskNodeMapping.objects.create(risk_node_id="PLC-Main", ip_address="10.1.0.10", label="PLC Main")

    nodes_payload = {
        "nodes": {
            "PLC-Main": {"states": ["Nominal"], "type": "controller", "category": "digital"},
            "Heat-Ctrl": {"states": ["Nominal"], "type": "controller", "category": "digital"},
        }
    }
    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse(nodes_payload)))

    response = user_client.get(reverse("dashboard:risk_assessment_mappings"))
    assert response.status_code == 200
    body = response.json()
    assert "risk_nodes" in body
    assert "nodes" in body
    assert "mappings" in body
    assert "PLC-Main" in body["risk_nodes"]
    assert any(mapping["risk_node_id"] == "PLC-Main" for mapping in body["mappings"])
    node_payload = next(node for node in body["nodes"] if node["name"] == "PLC-1")
    assert node_payload["os_info"] == "Linux"
    assert node_payload["platform_info"] == "x86_64"
    assert node_payload["cpu_count"] == 4
    assert node_payload["memory_total"] == 8 * 1024 * 1024 * 1024
    assert node_payload["active_ports"] == [22, 443]
    assert node_payload["mac_addresses"] == ["aa:bb:cc:dd:ee:ff"]


@pytest.mark.django_db
def test_risk_assessment_mappings_get_auto_suggests_hybrid_assets_and_prefers_in_band_ip(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    node = Node.objects.create(name="plc-main-agent", ip_address="172.31.250.14")
    NodeInterface.objects.create(node=node, name="eth0", ip="10.1.1.14", mac="aa:bb:cc:dd:ee:14")
    NodeInterface.objects.create(node=node, name="eth1", ip="10.1.2.14", mac="aa:bb:cc:dd:ee:15")

    nodes_payload = {
        "nodes": {
            "PLC-Main": {"states": ["Nominal"], "type": "controller", "category": "digital"},
        }
    }
    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse(nodes_payload)))

    response = user_client.get(reverse("dashboard:risk_assessment_mappings"))
    assert response.status_code == 200

    body = response.json()
    node_payload = next(item for item in body["nodes"] if item["id"] == node.id)
    assert node_payload["ip_address"] == "10.1.1.14"

    suggestion = next(mapping for mapping in body["mappings"] if mapping["risk_node_id"] == "PLC-Main")
    assert suggestion["node_id"] == node.id
    assert suggestion["node_name"] == "plc-main-agent"
    assert suggestion["ip_address"] == "10.1.1.14"
    assert suggestion["notes"] == "Auto-suggested from validated hybrid topology"
    assert suggestion["reason"] == "matched validated hybrid IP"
    assert suggestion["updated_at"] is None


@pytest.mark.django_db
def test_risk_assessment_mappings_post(user_client):
    node = Node.objects.create(name="PLC-2", ip_address="10.2.0.10")
    payload = {
        "risk_node_id": "PLC-2",
        "node_id": node.id,
        "ip_address": "",
        "label": "PLC Two",
        "notes": "Mapped in UI",
        "active": True,
    }

    response = user_client.post(
        reverse("dashboard:risk_assessment_mappings"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200

    mapping = RiskNodeMapping.objects.get(risk_node_id="PLC-2")
    assert mapping.node_id == node.id
    assert mapping.label == "PLC Two"


@pytest.mark.django_db
def test_risk_assessment_mappings_post_bulk(user_client):
    node = Node.objects.create(name="PLC-3", ip_address="10.3.0.10")
    payload = {
        "mappings": [
            {"risk_node_id": "PLC-3", "node_id": node.id, "active": True},
            {"risk_node_id": "PLC-4", "ip_address": "10.3.0.20", "active": False},
        ]
    }

    response = user_client.post(
        reverse("dashboard:risk_assessment_mappings"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert RiskNodeMapping.objects.filter(risk_node_id="PLC-3").exists()
    mapping = RiskNodeMapping.objects.get(risk_node_id="PLC-4")
    assert mapping.ip_address == "10.3.0.20"
    assert mapping.active is False


@pytest.mark.django_db
def test_risk_assessment_testbed_generate(user_client, monkeypatch):
    from dashboard import views as dashboard_views

    payload = {
        "nodes": {
            "PLC-Main": {"states": ["Nominal"], "type": "controller", "category": "digital"},
            "Heat-Ctrl": {"states": ["Nominal"], "type": "controller", "category": "digital"},
        }
    }
    monkeypatch.setattr(dashboard_views.requests, "get", Mock(return_value=MockResponse(payload)))

    response = user_client.post(
        reverse("dashboard:risk_assessment_testbed_generate"),
        data=json.dumps({
            "cidr": "192.168.10.0/30",
            "cves": "CVE-2024-0001\nCVE-2024-0002",
            "max_cves_per_node": 2,
        }),
        content_type="application/json",
    )
    assert response.status_code == 200

    body = response.json()
    assert body["nodes_created"] == 2
    assert body["mappings_updated"] == 2
    assert body["links_created"] >= 1
    assert RiskNodeMapping.objects.filter(risk_node_id="PLC-Main").exists()
    assert RiskNodeMapping.objects.filter(risk_node_id="Heat-Ctrl").exists()

    nodes = Node.objects.filter(name__in=["PLC-Main", "Heat-Ctrl"])
    assert nodes.count() == 2
    for node in nodes:
        assert node.vulnerability_set.count() == 2
