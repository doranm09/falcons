"""Test dashboard JSON ingestion."""

import json
import pytest
from unittest.mock import mock_open

from provisioning.scan_ingest.dashboard_json import parse_dashboard_json


def test_parse_dashboard_json_basic():
    """Test basic dashboard JSON parsing."""
    json_data = {
        "cyber_template_data": {
            "OS": "Ubuntu 24.04.2 LTS",
            "MAC": ["b0:4f:13:05:c6:90", "80:6d:97:42:4b:c3"],
            "lib": [],
            "port": [
                {"id": "128.61.144.211:22", "Protocol": "TCP"},
                {"id": "128.61.144.211:80", "Protocol": "TCP"}
            ]
        },
        "system_info": {
            "agent_id": "test-agent-123",
            "hostname": "TEST-HOST",
            "interfaces": [
                {
                    "name": "eno1",
                    "ip": "128.61.144.211",
                    "mac": "b0:4f:13:05:c6:90"
                }
            ]
        }
    }

    hosts = parse_dashboard_json(json_data)

    # Should have one host (loopback interfaces are skipped)
    assert len(hosts) == 1

    host = hosts[0]
    assert host.host_id == "test-agent-123_eno1"
    assert host.ip == "128.61.144.211"
    assert host.mac == "b0:4f:13:05:c6:90"
    assert host.os_family == "Linux"
    assert "ssh" in host.services
    assert "http" in host.services


def test_parse_dashboard_json_loopback_skipped():
    """Test that loopback interfaces are skipped."""
    json_data = {
        "cyber_template_data": {"OS": "Ubuntu", "MAC": [], "lib": [], "port": []},
        "system_info": {
            "agent_id": "test-agent",
            "hostname": "test-host",
            "interfaces": [
                {
                    "name": "lo",
                    "ip": "127.0.0.1",
                    "mac": "00:00:00:00:00:00"
                },
                {
                    "name": "eno1",
                    "ip": "192.168.1.100",
                    "mac": "aa:bb:cc:dd:ee:ff"
                }
            ]
        }
    }

    hosts = parse_dashboard_json(json_data)

    # Should skip lo and only return eno1
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.100"
    assert hosts[0].interface_name == "eno1"


def test_parse_dashboard_json_windows_os():
    """Test Windows OS detection."""
    json_data = {
        "cyber_template_data": {"OS": "Microsoft Windows Server 2019", "MAC": [], "lib": [], "port": []},
        "system_info": {
            "agent_id": "ws-agent",
            "hostname": "WIN-SERVER",
            "interfaces": [
                {
                    "name": "Ethernet",
                    "ip": "10.0.0.10",
                    "mac": "11:22:33:44:55:66"
                }
            ]
        }
    }

    hosts = parse_dashboard_json(json_data)

    assert len(hosts) == 1
    assert hosts[0].os_family == "Windows"


def test_parse_dashboard_json_no_interfaces():
    """Test handling of empty interfaces."""
    json_data = {
        "cyber_template_data": {"OS": "Linux", "MAC": [], "lib": [], "port": []},
        "system_info": {
            "agent_id": "empty-agent",
            "hostname": "empty-host",
            "interfaces": []
        }
    }

    hosts = parse_dashboard_json(json_data)

    assert len(hosts) == 0


def test_parse_dashboard_json_unknown_os():
    """Test unknown OS handling."""
    json_data = {
        "cyber_template_data": {"OS": "Some Unknown OS", "MAC": [], "lib": [], "port": []},
        "system_info": {
            "agent_id": "unknown-os-agent",
            "hostname": "unknown-host",
            "interfaces": [
                {
                    "name": "eth0",
                    "ip": "172.16.0.1",
                    "mac": "77:88:99:aa:bb:cc"
                }
            ]
        }
    }

    hosts = parse_dashboard_json(json_data)

    assert len(hosts) == 1
    assert hosts[0].os_family is None


def test_parse_dashboard_json_service_mapping():
    """Test service port mapping."""
    json_data = {
        "cyber_template_data": {
            "OS": "Ubuntu",
            "MAC": [],
            "lib": [],
            "port": [
                {"id": "10.0.0.1:443", "Protocol": "TCP"},  # HTTPS
                {"id": "10.0.0.1:53", "Protocol": "TCP"},   # DNS
                {"id": "10.0.0.1:9999", "Protocol": "TCP"}, # Unknown
                {"id": "10.0.0.1:445", "Protocol": "UDP"}   # SMB but UDP
            ]
        },
        "system_info": {
            "agent_id": "svc-agent",
            "hostname": "svc-host",
            "interfaces": [
                {
                    "name": "eth0",
                    "ip": "10.0.0.1",
                    "mac": "00:11:22:33:44:55"
                }
            ]
        }
    }

    hosts = parse_dashboard_json(json_data)

    assert len(hosts) == 1
    services = hosts[0].services
    assert "https" in services
    assert "dns" in services
    # Unknown port and UDP should not be mapped
    assert len([s for s in services if s not in ["https", "dns"]]) == 0
