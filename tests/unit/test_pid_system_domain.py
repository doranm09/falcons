from dashboard.pid_system import classify_domain, extract_ip


def test_classify_domain_prefers_explicit_domain():
    info = {"domain": "cyber"}
    assert classify_domain("PUMP_A", info) == "cyber"

    info = {"domain": "physical"}
    assert classify_domain("PUMP_A", info) == "physical"


def test_classify_domain_uses_hints():
    info = {"type": "PLC"}
    assert classify_domain("NODE", info) == "cyber"

    info = {"module": "PumpModule"}
    assert classify_domain("PUMP_A", info) == "physical"


def test_extract_ip():
    info = {"ip_address": "10.0.0.10"}
    assert extract_ip(info) == "10.0.0.10"
