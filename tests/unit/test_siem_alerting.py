from dashboard.models import AlertRule
from dashboard.siem_alerting import should_trigger, build_dedup_key


def test_should_trigger_sigma_rule():
    rule = AlertRule(
        name="Sigma Test",
        rule_type=AlertRule.RuleType.SIGMA,
        enabled=True,
        match_event_type="zeek.conn",
        match_source="zeek",
        match_contains="conn",
    )
    event = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "summary": "Conn established",
        "raw": {},
    }
    assert should_trigger(rule, event) is True


def test_should_trigger_suricata_rule():
    rule = AlertRule(
        name="Suricata Alerts",
        rule_type=AlertRule.RuleType.SURICATA,
        enabled=True,
        match_event_type="suricata.alert",
    )
    event = {
        "event_type": "suricata.alert",
        "source": "suricata",
        "summary": "ET MALWARE",
        "raw": {},
    }
    assert should_trigger(rule, event) is True


def test_build_dedup_key():
    rule = AlertRule(id=1, name="R", rule_type=AlertRule.RuleType.SIGMA)
    event = {"event_type": "x", "asset_ip": "1.2.3.4", "asset_id": "a"}
    assert build_dedup_key(rule, event) == "1:x:1.2.3.4:a"
