from dashboard.siem_syslog import parse_syslog_line, syslog_to_event


def test_parse_syslog_line_rfc3164():
    line = "<34>Oct 11 22:14:15 host1 sshd[123]: test"
    parsed = parse_syslog_line(line)
    assert parsed["host"] == "host1"


def test_syslog_to_event():
    line = "<34>Oct 11 22:14:15 host1 sshd[123]: test"
    event = syslog_to_event(line)
    assert event["event_type"] == "syslog.message"
