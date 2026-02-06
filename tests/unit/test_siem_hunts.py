from dashboard.siem_hunts import build_query_payload_from_form, parse_hunt_tags, validate_hunt_query


def test_parse_hunt_tags_dedup_case_insensitive():
    tags = parse_hunt_tags("alpha, beta,ALPHA,  gamma ")
    assert tags == ["alpha", "beta", "gamma"]


def test_build_query_payload_from_form_filters_fields():
    data = {
        "event_type": "zeek.conn",
        "source": "zeek",
        "agg": "source,event_type",
        "limit": "25",
        "irrelevant": "drop",
        "asset_ip": "",
    }
    payload = build_query_payload_from_form(data)
    assert payload == {
        "event_type": "zeek.conn",
        "source": "zeek",
        "agg": "source,event_type",
        "limit": "25",
    }


def test_validate_hunt_query_accepts_valid_params():
    params = {"event_type": "zeek.conn", "limit": "10"}
    parsed = validate_hunt_query(params)
    assert parsed["event_type"] == "zeek.conn"
    assert parsed["limit"] == 10
