import pytest

from dashboard.siem import parse_siem_search_params, SiemQueryError


def test_parse_siem_search_params_defaults():
    params = parse_siem_search_params({})
    assert params["limit"] == 100
    assert params["offset"] == 0
    assert params["severity"] is None


def test_parse_siem_search_params_severity():
    params = parse_siem_search_params({"severity": "5"})
    assert params["severity"] == 5


def test_parse_siem_search_params_invalid_limit():
    with pytest.raises(SiemQueryError):
        parse_siem_search_params({"limit": "bad"})


def test_parse_siem_search_params_invalid_severity():
    with pytest.raises(SiemQueryError):
        parse_siem_search_params({"severity": "high"})
