from django.utils import timezone

from dashboard.models import SiemEvent
from dashboard.siem_query import parse_search_request, search_siem_events


def test_parse_search_request_multi_filters():
    params = parse_search_request({"event_type_in": "a,b", "source_in": "x,y", "agg": "source"})
    assert params["event_type_in"] == ["a", "b"]
    assert params["source_in"] == ["x", "y"]
    assert params["agg_fields"] == ["source"]


def test_search_siem_events_aggregations(db):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.alert",
        summary="a",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="zeek",
        event_type="zeek.conn",
        summary="b",
        raw={},
    )

    params = {
        "agg_fields": ["source"],
        "agg_size": 10,
        "limit": 10,
        "offset": 0,
    }
    result = search_siem_events(params)
    assert result["count"] == 2
    assert result["aggregations"][0]["field"] == "source"
    assert len(result["aggregations"][0]["buckets"]) == 2
