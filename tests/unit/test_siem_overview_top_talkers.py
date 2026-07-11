from django.utils import timezone

from dashboard.models import SiemEvent
from dashboard.views import _build_top_talker_rows


def test_build_top_talker_rows_includes_noise_and_hybrid_assets_for_frontend_policy(db):
    now = timezone.now()
    SiemEvent.objects.create(
        timestamp=now,
        source="agent",
        event_type="agent.telemetry",
        asset_ip="fe80::2890:5ff:fe2b:8ae2",
        source_ip="fe80::2890:5ff:fe2b:8ae2",
        summary="ipv6 noise",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="zeek",
        event_type="zeek.conn",
        asset_ip="10.1.1.14",
        source_ip="10.1.1.14",
        destination_ip="10.1.1.10",
        summary="hybrid flow",
        raw={},
    )
    SiemEvent.objects.create(
        timestamp=now,
        source="suricata",
        event_type="suricata.alert",
        asset_ip="10.3.50.10",
        source_ip="10.3.50.10",
        destination_ip="10.4.50.20",
        summary="hybrid alert",
        raw={},
    )

    rows = _build_top_talker_rows(SiemEvent.objects.all(), limit=5)

    assert rows
    row_by_ip = {row["asset_ip"]: row for row in rows}
    assert "fe80::2890:5ff:fe2b:8ae2" in row_by_ip
    assert "ipv6_link_local" in row_by_ip["fe80::2890:5ff:fe2b:8ae2"]["policy_tags"]
    assert {row["asset_ip"] for row in rows} >= {"10.1.1.14", "10.1.1.10", "10.3.50.10", "10.4.50.20"}
