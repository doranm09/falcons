import pytest
from django.urls import reverse

from dashboard.models import Hunt, HuntNote, HuntSearch, HuntTag


@pytest.mark.django_db
def test_hunt_create_and_detail_flow(siem_analyst_client):
    resp = siem_analyst_client.post(
        reverse("dashboard:siem_hunt_create"),
        data={"name": "Hunt Alpha", "description": "Test", "tags": "alpha, beta"},
    )
    assert resp.status_code == 302
    assert Hunt.objects.count() == 1
    hunt = Hunt.objects.first()
    assert hunt is not None
    assert HuntTag.objects.filter(hunt=hunt).count() == 2

    detail = siem_analyst_client.get(reverse("dashboard:siem_hunt_detail", args=[hunt.id]))
    assert detail.status_code == 200


@pytest.mark.django_db
def test_hunt_add_note_and_search_and_replay(siem_analyst_client):
    hunt = Hunt.objects.create(name="Hunt Beta", description="Test")

    note_resp = siem_analyst_client.post(
        reverse("dashboard:siem_hunt_add_note", args=[hunt.id]),
        data={"title": "Hypothesis", "note": "Investigate unusual DNS"},
    )
    assert note_resp.status_code == 302
    assert HuntNote.objects.filter(hunt=hunt).count() == 1

    search_resp = siem_analyst_client.post(
        reverse("dashboard:siem_hunt_add_search", args=[hunt.id]),
        data={"search_name": "Zeek", "event_type": "zeek.conn"},
    )
    assert search_resp.status_code == 302
    search = HuntSearch.objects.filter(hunt=hunt).first()
    assert search is not None

    replay_resp = siem_analyst_client.get(
        reverse("dashboard:siem_hunt_replay_search", args=[hunt.id, search.id])
    )
    assert replay_resp.status_code == 200
    body = replay_resp.json()
    assert body["hunt_id"] == hunt.id
    assert body["search_id"] == search.id
