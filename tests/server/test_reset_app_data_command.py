import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.core.management.base import CommandError

from dashboard.models import Node
from sliver.models import Teamserver


@pytest.mark.django_db
def test_reset_app_data_preserves_users_and_clears_application_tables():
    user = get_user_model().objects.create_user(username="alice", password="secret123")
    Node.objects.create(name="plc-1", ip_address="192.168.1.10")
    Teamserver.objects.create(name="primary", host="127.0.0.1", port=31337)

    session = SessionStore()
    session["user_id"] = user.id
    session.create()

    assert Session.objects.count() == 1
    assert Node.objects.count() == 1
    assert Teamserver.objects.count() == 1

    call_command("reset_app_data", "--force")

    user.refresh_from_db()
    assert get_user_model().objects.count() == 1
    assert user.check_password("secret123")
    assert Session.objects.count() == 0
    assert Node.objects.count() == 0
    assert Teamserver.objects.count() == 0


@pytest.mark.django_db
def test_reset_app_data_requires_force():
    get_user_model().objects.create_user(username="alice", password="secret123")
    Node.objects.create(name="plc-1", ip_address="192.168.1.10")

    with pytest.raises(CommandError, match="--force"):
        call_command("reset_app_data")

    assert get_user_model().objects.count() == 1
    assert Node.objects.count() == 1
