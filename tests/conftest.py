import pytest
import tempfile
from pathlib import Path
from django.conf import settings
from django.test import Client
from django.contrib.auth import get_user_model
from factories.user_factory import UserFactory


@pytest.fixture(autouse=True)
def setup_isolated_media_root(tmp_path):
    """Set up isolated MEDIA_ROOT for tests."""
    settings.MEDIA_ROOT = tmp_path / "media"
    settings.MEDIA_ROOT.mkdir(exist_ok=True)


@pytest.fixture
def user():
    """Create a regular user."""
    return UserFactory()


@pytest.fixture
def admin_user():
    """Create an admin user."""
    return UserFactory(is_staff=True, is_superuser=True)


@pytest.fixture
def client():
    """Basic Django test client."""
    return Client()


@pytest.fixture
def user_client(user):
    """Django test client logged in as regular user."""
    client = Client()
    client.login(username=user.username, password="password")  # Factory sets this password
    return client


@pytest.fixture
def admin_client(admin_user):
    """Django test client logged in as admin user."""
    client = Client()
    client.login(username=admin_user.username, password="password")
    return client


@pytest.fixture
def live_server_with_djangofixture(live_server):
    """Live server with Django fixtures available."""
    # This ensures Django fixtures can be used with live_server
    return live_server
