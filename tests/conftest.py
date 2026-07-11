import pytest
import tempfile
from pathlib import Path
import os
from django.conf import settings
from django.test import Client
from django.contrib.auth import get_user_model
from factories.user_factory import UserFactory
from dashboard.models import SiemUserRole


@pytest.fixture(autouse=True)
def setup_isolated_media_root(tmp_path):
    """Set up isolated MEDIA_ROOT for tests."""
    settings.MEDIA_ROOT = tmp_path / "media"
    settings.MEDIA_ROOT.mkdir(exist_ok=True)


@pytest.fixture(autouse=True)
def isolate_host_agent_zip_cache():
    """Prevent the shared temporary agent ZIP from leaking between tests."""
    cache_path = Path(tempfile.gettempdir()) / "cyber_agent_zips" / "host_agent.zip"
    cache_path.unlink(missing_ok=True)
    yield
    cache_path.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def setup_siem_tokens(settings):
    settings.SIEM_INGEST_TOKEN = "test-siem-token"
    settings.SIEM_SENSOR_TOKEN = "test-siem-token"
    settings.SIEM_INGEST_TOKEN_REQUIRED = True
    settings.AGENT_API_TOKEN = "test-agent-token"
    settings.AGENT_API_TOKEN_REQUIRED = True


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
def siem_client(settings):
    """Django test client with SIEM ingest token headers."""
    client = Client()
    client.defaults["HTTP_X_SIEM_TOKEN"] = settings.SIEM_INGEST_TOKEN
    return client


@pytest.fixture
def agent_client(settings):
    """Django test client with agent token headers."""
    client = Client()
    client.defaults["HTTP_X_AGENT_TOKEN"] = settings.AGENT_API_TOKEN
    return client


@pytest.fixture
def siem_admin_client(admin_user):
    """Django test client logged in as SIEM admin."""
    SiemUserRole.objects.update_or_create(
        user=admin_user, defaults={"role": SiemUserRole.Role.ADMIN}
    )
    client = Client()
    client.defaults["HTTP_X_SIEM_TOKEN"] = settings.SIEM_INGEST_TOKEN
    client.defaults["HTTP_X_AGENT_TOKEN"] = settings.AGENT_API_TOKEN
    client.login(username=admin_user.username, password="password")
    return client


@pytest.fixture
def siem_analyst_client(user):
    """Django test client logged in as SIEM analyst."""
    SiemUserRole.objects.update_or_create(
        user=user, defaults={"role": SiemUserRole.Role.ANALYST}
    )
    client = Client()
    client.defaults["HTTP_X_SIEM_TOKEN"] = settings.SIEM_INGEST_TOKEN
    client.defaults["HTTP_X_AGENT_TOKEN"] = settings.AGENT_API_TOKEN
    client.login(username=user.username, password="password")
    return client


@pytest.fixture
def live_server_with_djangofixture(live_server):
    """Live server with Django fixtures available."""
    # This ensures Django fixtures can be used with live_server
    return live_server


def pytest_collection_modifyitems(config, items):
    """Skip Playwright E2E tests unless explicitly enabled."""
    if os.getenv("RUN_E2E") in {"1", "true", "yes"}:
        return
    skip_playwright = pytest.mark.skip(reason="Playwright E2E tests disabled. Set RUN_E2E=1 to enable.")
    for item in items:
        if "playwright" in item.keywords:
            item.add_marker(skip_playwright)
