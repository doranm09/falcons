from django.contrib.auth import get_user_model
from django.urls import reverse

from dashboard.models import MinimegaExecutionLog


def test_minimega_logs_requires_staff(client):
    response = client.get(reverse("dashboard:minimega_execution_logs"))
    assert response.status_code == 401


def test_minimega_logs_staff_access(client):
    User = get_user_model()
    user = User.objects.create_user(username="stafflog", password="pass", is_staff=True)
    client.force_login(user)

    MinimegaExecutionLog.objects.create(action="execute", status="success")

    response = client.get(reverse("dashboard:minimega_execution_logs"))
    assert response.status_code == 200
    assert b"MiniMega Execution Logs" in response.content
