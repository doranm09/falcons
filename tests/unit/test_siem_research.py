import pytest

from dashboard.models import ResearchProfile
from dashboard.siem_research import apply_profile_max_batch, get_active_profile


@pytest.mark.django_db
def test_apply_profile_max_batch_overrides_default():
    profile = ResearchProfile.objects.create(
        name="Profile A",
        version="1.0",
        pipeline_version="1.0",
        ruleset_version="1.0",
        retention_days=30,
        max_batch=5,
        active=True,
    )
    assert get_active_profile() == profile
    assert apply_profile_max_batch(500) == 5
