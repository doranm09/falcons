from __future__ import annotations

from typing import Optional

from .models import ResearchProfile


def get_active_profile() -> Optional[ResearchProfile]:
    return ResearchProfile.objects.filter(active=True).order_by("-updated_at").first()


def apply_profile_max_batch(default_max: int) -> int:
    profile = get_active_profile()
    if profile and profile.max_batch:
        return int(profile.max_batch)
    return default_max


def activate_profile(profile: ResearchProfile) -> None:
    ResearchProfile.objects.exclude(id=profile.id).update(active=False)
    profile.active = True
    profile.save(update_fields=["active"])
