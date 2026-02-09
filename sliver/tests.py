from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import Teamserver, Engagement, SliverSession, SliverJob


class SliverModelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="tester", password="password")
        self.teamserver = Teamserver.objects.create(
            name="ts1",
            host="127.0.0.1",
            port=31337,
        )
        self.engagement = Engagement.objects.create(
            name="eng1",
            teamserver=self.teamserver,
            operator=self.user,
            status=Engagement.Status.ACTIVE,
        )

    def test_engagement_session_and_job_counts(self):
        SliverSession.objects.create(
            session_id="sess-1",
            engagement=self.engagement,
            status=SliverSession.Status.ACTIVE,
        )
        SliverSession.objects.create(
            session_id="sess-2",
            engagement=self.engagement,
            status=SliverSession.Status.DEAD,
        )
        session = SliverSession.objects.first()
        SliverJob.objects.create(
            job_id="job-1",
            session=session,
            status=SliverJob.Status.COMPLETED,
            command="whoami",
        )

        assert self.engagement.get_active_sessions_count() == 1
        assert self.engagement.get_completed_jobs_count() == 1

    def test_session_is_online(self):
        session = SliverSession.objects.create(
            session_id="sess-online",
            engagement=self.engagement,
            status=SliverSession.Status.ACTIVE,
            last_checkin=timezone.now(),
            reconfigure_interval=10,
        )
        assert session.is_online() is True

        stale = timezone.now() - timezone.timedelta(minutes=30)
        SliverSession.objects.filter(pk=session.pk).update(last_checkin=stale)
        session.refresh_from_db()
        assert session.is_online() is False

    def test_job_duration(self):
        session = SliverSession.objects.create(
            session_id="sess-job",
            engagement=self.engagement,
        )
        job = SliverJob.objects.create(
            job_id="job-duration",
            session=session,
            command="whoami",
            started_at=timezone.now() - timezone.timedelta(seconds=10),
            completed_at=timezone.now(),
        )
        assert job.duration() is not None
