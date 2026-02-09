from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
import secrets

from pathlib import Path
from django.http import JsonResponse, Http404, FileResponse, HttpResponse
from urllib.parse import urlencode
import csv
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db import models as dj_models
from django.urls import reverse
from django.utils.html import format_html
import json

# Import Sliver models/utilities (always available)
from dashboard.models import AgentCommand, AgentStatus
from .models import (
    Teamserver, Engagement, SliverSession, SliverJob, Loot,
    TaskTemplate, ImplantTemplate, ImplantArtifact, SliverEvent, AuditLog, Watcher
)
from .utils import get_sliver_client, log_audit_action, resolve_artifact_path, get_session_status_summary
from .forms import TeamserverForm

# Sliver client integration (optional)
try:
    import sliver as sliver_client  # type: ignore
    SLIVER_AVAILABLE = True
except ImportError:
    sliver_client = None
    SLIVER_AVAILABLE = False


@login_required
def sliver_dashboard(request):
    """Main Sliver dashboard."""
    if not SLIVER_AVAILABLE:
        messages.warning(request, "Sliver integration is not configured. Install sliver-py for live teamserver actions.")

    # Get summary stats
    engagements = Engagement.objects.filter(operator=request.user)
    active_sessions = SliverSession.objects.filter(
        engagement__operator=request.user,
        status='ACTIVE'
    ).count()
    recent_jobs = SliverJob.objects.filter(
        session__engagement__operator=request.user
    ).order_by('-created_at')[:5]
    recent_loot = Loot.objects.filter(
        engagement__operator=request.user
    ).order_by('-collected_at')[:5]

    context = {
        'engagements': engagements,
        'active_sessions': active_sessions,
        'recent_jobs': recent_jobs,
        'recent_loot': recent_loot,
        'total_engagements': engagements.count(),
        'active_engagements': engagements.filter(status='ACTIVE').count(),
        'completed_jobs': SliverJob.objects.filter(
            session__engagement__operator=request.user,
            status='COMPLETED'
        ).count(),
    }

    return render(request, 'sliver/dashboard.html', context)


@login_required
def engagement_list(request):
    """List all engagements for the current user."""
    engagements = Engagement.objects.filter(
        operator=request.user
    ).order_by('-created_at')
    teamservers = Teamserver.objects.all().order_by('name')

    # Add session/jobe counts to each engagement
    for engagement in engagements:
        engagement.active_sessions_count = engagement.get_active_sessions_count()
        engagement.completed_jobs_count = engagement.get_completed_jobs_count()

    return render(request, 'sliver/engagements.html', {
        'engagements': engagements,
        'teamservers': teamservers,
    })


@login_required
def engagement_detail(request, engagement_id):
    """Detailed view of an engagement."""
    engagement = get_object_or_404(
        Engagement,
        id=engagement_id,
        operator=request.user
    )

    # Get related data
    sessions = SliverSession.objects.filter(engagement=engagement).order_by('-last_checkin')
    jobs_qs = SliverJob.objects.filter(
        session__engagement=engagement
    ).order_by('-created_at')
    recent_jobs = jobs_qs[:20]
    loot = Loot.objects.filter(engagement=engagement).order_by('-collected_at')[:10]
    events = SliverEvent.objects.filter(engagement=engagement).order_by('-timestamp')[:20]

    return render(request, 'sliver/engagement_detail.html', {
        'engagement': engagement,
        'sessions': sessions,
        'recent_jobs': recent_jobs,
        'loot': loot,
        'events': events,
        'active_sessions_count': sessions.filter(status='ACTIVE').count(),
        'pending_jobs_count': jobs_qs.filter(status__in=['PENDING', 'RUNNING']).count(),
    })


@login_required
@require_POST
def create_engagement(request):
    """Create a new engagement."""
    name = request.POST.get('name')
    description = request.POST.get('description', '')
    teamserver_id = request.POST.get('teamserver_id')
    target_scope = request.POST.get('target_scope', '')

    if not all([name, teamserver_id]):
        messages.error(request, "Name and teamserver are required.")
        return redirect('sliver:engagement_list')

    try:
        teamserver = Teamserver.objects.get(id=teamserver_id)
        engagement = Engagement.objects.create(
            name=name,
            description=description,
            teamserver=teamserver,
            operator=request.user,
            target_scope=target_scope
        )

        # Log audit action
        log_audit_action(
            action='ENGAGEMENT_STARTED',
            user=request.user,
            teamserver=teamserver,
            engagement=engagement,
            details={'message': f"Engagement '{name}' created"}
        )

        messages.success(request, f"Engagement '{name}' created successfully.")
        return redirect('sliver:engagement_detail', engagement_id=engagement.id)

    except Teamserver.DoesNotExist:
        messages.error(request, "Selected teamserver does not exist.")
    except Exception as e:
        messages.error(request, f"Error creating engagement: {str(e)}")

    return redirect('sliver:engagement_list')


@login_required
@require_POST
def start_engagement(request, engagement_id):
    """Start an engagement."""
    engagement = get_object_or_404(
        Engagement,
        id=engagement_id,
        operator=request.user
    )

    if engagement.status != 'ACTIVE':
        engagement.status = 'ACTIVE'
        engagement.start_date = timezone.now()
        engagement.save()

        log_audit_action(
            action='ENGAGEMENT_STARTED',
            user=request.user,
            teamserver=engagement.teamserver,
            engagement=engagement,
            details={'message': f"Engagement '{engagement.name}' started"}
        )

        messages.success(request, f"Engagement '{engagement.name}' started.")
    else:
        messages.warning(request, f"Engagement '{engagement.name}' is already active.")

    return redirect('sliver:engagement_detail', engagement_id=engagement_id)


@login_required
@require_POST
def stop_engagement(request, engagement_id):
    """Stop an engagement."""
    engagement = get_object_or_404(
        Engagement,
        id=engagement_id,
        operator=request.user
    )

    if engagement.status == 'ACTIVE':
        engagement.status = 'COMPLETED'
        engagement.end_date = timezone.now()
        engagement.save()

        log_audit_action(
            action='ENGAGEMENT_STOPPED',
            user=request.user,
            teamserver=engagement.teamserver,
            engagement=engagement,
            details={'message': f"Engagement '{engagement.name}' stopped"}
        )

        messages.success(request, f"Engagement '{engagement.name}' stopped.")
    else:
        messages.warning(request, f"Engagement '{engagement.name}' is not active.")

    return redirect('sliver:engagement_detail', engagement_id=engagement_id)


@login_required
def session_list(request, engagement_id=None):
    """List all sessions, optionally filtered by engagement."""
    sessions = SliverSession.objects.filter(
        engagement__operator=request.user
    ).order_by('-last_checkin')
    engagements = Engagement.objects.filter(operator=request.user).order_by('name')
    templates = TaskTemplate.objects.all().order_by('category', 'name')

    if engagement_id:
        engagement = get_object_or_404(
            Engagement,
            id=engagement_id,
            operator=request.user
        )
        sessions = sessions.filter(engagement=engagement)

    # Get online status for each session
    for session in sessions:
        session.is_online_status = session.is_online()

    # Get recent jobs for each session
    for session in sessions:
        session.recent_jobs = SliverJob.objects.filter(
            session=session
        ).order_by('-created_at')[:3]

    for engagement in engagements:
        engagement.active_sessions_count = engagement.get_active_sessions_count()

    summary = get_session_status_summary(sessions)

    # Paginate
    paginator = Paginator(sessions, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'sliver/sessions.html', {
        'page_obj': page_obj,
        'engagement_id': engagement_id,
        'engagements': engagements,
        'templates': templates,
        'summary': summary,
    })


@login_required
def session_detail(request, session_id):
    """Detailed view of a session."""
    session = get_object_or_404(
        SliverSession,
        session_id=session_id,
        engagement__operator=request.user
    )

    # Get session data
    recent_jobs = SliverJob.objects.filter(session=session).order_by('-created_at')[:20]
    loot = Loot.objects.filter(session=session).order_by('-collected_at')[:10]

    templates = TaskTemplate.objects.all().order_by('category', 'name')

    return render(request, 'sliver/session_detail.html', {
        'session': session,
        'recent_jobs': recent_jobs,
        'loot': loot,
        'is_online': session.is_online(),
        'templates': templates,
    })


@login_required
@require_POST
def collect_loot(request, session_id):
    """Trigger a loot collection task for a session."""
    session = get_object_or_404(
        SliverSession,
        session_id=session_id,
        engagement__operator=request.user
    )

    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('sliver:session_detail', session_id=session_id)

    try:
        from .tasks import collect_loot_task
        collect_loot_task.delay(session_id=session.session_id, user_id=request.user.id)
        messages.success(request, f"Loot collection started for session '{session.name or session.session_id}'.")
    except Exception as e:
        messages.error(request, f"Failed to start loot collection: {str(e)}")

    fallback_url = reverse('sliver:session_detail', args=[session_id])
    return redirect(request.META.get('HTTP_REFERER') or fallback_url)


@login_required
@require_POST
def execute_command(request, session_id):
    """Execute a command on a session."""
    session = get_object_or_404(
        SliverSession,
        session_id=session_id,
        engagement__operator=request.user
    )

    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('sliver:session_detail', session_id=session_id)

    command = request.POST.get('command', '').strip()
    if not command:
        messages.error(request, "Command cannot be empty.")
        return redirect('sliver:session_detail', session_id=session_id)

    try:
        client = get_sliver_client(session.engagement.teamserver)

        # Execute command asynchronously via Celery
        from .tasks import execute_sliver_command_task
        task = execute_sliver_command_task.delay(
            session_id=session.session_id,
            command=command,
            user_id=request.user.id
        )

        # Create job record (in PENDING state until Celery picks it up)
        job = SliverJob.objects.create(
            job_id=f"job_{task.id}",
            session=session,
            status='PENDING',
            command=command,
            operator=request.user,
            started_at=timezone.now()
        )

        job_url = reverse('sliver:job_detail', args=[job.job_id])
        messages.success(
            request,
            format_html(
                "Command sent to session '{}'. <a href=\"{}\">View job {}</a>.",
                session.name or session.session_id,
                job_url,
                job.job_id,
            )
        )

    except Exception as e:
        messages.error(request, f"Failed to send command: {str(e)}")

    return redirect('sliver:session_detail', session_id=session_id)


@login_required
def job_list(request, session_id=None):
    """List jobs, optionally filtered by session."""
    jobs = SliverJob.objects.filter(
        session__engagement__operator=request.user
    ).select_related('session', 'template', 'session__engagement').order_by('-created_at')

    if session_id:
        session = get_object_or_404(
            SliverSession,
            session_id=session_id,
            engagement__operator=request.user
        )
        jobs = jobs.filter(session=session)

    jobs, filters = _filter_jobs(request, jobs)
    if session_id:
        filters['session_id'] = session_id

    status_counts = jobs.values('status').order_by().annotate(total=dj_models.Count('status'))
    status_map = {row['status']: row['total'] for row in status_counts}
    engagements = Engagement.objects.filter(operator=request.user).order_by('name')
    sessions = SliverSession.objects.filter(engagement__operator=request.user).order_by('name')

    # Paginate
    paginator = Paginator(jobs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    query_params = {key: value for key, value in filters.items() if value}
    jobs_api_query = urlencode(query_params)
    pagination_query = jobs_api_query

    return render(request, 'sliver/jobs.html', {
        'page_obj': page_obj,
        'session_id': session_id,
        'filters': filters,
        'status_counts': status_map,
        'engagements': engagements,
        'sessions': sessions,
        'jobs_api_query': jobs_api_query,
        'pagination_query': pagination_query,
    })


@login_required
def job_detail(request, job_id):
    """Detailed view of a job with output."""
    job = get_object_or_404(
        SliverJob,
        job_id=job_id,
        session__engagement__operator=request.user
    )

    return render(request, 'sliver/job_detail.html', {
        'job': job,
    })


@login_required
def job_output(request, job_id):
    """Return job output as text (optionally downloadable)."""
    job = get_object_or_404(
        SliverJob,
        job_id=job_id,
        session__engagement__operator=request.user
    )
    return _job_text_response(job, field='output', label='output', request=request)


@login_required
def job_error(request, job_id):
    """Return job error output as text (optionally downloadable)."""
    job = get_object_or_404(
        SliverJob,
        job_id=job_id,
        session__engagement__operator=request.user
    )
    return _job_text_response(job, field='error', label='error', request=request)


@login_required
@require_POST
def retry_job(request, job_id):
    """Retry a job by re-running the same command."""
    job = get_object_or_404(
        SliverJob,
        job_id=job_id,
        session__engagement__operator=request.user
    )

    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect(request.META.get('HTTP_REFERER') or reverse('sliver:job_detail', args=[job_id]))

    try:
        from .tasks import execute_sliver_command_task
        task = execute_sliver_command_task.delay(
            session_id=job.session.session_id,
            command=job.command,
            parameters=job.parameters,
            template_id=job.template_id,
            user_id=request.user.id
        )

        SliverJob.objects.create(
            job_id=f"job_{task.id}",
            name=job.name,
            session=job.session,
            template=job.template,
            status='PENDING',
            command=job.command,
            parameters=job.parameters,
            operator=request.user,
            started_at=timezone.now()
        )
        messages.success(request, f"Job {job_id} retried.")
    except Exception as e:
        messages.error(request, f"Failed to retry job: {str(e)}")

    return redirect(request.META.get('HTTP_REFERER') or reverse('sliver:job_detail', args=[job_id]))


@login_required
@require_GET
def export_jobs(request):
    """Export filtered jobs as CSV."""
    jobs = SliverJob.objects.filter(
        session__engagement__operator=request.user
    ).select_related('session', 'template', 'session__engagement').order_by('-created_at')
    jobs, _ = _filter_jobs(request, jobs)

    response = HttpResponse(content_type='text/csv')
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="sliver_jobs_{timestamp}.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'job_id', 'status', 'command', 'session_id', 'session_name',
        'engagement', 'template', 'started_at', 'completed_at', 'exit_code'
    ])

    for job in jobs[:5000]:
        writer.writerow([
            job.job_id,
            job.status,
            job.command,
            job.session.session_id,
            job.session.name,
            job.session.engagement.name,
            job.template.name if job.template else '',
            job.started_at.isoformat() if job.started_at else '',
            job.completed_at.isoformat() if job.completed_at else '',
            job.exit_code if job.exit_code is not None else '',
        ])

    return response


@login_required
def loot_list(request, engagement_id=None):
    """List collected loot."""
    loot_items = Loot.objects.filter(
        engagement__operator=request.user
    ).select_related('session', 'engagement').order_by('-collected_at')

    if engagement_id:
        engagement = get_object_or_404(
            Engagement,
            id=engagement_id,
            operator=request.user
        )
        loot_items = loot_items.filter(engagement=engagement)

    # Paginate
    paginator = Paginator(loot_items, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'sliver/loot.html', {
        'page_obj': page_obj,
        'engagement_id': engagement_id,
    })


@login_required
def download_loot(request, loot_id):
    """Download a loot item if available."""
    loot = get_object_or_404(Loot, id=loot_id)

    if loot.engagement.operator != request.user and not request.user.is_superuser:
        raise Http404

    if loot.local_path:
        file_name = Path(loot.local_path.name).name or loot.name or loot.loot_id
        return FileResponse(
            loot.local_path.open('rb'),
            as_attachment=True,
            filename=file_name
        )

    if loot.content:
        file_name = loot.name or f"loot_{loot.loot_id}.txt"
        response = HttpResponse(loot.content, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response

    messages.error(request, "Loot file is not available for download.")
    return redirect(request.META.get('HTTP_REFERER', 'sliver:loot_list'))

@login_required
def generate_implant(request):
    """Generate an implant/stager."""
    if request.method == 'POST':
        if not SLIVER_AVAILABLE:
            messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
            return redirect('sliver:generate_implant')
        template_id = request.POST.get('template_id')
        engagement_id = request.POST.get('engagement_id')
        raw_name = request.POST.get('name', '').strip()
        name = raw_name or f"implant_{timezone.now().strftime('%Y%m%d_%H%M%S')}"

        try:
            template = ImplantTemplate.objects.get(id=template_id)
            engagement = Engagement.objects.get(id=engagement_id, operator=request.user)
            file_name = name
            if '.' not in file_name:
                ext = template.file_format or template.config.get('format') or 'bin'
                file_name = f"{file_name}.{ext.lstrip('.')}"

            artifact = ImplantArtifact.objects.create(
                name=name,
                file_name=file_name,
                engagement=engagement,
                template=template,
                generated_by=request.user,
                status=ImplantArtifact.Status.PENDING,
            )

            # Launch async implant generation
            from .tasks import generate_implant_task
            task = generate_implant_task.delay(
                engagement_id=engagement.id,
                template_id=template.id,
                name=name,
                user_id=request.user.id,
                artifact_id=artifact.id,
            )

            messages.success(request, f"Implant generation started for '{name}'.")
            return redirect('sliver:engagement_implants', engagement_id=engagement_id)

        except (ImplantTemplate.DoesNotExist, Engagement.DoesNotExist):
            messages.error(request, "Invalid template or engagement.")
        except Exception as e:
            messages.error(request, f"Error generating implant: {str(e)}")

    # GET request - show implant generation form
    templates = ImplantTemplate.objects.all()
    engagements = Engagement.objects.filter(operator=request.user, status='ACTIVE')

    return render(request, 'sliver/generate_implant.html', {
        'templates': templates,
        'engagements': engagements,
    })


@login_required
def implant_artifacts(request, engagement_id=None):
    """List generated implant artifacts."""
    if not SLIVER_AVAILABLE:
        messages.warning(request, "Sliver integration is not configured. Install sliver-py for live implant generation.")

    artifacts = ImplantArtifact.objects.select_related(
        'template', 'engagement', 'generated_by'
    ).order_by('-created_at')
    agents = AgentStatus.objects.all().order_by('-last_heartbeat')
    engagement = None

    if engagement_id:
        engagement = get_object_or_404(
            Engagement,
            id=engagement_id,
            operator=request.user
        )
        artifacts = artifacts.filter(engagement=engagement)
    else:
        artifacts = artifacts.filter(
            dj_models.Q(engagement__operator=request.user) |
            dj_models.Q(generated_by=request.user)
        )

    return render(request, 'sliver/implants.html', {
        'artifacts': artifacts,
        'engagement': engagement,
        'agents': agents,
    })


@login_required
def download_implant(request, artifact_id):
    """Download a generated implant artifact."""
    artifact = get_object_or_404(ImplantArtifact, id=artifact_id)

    if artifact.engagement and artifact.engagement.operator != request.user and not request.user.is_superuser:
        raise Http404
    if artifact.generated_by and artifact.generated_by != request.user and not request.user.is_superuser:
        raise Http404

    if artifact.status != ImplantArtifact.Status.READY:
        messages.warning(request, "Artifact is not ready for download.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))
    if not artifact.relative_path:
        messages.error(request, "Artifact path is missing.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))

    try:
        artifact_path = resolve_artifact_path(artifact.relative_path)
    except ValueError:
        raise Http404

    if not artifact_path.exists():
        messages.error(request, "Artifact file not found on disk.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))

    return FileResponse(
        open(artifact_path, 'rb'),
        as_attachment=True,
        filename=artifact.file_name or artifact_path.name,
    )


@require_GET
def download_implant_token(request, artifact_id):
    """Token-based download endpoint for agents."""
    token = request.GET.get('token', '')
    if not token:
        raise Http404

    artifact = get_object_or_404(ImplantArtifact, id=artifact_id)
    if artifact.download_token != token:
        raise Http404
    if artifact.token_expires_at and timezone.now() > artifact.token_expires_at:
        raise Http404
    if artifact.status != ImplantArtifact.Status.READY or not artifact.relative_path:
        raise Http404

    try:
        artifact_path = resolve_artifact_path(artifact.relative_path)
    except ValueError:
        raise Http404

    if not artifact_path.exists():
        raise Http404

    return FileResponse(
        open(artifact_path, 'rb'),
        as_attachment=True,
        filename=artifact.file_name or artifact_path.name,
    )


@login_required
@require_POST
def deploy_implant_to_agent(request, artifact_id):
    """Send a deploy command to a host agent for this artifact."""
    artifact = get_object_or_404(ImplantArtifact, id=artifact_id)
    if artifact.status != ImplantArtifact.Status.READY:
        messages.error(request, "Artifact is not ready for deployment.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))

    agent_id = request.POST.get('agent_id')
    if not agent_id:
        messages.error(request, "Agent ID is required for deployment.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))

    try:
        AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        messages.error(request, "Selected agent was not found.")
        return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))

    token = secrets.token_urlsafe(32)
    artifact.download_token = token
    artifact.token_expires_at = timezone.now() + timezone.timedelta(hours=1)
    artifact.save(update_fields=['download_token', 'token_expires_at'])

    fetch_url = request.build_absolute_uri(
        reverse('sliver:download_implant_token', args=[artifact.id])
    )

    execute_after = request.POST.get('execute_after') == 'on'
    execute_args_raw = request.POST.get('execute_args', '').strip()
    execute_args = None
    if execute_args_raw:
        try:
            parsed = json.loads(execute_args_raw)
            execute_args = parsed if isinstance(parsed, list) else [str(parsed)]
        except Exception:
            execute_args = execute_args_raw.split()

    parameters = {
        'artifact_id': artifact.id,
        'name': artifact.name,
        'file_name': artifact.file_name,
        'sha256': artifact.sha256,
        'size': artifact.file_size,
        'url': f"{fetch_url}?token={token}",
    }
    if execute_after:
        parameters['execute'] = True
        if execute_args:
            parameters['execute_args'] = execute_args

    AgentCommand.objects.create(
        agent_id=agent_id,
        action='sliver_deploy',
        parameters=parameters,
    )

    if artifact.engagement:
        log_audit_action(
            action='IMPLANT_DEPLOYED',
            user=request.user,
            teamserver=artifact.engagement.teamserver,
            engagement=artifact.engagement,
            details={
                'artifact_id': artifact.id,
                'artifact_name': artifact.name,
                'agent_id': agent_id,
                'execute_after': execute_after,
            }
        )

    messages.success(request, f"Deployment command queued for agent {agent_id}.")
    return redirect(request.META.get('HTTP_REFERER', 'sliver:implant_artifacts'))


@login_required
def teamserver_list(request):
    """List teamserver configurations and statuses."""
    if not SLIVER_AVAILABLE:
        messages.warning(request, "Sliver integration is not configured. Install sliver-py to test connections.")

    teamservers = Teamserver.objects.all().order_by('name')
    return render(request, 'sliver/teamservers.html', {
        'teamservers': teamservers,
    })


@login_required
def teamserver_create(request):
    """Create a new teamserver configuration."""
    if request.method == 'POST':
        form = TeamserverForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Teamserver created.")
            return redirect('sliver:teamserver_list')
    else:
        form = TeamserverForm()

    return render(request, 'sliver/teamserver_form.html', {
        'form': form,
        'mode': 'create',
    })


@login_required
def teamserver_edit(request, teamserver_id):
    """Edit an existing teamserver configuration."""
    teamserver = get_object_or_404(Teamserver, id=teamserver_id)

    if request.method == 'POST':
        form = TeamserverForm(request.POST, instance=teamserver)
        if form.is_valid():
            form.save()
            messages.success(request, "Teamserver updated.")
            return redirect('sliver:teamserver_list')
    else:
        form = TeamserverForm(instance=teamserver)

    return render(request, 'sliver/teamserver_form.html', {
        'form': form,
        'mode': 'edit',
        'teamserver': teamserver,
    })


@login_required
@require_POST
def teamserver_delete(request, teamserver_id):
    """Delete a teamserver configuration."""
    teamserver = get_object_or_404(Teamserver, id=teamserver_id)
    teamserver.delete()
    messages.success(request, "Teamserver deleted.")
    return redirect('sliver:teamserver_list')


@login_required
@require_POST
def test_teamserver_connection(request, teamserver_id):
    """Test teamserver connectivity."""
    teamserver = get_object_or_404(Teamserver, id=teamserver_id)

    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('sliver:teamserver_list')

    try:
        _ = get_sliver_client(teamserver)
        messages.success(request, f"Connected to {teamserver.name}.")
    except Exception as e:
        messages.error(request, f"Connection failed: {str(e)}")

    return redirect('sliver:teamserver_list')


@login_required
@require_POST
def test_all_teamservers(request):
    """Test connectivity for all teamservers."""
    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('sliver:teamserver_list')

    teamservers = Teamserver.objects.all()
    successes = 0
    failures = 0

    for ts in teamservers:
        try:
            _ = get_sliver_client(ts)
            successes += 1
        except Exception:
            failures += 1

    if successes:
        messages.success(request, f"Successfully connected to {successes} teamserver(s).")
    if failures:
        messages.warning(request, f"Failed to connect to {failures} teamserver(s).")

    return redirect('sliver:teamserver_list')


@login_required
def task_templates(request):
    """Manage task templates."""
    templates = TaskTemplate.objects.all().order_by('category', 'name')

    # Group by category
    categories = {}
    for template in templates:
        if template.category not in categories:
            categories[template.category] = []
        categories[template.category].append(template)

    return render(request, 'sliver/task_templates.html', {
        'categories': categories,
    })


@login_required
@require_POST
def run_template_task(request, session_id):
    """Run a task template on a session."""
    session = get_object_or_404(
        SliverSession,
        session_id=session_id,
        engagement__operator=request.user
    )

    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('sliver:session_detail', session_id=session_id)

    template_id = request.POST.get('template_id')
    try:
        template = TaskTemplate.objects.get(id=template_id)

        # Execute template command
        from .tasks import execute_sliver_command_task
        task = execute_sliver_command_task.delay(
            session_id=session.session_id,
            command=template.command,
            parameters=template.parameters,
            template_id=template.id,
            user_id=request.user.id
        )

        # Create job record
        job = SliverJob.objects.create(
            job_id=f"job_{task.id}",
            name=template.name,
            session=session,
            template=template,
            status='PENDING',
            command=template.command,
            parameters=template.parameters,
            operator=request.user,
            started_at=timezone.now()
        )

        job_url = reverse('sliver:job_detail', args=[job.job_id])
        messages.success(
            request,
            format_html(
                "Task '{}' started on session '{}'. <a href=\"{}\">View job {}</a>.",
                template.name,
                session.name or session.session_id,
                job_url,
                job.job_id,
            )
        )

    except TaskTemplate.DoesNotExist:
        messages.error(request, "Task template not found.")
    except Exception as e:
        messages.error(request, f"Error running task: {str(e)}")

    return redirect('sliver:session_detail', session_id=session_id)


# -----------------------------
# API Endpoints for React UI
# -----------------------------
@login_required
@require_GET
def api_sessions(request):
    """API endpoint for session data."""
    engagement_id = request.GET.get('engagement_id')
    sessions = SliverSession.objects.filter(
        engagement__operator=request.user
    ).order_by('-last_checkin')

    if engagement_id:
        sessions = sessions.filter(engagement_id=engagement_id)

    # Serialize sessions
    session_data = []
    for session in sessions:
        session_data.append({
            'session_id': session.session_id,
            'name': session.name,
            'engagement_id': session.engagement.id,
            'engagement': session.engagement.name,
            'status': session.status,
            'session_type': session.session_type,
            'hostname': session.hostname,
            'username': session.username,
            'os': session.os,
            'arch': session.arch,
            'is_privileged': session.is_privileged,
            'is_online': session.is_online(),
            'last_checkin': session.last_checkin.strftime('%Y-%m-%d %H:%M:%S') if session.last_checkin else None,
            'remote_address': session.remote_address,
            'transport': session.transport,
            'reconfigure_interval': session.reconfigure_interval,
        })

    return JsonResponse({'sessions': session_data})


@login_required
@require_GET
def api_jobs(request):
    """API endpoint for job data."""
    session_id = request.GET.get('session_id')
    status = request.GET.get('status')

    jobs = SliverJob.objects.filter(
        session__engagement__operator=request.user
    ).select_related('session', 'template').order_by('-created_at')

    if session_id:
        jobs = jobs.filter(session__session_id=session_id)
    if status:
        jobs = jobs.filter(status=status)
    engagement_id = request.GET.get('engagement_id')
    if engagement_id:
        jobs = jobs.filter(session__engagement_id=engagement_id)
    search = request.GET.get('search')
    if search:
        jobs = jobs.filter(
            dj_models.Q(job_id__icontains=search) |
            dj_models.Q(command__icontains=search) |
            dj_models.Q(session__session_id__icontains=search) |
            dj_models.Q(session__name__icontains=search)
        )

    # Serialize jobs
    job_data = []
    for job in jobs[:100]:  # Limit to prevent huge responses
        job_data.append({
            'job_id': job.job_id,
            'name': job.name,
            'session_id': job.session.session_id,
            'session_name': job.session.name,
            'engagement': job.session.engagement.name,
            'status': job.status,
            'command': job.command,
            'output': job.output[:200] + '...' if job.output and len(job.output) > 200 else job.output,
            'error': job.error[:200] + '...' if job.error and len(job.error) > 200 else job.error,
            'exit_code': job.exit_code,
            'started_at': job.started_at.strftime('%Y-%m-%d %H:%M:%S') if job.started_at else None,
            'completed_at': job.completed_at.strftime('%Y-%m-%d %H:%M:%S') if job.completed_at else None,
            'template': job.template.name if job.template else None,
            'duration': str(job.duration()) if job.duration() else None,
        })

    return JsonResponse({'jobs': job_data})


@login_required
@require_GET
def api_events(request):
    """API endpoint for real-time events."""
    engagement_id = request.GET.get('engagement_id')
    limit = int(request.GET.get('limit', 50))

    events = SliverEvent.objects.filter(
        teamserver__engagement_set__operator=request.user
    ).order_by('-timestamp')[:limit]

    if engagement_id:
        events = events.filter(engagement_id=engagement_id)

    event_data = []
    for event in events:
        event_data.append({
            'event_id': event.event_id,
            'event_type': event.event_type,
            'engagement': event.engagement.name if event.engagement else None,
            'session_id': event.session.session_id if event.session else None,
            'message': event.message,
            'data': event.data,
            'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        })

    return JsonResponse({'events': event_data})


@login_required
@require_GET
def api_loot(request):
    """API endpoint for loot data."""
    engagement_id = request.GET.get('engagement_id')
    session_id = request.GET.get('session_id')
    limit = int(request.GET.get('limit', 100))

    loot_items = Loot.objects.filter(
        engagement__operator=request.user
    ).select_related('session', 'engagement').order_by('-collected_at')

    if engagement_id:
        loot_items = loot_items.filter(engagement_id=engagement_id)
    if session_id:
        loot_items = loot_items.filter(session__session_id=session_id)

    loot_data = []
    for item in loot_items[:limit]:
        loot_data.append({
            'loot_id': item.loot_id,
            'name': item.name,
            'loot_type': item.loot_type,
            'session_id': item.session.session_id,
            'session_name': item.session.name,
            'engagement': item.engagement.name,
            'collected_at': item.collected_at.strftime('%Y-%m-%d %H:%M:%S') if item.collected_at else None,
            'size_bytes': item.size_bytes,
            'has_file': bool(item.local_path),
            'has_content': bool(item.content),
            'download_url': reverse('sliver:download_loot', args=[item.id]),
        })

    return JsonResponse({'loot': loot_data})


@login_required
@require_GET
def api_teamserver_status(request):
    """API endpoint for teamserver connection status."""
    teamserver_id = request.GET.get('teamserver_id')

    if teamserver_id:
        teamserver = get_object_or_404(Teamserver, id=teamserver_id)
        status = {'connected': teamserver.is_connected}
    else:
        # Check all teamservers
        teamservers = Teamserver.objects.all()
        status = {}
        for ts in teamservers:
            try:
                # Quick connectivity check
                client = get_sliver_client(ts)
                status[ts.id] = {'connected': True}
                ts.is_connected = True
                ts.last_connected = timezone.now()
                ts.save(update_fields=['is_connected', 'last_connected'])
            except:
                status[ts.id] = {'connected': False, 'error': 'Connection failed'}
                ts.is_connected = False
                ts.save(update_fields=['is_connected'])

    return JsonResponse({'status': status})


def _filter_jobs(request, jobs):
    """Apply query parameter filters to a job queryset."""
    status = request.GET.get('status', '')
    session_id = request.GET.get('session_id', '')
    engagement_id = request.GET.get('engagement_id', '')
    search = request.GET.get('search', '')

    if status:
        jobs = jobs.filter(status=status)
    if session_id:
        jobs = jobs.filter(session__session_id=session_id)
    if engagement_id:
        jobs = jobs.filter(session__engagement_id=engagement_id)
    if search:
        jobs = jobs.filter(
            dj_models.Q(job_id__icontains=search) |
            dj_models.Q(command__icontains=search) |
            dj_models.Q(session__session_id__icontains=search) |
            dj_models.Q(session__name__icontains=search)
        )

    filters = {
        'status': status,
        'session_id': session_id,
        'engagement_id': engagement_id,
        'search': search,
    }

    return jobs, filters


def _job_text_response(job, field, label, request):
    content = getattr(job, field) or ''
    if not content:
        content = f"No {label} captured."

    response = HttpResponse(content, content_type='text/plain')
    if request.GET.get('download') == '1':
        filename = f"{job.job_id}_{label}.txt"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# -----------------------------
# WebSocket Endpoint for Real-time Updates (placeholder)
# -----------------------------
@login_required
def events_stream(request):
    """Server-sent events for real-time updates."""
    # This would be implemented with Django Channels for WebSocket support
    # For now, return a simple JSON response
    recent_events = SliverEvent.objects.filter(
        teamserver__engagement_set__operator=request.user
    ).order_by('-timestamp')[:10]

    events_data = []
    for event in recent_events:
        events_data.append({
            'type': event.event_type,
            'message': event.message,
            'timestamp': event.timestamp.isoformat(),
        })

    return JsonResponse({'events': events_data})


@login_required
@require_POST
def refresh_sessions(request):
    """Manually refresh session data from Sliver teamserver."""
    engagement_id = request.POST.get('engagement_id')

    if engagement_id:
        engagement = get_object_or_404(
            Engagement,
            id=engagement_id,
            operator=request.user
        )
        engagements = [engagement]
    else:
        engagements = Engagement.objects.filter(operator=request.user)

    refreshed_count = 0
    errors = []

    for engagement in engagements:
        try:
            from .tasks import sync_sessions_task
            sync_sessions_task.delay(engagement_id=engagement.id, user_id=request.user.id)
            refreshed_count += 1
        except Exception as e:
            errors.append(f"Engagement '{engagement.name}': {str(e)}")

    if refreshed_count > 0:
        messages.success(request, f"Session refresh initiated for {refreshed_count} engagement(s).")
    if errors:
        messages.warning(request, f"Errors during refresh: {'; '.join(errors)}")

    return redirect(request.META.get('HTTP_REFERER', 'sliver:dashboard'))
