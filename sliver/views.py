from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
import json

# Import Sliver client and models
try:
    import sliver as sliver_client
    from .models import (
        Teamserver, Engagement, SliverSession, SliverJob, Loot,
        TaskTemplate, ImplantTemplate, SliverEvent, AuditLog, Watcher
    )
    from .utils import get_sliver_client, log_audit_action
    SLIVER_AVAILABLE = True
except ImportError:
    SLIVER_AVAILABLE = False


@login_required
def sliver_dashboard(request):
    """Main Sliver dashboard."""
    if not SLIVER_AVAILABLE:
        messages.error(request, "Sliver integration is not configured. Please install sliver-py.")
        return redirect('dashboard:home')

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

    # Add session/jobe counts to each engagement
    for engagement in engagements:
        engagement.active_sessions = engagement.get_active_sessions_count()
        engagement.completed_jobs = engagement.get_completed_jobs_count()

    return render(request, 'sliver/engagements.html', {
        'engagements': engagements
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
    recent_jobs = SliverJob.objects.filter(
        session__engagement=engagement
    ).order_by('-created_at')[:20]
    loot = Loot.objects.filter(engagement=engagement).order_by('-collected_at')[:10]
    events = SliverEvent.objects.filter(engagement=engagement).order_by('-timestamp')[:20]

    return render(request, 'sliver/engagement_detail.html', {
        'engagement': engagement,
        'sessions': sessions,
        'recent_jobs': recent_jobs,
        'loot': loot,
        'events': events,
        'active_sessions_count': sessions.filter(status='ACTIVE').count(),
        'pending_jobs_count': recent_jobs.filter(status__in=['PENDING', 'RUNNING']).count(),
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

    if engagement_id:
        engagement = get_object_or_404(
            Engagement,
            id=engagement_id,
            operator=request.user
        )
        sessions = sessions.filter(engagement=engagement)

    # Get online status for each session
    for session in sessions:
        session.is_online = session.is_online()

    # Get recent jobs for each session
    for session in sessions:
        session.recent_jobs = SliverJob.objects.filter(
            session=session
        ).order_by('-created_at')[:3]

    # Paginate
    paginator = Paginator(sessions, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'sliver/sessions.html', {
        'page_obj': page_obj,
        'engagement_id': engagement_id,
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

    return render(request, 'sliver/session_detail.html', {
        'session': session,
        'recent_jobs': recent_jobs,
        'loot': loot,
        'is_online': session.is_online(),
    })


@login_required
@require_POST
def execute_command(request, session_id):
    """Execute a command on a session."""
    session = get_object_or_404(
        SliverSession,
        session_id=session_id,
        engagement__operator=request.user
    )

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

        messages.success(request, f"Command sent to session '{session.name or session.session_id}'. Job ID: {job.job_id}")

    except Exception as e:
        messages.error(request, f"Failed to send command: {str(e)}")

    return redirect('sliver:session_detail', session_id=session_id)


@login_required
def job_list(request, session_id=None):
    """List jobs, optionally filtered by session."""
    jobs = SliverJob.objects.filter(
        session__engagement__operator=request.user
    ).select_related('session', 'template').order_by('-created_at')

    if session_id:
        session = get_object_or_404(
            SliverSession,
            session_id=session_id,
            engagement__operator=request.user
        )
        jobs = jobs.filter(session=session)

    # Paginate
    paginator = Paginator(jobs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'sliver/jobs.html', {
        'page_obj': page_obj,
        'session_id': session_id,
    })


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
def generate_implant(request):
    """Generate an implant/stager."""
    if request.method == 'POST':
        template_id = request.POST.get('template_id')
        engagement_id = request.POST.get('engagement_id')
        name = request.POST.get('name', f"implant_{timezone.now().strftime('%Y%m%d_%H%M%S')}")

        try:
            template = ImplantTemplate.objects.get(id=template_id)
            engagement = Engagement.objects.get(id=engagement_id, operator=request.user)

            # Launch async implant generation
            from .tasks import generate_implant_task
            task = generate_implant_task.delay(
                engagement_id=engagement.id,
                template_id=template.id,
                name=name,
                user_id=request.user.id
            )

            messages.success(request, f"Implant generation started for '{name}'.")
            return redirect('sliver:engagement_detail', engagement_id=engagement_id)

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

        messages.success(request, f"Task '{template.name}' started on session '{session.name or session.session_id}'.")

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
            'engagement': session.engagement.name,
            'status': session.status,
            'session_type': session.session_type,
            'hostname': session.hostname,
            'username': session.username,
            'os': session.os,
            'arch': session.arch,
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

    # Serialize jobs
    job_data = []
    for job in jobs[:100]:  # Limit to prevent huge responses
        job_data.append({
            'job_id': job.job_id,
            'name': job.name,
            'session_id': job.session.session_id,
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
