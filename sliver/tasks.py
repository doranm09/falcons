import base64
import hashlib
import json
import shutil
from pathlib import Path

from celery import shared_task
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.utils import timezone

from .models import *

try:
    import sliver as sliver_client
    from .utils import get_sliver_client, get_artifact_base_dir, log_audit_action
except ImportError:
    sliver_client = None
    get_sliver_client = None
    log_audit_action = None
    get_artifact_base_dir = None


def _normalize_sliver_response(response):
    if isinstance(response, (bytes, bytearray)):
        try:
            response = response.decode()
        except Exception:
            return {"raw": str(response)}
    if isinstance(response, str):
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"raw": response}
    if isinstance(response, dict):
        return response
    return {"raw": str(response)}


def _extract_artifact_bytes(payload):
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        try:
            return base64.b64decode(payload, validate=True)
        except Exception:
            return payload.encode()
    return None


@shared_task(bind=True)
def sync_sessions_task(self, engagement_id, user_id):
    """Sync session data from Sliver teamserver."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    try:
        engagement = Engagement.objects.get(id=engagement_id)
        client = get_sliver_client(engagement.teamserver)

        # Get sessions from Sliver
        sessions_resp = client.rpc.sessions()
        sessions_data = json.loads(sessions_resp)

        synced_count = 0
        for session_data in sessions_data.get('sessions', []):
            session_id = session_data.get('ID')

            # Update or create session
            session, created = SliverSession.objects.update_or_create(
                session_id=session_id,
                defaults={
                    'name': session_data.get('Name', ''),
                    'engagement': engagement,
                    'status': 'ACTIVE' if session_data.get('IsDead', False) == False else 'DEAD',
                    'session_type': 'BEACON' if session_data.get('IsBeacon', False) else 'SESSION',
                    'hostname': session_data.get('Hostname', ''),
                    'username': session_data.get('Username', ''),
                    'uid': session_data.get('UID', ''),
                    'gid': session_data.get('GID', ''),
                    'os': session_data.get('OS', ''),
                    'arch': session_data.get('Arch', ''),
                    'pid': session_data.get('PID'),
                    'remote_address': session_data.get('RemoteAddress'),
                    'version': session_data.get('Version', ''),
                    'is_privileged': session_data.get('IsPrivileged', False),
                    'transport': session_data.get('Transport', ''),
                    'encoder': session_data.get('Encoder', ''),
                    'reconfigure_interval': session_data.get('ReconnectIntervalSeconds', 60),
                    'last_checkin': timezone.now(),
                }
            )
            if created:
                synced_count += 1

        return {'synced_sessions': synced_count, 'engagement': engagement.name}

    except Exception as e:
        return {'error': str(e)}


@shared_task(bind=True)
def execute_sliver_command_task(self, session_id, command, user_id=None, parameters=None, template_id=None):
    """Execute a command on a Sliver session."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    try:
        # Get session and related data
        session = SliverSession.objects.get(session_id=session_id)
        user = get_user_model().objects.get(id=user_id) if user_id else None
        template = TaskTemplate.objects.get(id=template_id) if template_id else None

        client = get_sliver_client(session.engagement.teamserver)

        # Combine command with parameters if provided
        full_command = command
        if parameters:
            # Simple parameter substitution - extend as needed
            for key, value in parameters.items():
                full_command = full_command.replace(f'{{{key}}}', str(value))

        # Execute command
        if 'shell' in command.lower() or len(command) <= 200:
            # Use shell task for simple commands
            response = client.rpc.shell(session_id, full_command, timeout=30)
        else:
            # For more complex operations, might need to create task
            response = client.rpc.task(session_id, 'shell', [full_command], timeout=60)

        # Parse response
        result_data = json.loads(response) if isinstance(response, str) else response
        output = result_data.get('output', '')
        error = result_data.get('error', '')
        exit_code = result_data.get('exit_code', 0)

        # Update job record
        job_id = f"job_{self.request.id}"
        job, created = SliverJob.objects.get_or_create(
            job_id=job_id,
            defaults={
                'session': session,
                'template': template,
                'status': 'RUNNING',
                'command': full_command,
                'parameters': parameters or {},
                'operator': user,
                'started_at': timezone.now(),
            }
        )

        if not created:
            job.status = 'RUNNING'

        job.output = output
        job.error = error
        job.exit_code = exit_code
        job.completed_at = timezone.now()
        job.status = 'COMPLETED' if exit_code == 0 else 'FAILED'
        job.save()

        # Log audit action
        log_audit_action(
            action='COMMAND_EXECUTED',
            user=user,
            teamserver=session.engagement.teamserver,
            session=session,
            job=job,
            details={
                'command': full_command,
                'exit_code': exit_code,
                'has_output': bool(output),
                'has_error': bool(error)
            }
        )

        return {
            'job_id': job_id,
            'output': output,
            'error': error,
            'exit_code': exit_code,
            'status': job.status
        }

    except Exception as e:
        # Update job with error
        try:
            job = SliverJob.objects.get(job_id=f"job_{self.request.id}")
            job.status = 'FAILED'
            job.error = str(e)
            job.completed_at = timezone.now()
            job.save()
        except:
            pass

        return {'error': str(e)}


@shared_task(bind=True)
def generate_implant_task(self, engagement_id, template_id, name, user_id, artifact_id=None):
    """Generate an implant/stager asynchronously."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    artifact = None
    try:
        engagement = Engagement.objects.get(id=engagement_id)
        template = ImplantTemplate.objects.get(id=template_id)
        user = get_user_model().objects.get(id=user_id)
        client = get_sliver_client(engagement.teamserver)

        # Generate implant using template configuration
        config = template.config
        if artifact_id:
            artifact = ImplantArtifact.objects.filter(id=artifact_id).first()
        if not artifact:
            artifact = ImplantArtifact.objects.create(
                name=name,
                file_name='',
                engagement=engagement,
                template=template,
                generated_by=user,
                status=ImplantArtifact.Status.RUNNING,
            )
        else:
            artifact.status = ImplantArtifact.Status.RUNNING
            artifact.save(update_fields=['status'])

        # This would need to be adapted based on the actual Sliver implant generation API
        implant_resp = client.rpc.generate(name=name, config=config)
        implant_data = _normalize_sliver_response(implant_resp)

        artifact.metadata = implant_data

        base_dir = get_artifact_base_dir() if get_artifact_base_dir else None
        if base_dir is None:
            raise RuntimeError("Artifact storage is not configured")
        base_dir = Path(base_dir)
        output_dir = base_dir / f"engagement_{engagement.id}" / timezone.now().strftime("%Y%m%d")
        output_dir.mkdir(parents=True, exist_ok=True)

        file_name = artifact.file_name or name
        if '.' not in Path(file_name).name:
            ext = template.file_format or template.config.get('format') or 'bin'
            file_name = f"{file_name}.{ext.lstrip('.')}"

        local_path = output_dir / file_name

        file_bytes = None
        for key in ('data', 'file', 'content', 'payload'):
            if key in implant_data:
                file_bytes = _extract_artifact_bytes(implant_data.get(key))
                if file_bytes:
                    break

        if file_bytes:
            local_path.write_bytes(file_bytes)
        else:
            candidate_path = implant_data.get('file_path') or implant_data.get('path')
            if candidate_path and Path(candidate_path).is_file():
                shutil.copyfile(candidate_path, local_path)

        if local_path.is_file():
            artifact.relative_path = str(local_path.relative_to(base_dir))
            artifact.file_name = local_path.name
            artifact.file_size = local_path.stat().st_size
            artifact.sha256 = hashlib.sha256(local_path.read_bytes()).hexdigest()
            artifact.status = ImplantArtifact.Status.READY
            artifact.error_message = ""
        else:
            artifact.status = ImplantArtifact.Status.FAILED
            artifact.error_message = "Sliver API did not return implant data or accessible file path."

        # Log audit action
        log_audit_action(
            action='IMPLANT_GENERATED',
            user=user,
            teamserver=engagement.teamserver,
            engagement=engagement,
            details={
                'implant_name': name,
                'template': template.name,
                'os': template.operating_system,
                'arch': template.architecture
            }
        )
        artifact.save()

        return {
            'implant_name': name,
            'file_path': artifact.relative_path,
            'size': artifact.file_size,
            'template': template.name,
            'status': artifact.status,
        }

    except Exception as e:
        if artifact:
            artifact.status = ImplantArtifact.Status.FAILED
            artifact.error_message = str(e)
            artifact.save(update_fields=['status', 'error_message', 'updated_at'])
        elif artifact_id:
            ImplantArtifact.objects.filter(id=artifact_id).update(
                status=ImplantArtifact.Status.FAILED,
                error_message=str(e),
            )
        return {'error': str(e)}


@shared_task(bind=True)
def collect_loot_task(self, session_id, user_id, loot_type='ALL'):
    """Collect loot from a session."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    try:
        session = SliverSession.objects.get(session_id=session_id)
        # System-triggered workflows (watchers/sync jobs) may run without a user.
        user = get_user_model().objects.filter(id=user_id).first() if user_id else None
        client = get_sliver_client(session.engagement.teamserver)

        # Get loot from session
        loot_resp = client.rpc.loot()
        loot_data = json.loads(loot_resp)

        collected_count = 0
        for loot_item in loot_data.get('loot', []):
            loot_session_id = loot_item.get('SessionID') or loot_item.get('session_id')
            if loot_session_id != session_id:
                continue

            loot_id = loot_item.get('LootID') or loot_item.get('loot_id')
            loot_name = loot_item.get('Name') or loot_item.get('name') or ''
            loot_type_value = (loot_item.get('Type') or loot_item.get('type') or 'OTHER').upper()
            file_path = loot_item.get('FilePath') or loot_item.get('file_path') or ''
            content = loot_item.get('Data') or loot_item.get('data') or ''
            size_bytes = loot_item.get('Size') or loot_item.get('size') or 0

            # Create loot record
            loot_obj = Loot.objects.create(
                loot_id=loot_id,
                name=loot_name,
                loot_type=loot_type_value,
                session=session,
                engagement=session.engagement,
                file_path=file_path,
                content=content if isinstance(content, str) else '',
                size_bytes=size_bytes or 0,
                operator=user
            )

            payload = None
            for key in ('Data', 'data', 'Content', 'content', 'Payload', 'payload'):
                if key in loot_item:
                    payload = loot_item.get(key)
                    break

            file_bytes = _extract_artifact_bytes(payload) if payload is not None else None
            if file_bytes:
                candidate_name = loot_name or Path(file_path).name or f"loot_{loot_id or loot_obj.id}"
                safe_name = Path(candidate_name).name or f"loot_{loot_obj.id}"
                loot_obj.local_path.save(safe_name, ContentFile(file_bytes), save=False)
                loot_obj.size_bytes = len(file_bytes)
                loot_obj.save(update_fields=['local_path', 'size_bytes', 'updated_at'])

            collected_count += 1

        # Log audit action
        log_audit_action(
            action='LOOT_DOWNLOADED',
            user=user,
            teamserver=session.engagement.teamserver,
            session=session,
            details={'count': collected_count}
        )

        return {'collected_loot': collected_count, 'session': session.session_id}

    except Exception as e:
        return {'error': str(e)}


@shared_task(bind=True)
def monitor_events_task(self):
    """Monitor Sliver events and store them in database."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    try:
        teamservers = Teamserver.objects.filter(is_connected=True)
        events_processed = 0

        for ts in teamservers:
            try:
                client = get_sliver_client(ts)

                # Get recent events (this is a placeholder - actual API may differ)
                events_resp = client.rpc.events()
                events_data = json.loads(events_resp)

                for event_data in events_data.get('events', []):
                    event_id = event_data.get('EventID')

                    # Get related objects
                    engagement = None
                    session = None

                    if event_data.get('SessionID'):
                        try:
                            session = SliverSession.objects.get(session_id=event_data['SessionID'])
                            engagement = session.engagement
                        except SliverSession.DoesNotExist:
                            pass

                    # Create event record
                    event, created = SliverEvent.objects.update_or_create(
                        event_id=event_id,
                        defaults={
                            'event_type': event_data.get('EventType', 'UNKNOWN'),
                            'teamserver': ts,
                            'engagement': engagement,
                            'session': session,
                            'data': event_data,
                            'message': event_data.get('Message', ''),
                            'timestamp': timezone.now(),
                        }
                    )

                    if created:
                        events_processed += 1

                        # Trigger watchers if applicable
                        watchers = Watcher.objects.filter(
                            engagement=engagement,
                            is_active=True
                        )

                        for watcher in watchers:
                            # Check if event matches watcher filter
                            if matches_event_filter(watcher.event_filter, event_data):
                                # Trigger automated response
                                trigger_watcher_response.delay(watcher.id, event_id)

            except Exception as e:
                # Log teamserver-specific errors
                pass

        return {'events_processed': events_processed}

    except Exception as e:
        return {'error': str(e)}


@shared_task(bind=True)
def trigger_watcher_response(self, watcher_id, event_id):
    """Execute automated responses for watcher triggers."""
    try:
        watcher = Watcher.objects.get(id=watcher_id)
        event = SliverEvent.objects.get(event_id=event_id)

        # Execute automated response based on watcher action_config
        actions = watcher.action_config.get('actions', [])

        for action in actions:
            action_type = action.get('type')

            if action_type == 'command':
                # Execute command on session
                session_id = event.session.session_id if event.session else None
                if session_id:
                    execute_sliver_command_task.delay(
                        session_id=session_id,
                        command=action.get('command', ''),
                        parameters=action.get('parameters', {}),
                        user_id=None  # System action
                    )
            elif action_type == 'collect_loot':
                # Collect loot from session
                if event.session:
                    collect_loot_task.delay(
                        session_id=event.session.session_id,
                        user_id=None  # System action
                    )
            elif action_type == 'alert':
                # Send alert (could integrate with notification system)
                pass

    except Exception as e:
        # Log watcher execution errors
        pass


def matches_event_filter(event_filter, event_data):
    """Check if event matches the given filter criteria."""
    # Simple filter matching - extend as needed
    if not event_filter:
        return False

    for key, expected_value in event_filter.items():
        if key not in event_data:
            return False
        actual_value = event_data[key]

        if isinstance(expected_value, str) and expected_value != actual_value:
            return False
        elif isinstance(expected_value, list) and actual_value not in expected_value:
            return False
        # Add more sophisticated matching logic as needed

    return True


@shared_task(bind=True)
def sync_loot_task(self, engagement_id=None):
    """Sync loot data from all teamserver connections."""
    if not sliver_client or not get_sliver_client:
        return {'error': 'Sliver client not available'}

    try:
        if engagement_id:
            engagements = [Engagement.objects.get(id=engagement_id)]
        else:
            engagements = Engagement.objects.filter(status='ACTIVE')

        total_loot = 0
        for engagement in engagements:
            try:
                sync_sessions_task.delay(engagement.id, None)  # Refresh sessions first
                client = get_sliver_client(engagement.teamserver)

                # Sync loot
                loot_resp = client.rpc.loot()
                loot_data = json.loads(loot_resp)

                for loot_item in loot_data.get('loot', []):
                    # Skip if already exists
                    if Loot.objects.filter(loot_id=loot_item.get('LootID')).exists():
                        continue

                    # Find associated session
                    session = None
                    if loot_item.get('SessionID'):
                        try:
                            session = SliverSession.objects.get(
                                session_id=loot_item['SessionID'],
                                engagement=engagement
                            )
                        except SliverSession.DoesNotExist:
                            pass

                    if session:  # Only create loot for sessions we know about
                        Loot.objects.create(
                            loot_id=loot_item.get('LootID'),
                            name=loot_item.get('Name', ''),
                            loot_type=loot_item.get('Type', 'OTHER').upper(),
                            session=session,
                            engagement=engagement,
                            file_path=loot_item.get('FilePath', ''),
                            content=loot_item.get('Data', ''),
                            size_bytes=loot_item.get('Size', 0),
                            collected_at=timezone.now()
                        )
                        total_loot += 1

            except Exception as e:
                # Log per-engagement errors
                pass

        return {'total_loot_synced': total_loot}

    except Exception as e:
        return {'error': str(e)}
