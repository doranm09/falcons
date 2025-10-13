"""
Server-Sent Events (SSE) streaming for MiniMega script execution.
Provides real-time streaming console output for VM provisioning scripts.
"""

import os
import json
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Generator, Dict, Any, Optional
import asyncio
from django.http import StreamingHttpResponse
from django.views.decorators.http import require_GET
from django.conf import settings
from .models import Node  # Import any needed models
import time


class StreamingMiniMegaRunner:
    """MiniMega runner that streams output via Server-Sent Events."""

    def __init__(self):
        self.run_output_dir = Path(settings.BASE_DIR) / "out" / "runs"
        self.state_dir = Path(settings.BASE_DIR) / "out" / "state"
        self.mm_scripts_dir = Path(settings.BASE_DIR) / "out" / "mm"
        self.run_output_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def run_with_stream(self, mm_file: str, label: str, dry_run: bool = False) -> Generator[str, None, None]:
        """
        Execute MiniMega script and yield SSE events with real-time output.

        Args:
            mm_file: Path to .mm script file
            label: Run label for tracking
            dry_run: If True, just print script content without execution

        Yields:
            SSE formatted strings for real-time streaming
        """
        # Security check: ensure mm_file is within expected directory
        script_path = Path(mm_file).resolve()
        mm_scripts_dir_resolved = self.mm_scripts_dir.resolve()

        if not str(script_path).startswith(str(mm_scripts_dir_resolved)):
            yield f"data: {json.dumps({'error': 'Invalid script path', 'done': True})}\n\n"
            return

        if not script_path.exists():
            yield f"data: {json.dumps({'error': f'Script {mm_file} not found', 'done': True})}\n\n"
            return

        timestamp = datetime.now().isoformat()
        run_log = {
            "success": False,
            "label": label,
            "mm_file": mm_file,
            "timestamp": timestamp,
            "dry_run": dry_run,
            "stdout": [],
            "stderr": [],
            "exit_code": None,
            "commands": []
        }

        # Send initial status
        yield f"data: {json.dumps({'status': 'started', 'label': label, 'timestamp': timestamp})}\n\n"

        commands_executed = []
        total_commands = 0

        try:
            # Count total commands first
            with open(script_path, 'r') as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    total_commands += 1

            current_command = 0
            yield f"data: {json.dumps({'status': 'counted', 'total_commands': total_commands})}\n\n"

            # Execute each command in the script
            with open(script_path, 'r') as f:
                for line in f:
                    command = line.strip()
                    if not command or command.startswith("#"):
                        continue  # skip empty lines and comments

                    current_command += 1
                    command_number = current_command

                    # Send command start event
                    yield f"data: {json.dumps({'type': 'command', 'command': command, 'number': command_number})}\n\n"

                    # Execute the command
                    try:
                        result = subprocess.run(
                            ["sudo", "minimega", "-e", command],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=300  # 5 minute timeout per command
                        )

                        # Stream stdout line by line
                        if result.stdout:
                            stdout_lines = result.stdout.strip().split('\n')
                            for line in stdout_lines:
                                if line.strip():
                                    run_log["stdout"].append(line)
                                    yield f"data: {json.dumps({'type': 'stdout', 'line': line, 'command': command_number})}\n\n"
                                    asyncio.sleep(0.01)  # Small delay for smooth streaming

                        # Stream stderr line by line
                        if result.stderr:
                            stderr_lines = result.stderr.strip().split('\n')
                            for line in stderr_lines:
                                if line.strip():
                                    run_log["stderr"].append(line)
                                    yield f"data: {json.dumps({'type': 'stderr', 'line': line, 'command': command_number})}\n\n"
                                    asyncio.sleep(0.01)  # Small delay for smooth streaming

                        # Send command completion
                        commands_executed.append({
                            "command": command,
                            "exit_code": result.returncode,
                            "success": result.returncode == 0
                        })

                        yield f"data: {json.dumps({'type': 'command_complete', 'command': command_number, 'exit_code': result.returncode})}\n\n"

                    except subprocess.TimeoutExpired:
                        error_msg = f"Command timed out after 300 seconds: {command}"
                        run_log["stderr"].append(error_msg)
                        yield f"data: {json.dumps({'type': 'stderr', 'line': error_msg, 'command': command_number})}\n\n"

                    except Exception as e:
                        error_msg = f"Error executing command: {str(e)}"
                        run_log["stderr"].append(error_msg)
                        yield f"data: {json.dumps({'type': 'stderr', 'line': error_msg, 'command': command_number})}\n\n"

            # All commands completed
            run_log["commands"] = commands_executed
            run_log["success"] = all(cmd["success"] for cmd in commands_executed)
            run_log["exit_code"] = 0 if run_log["success"] else 1

            # Send completion status
            yield f"data: {json.dumps({'status': 'completed', 'success': run_log['success'], 'total_commands': len(commands_executed)})}\n\n"

        except Exception as e:
            run_log["success"] = False
            run_log["stderr"].append(str(e))
            run_log["exit_code"] = 1
            yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"

        # Save run log
        self._save_run_log(run_log)

        # Update inventory state (this would be done by the MinimegaRunner normally)
        self._update_inventory_state(label)

        # Final done event
        yield f"data: {json.dumps({'done': True, 'success': run_log['success']})}\n\n"

    def _save_run_log(self, result: Dict[str, Any]) -> None:
        """Save execution result to run log."""
        log_file = self.run_output_dir / f"run_{result['label']}_{result['timestamp'][:19].replace(':', '-')}.json"

        with open(log_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)

    def _update_inventory_state(self, label: str) -> None:
        """Update the inventory state with current VMs (placeholder for actual implementation)."""
        # This would typically query minimega for current VMs and update out/state/inventory.json
        # For now, just ensure the file exists
        inventory_file = self.state_dir / "inventory.json"
        if inventory_file.exists():
            try:
                with open(inventory_file, 'r') as f:
                    inventory = json.load(f)
            except json.JSONDecodeError:
                inventory = {}
        else:
            inventory = {}

        # Add a basic entry for this run (in real implementation, this would be populated by actual VM data)
        if label not in inventory:
            inventory[label] = [{
                "label": label,
                "timestamp": datetime.now().isoformat(),
                "vms": []  # Would be populated with actual VM data
            }]

        with open(inventory_file, 'w') as f:
            json.dump(inventory, f, indent=2, default=str)


@require_GET
def stream_minimega_execution(request):
    """
    SSE endpoint for streaming MiniMega script execution.
    Expects GET parameters: script_filename, label, dry_run
    """
    script_filename = request.GET.get('script_filename')
    label = request.GET.get('label', 'sse-deploy')
    dry_run = request.GET.get('dry_run', 'false').lower() == 'true'

    if not script_filename:
        return StreamingHttpResponse(
            f"data: {json.dumps({'error': 'script_filename parameter required', 'done': True})}\n\n",
            content_type='text/event-stream'
        )

    # Security: validate script filename
    from pathlib import Path
    runner = StreamingMiniMegaRunner()
    script_path = runner.mm_scripts_dir / script_filename

    mm_scripts_dir_resolved = runner.mm_scripts_dir.resolve()
    script_path_resolved = script_path.resolve()

    if not str(script_path_resolved).startswith(str(mm_scripts_dir_resolved)):
        return StreamingHttpResponse(
            f"data: {json.dumps({'error': 'Invalid script path', 'done': True})}\n\n",
            content_type='text/event-stream'
        )

    if not script_path.exists():
        return StreamingHttpResponse(
            f"data: {json.dumps({'error': f'Script {script_filename} not found', 'done': True})}\n\n",
            content_type='text/event-stream'
        )

    def event_generator():
        yield f"data: {json.dumps({'status': 'connecting'})}\n\n"
        for event in runner.run_with_stream(str(script_path), label, dry_run):
            yield event

    response = StreamingHttpResponse(
        event_generator(),
        content_type='text/event-stream'
    )

    # SSE headers
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    return response


# Async version using asyncio (Django 3.1+)
async def stream_minimega_execution_async(request):
    """
    Async version of SSE streaming for MiniMega execution.
    Better for handling long-running executions with proper async support.
    """
    script_filename = request.GET.get('script_filename')
    label = request.GET.get('label', 'sse-async-deploy')
    dry_run = request.GET.get('dry_run', 'false').lower() == 'true'

    if not script_filename:
        async def error_gen():
            yield f"data: {json.dumps({'error': 'script_filename parameter required', 'done': True})}\n\n"
        return StreamingHttpResponse(
            error_gen(),
            content_type='text/event-stream'
        )

    # Security: validate script filename
    from pathlib import Path
    runner = StreamingMiniMegaRunner()
    script_path = runner.mm_scripts_dir / script_filename

    mm_scripts_dir_resolved = runner.mm_scripts_dir.resolve()
    script_path_resolved = script_path.resolve()

    if not str(script_path_resolved).startswith(str(mm_scripts_dir_resolved)):
        async def error_gen():
            yield f"data: {json.dumps({'error': 'Invalid script path', 'done': True})}\n\n"
        return StreamingHttpResponse(
            error_gen(),
            content_type='text/event-stream'
        )

    if not script_path.exists():
        async def error_gen():
            yield f"data: {json.dumps({'error': f'Script {script_filename} not found', 'done': True})}\n\n"
        return StreamingHttpResponse(
            error_gen(),
            content_type='text/event-stream'
        )

    async def async_event_generator():
        yield f"data: {json.dumps({'status': 'connecting'})}\n\n"

        # Run in thread pool to avoid blocking the event loop
        import concurrent.futures
        loop = asyncio.get_event_loop()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Convert sync generator to async
            sync_gen = runner.run_with_stream(str(script_path), label, dry_run)
            for event in sync_gen:
                yield event
                await asyncio.sleep(0.001)  # Small async delay

    response = StreamingHttpResponse(
        async_event_generator(),
        content_type='text/event-stream'
    )

    # SSE headers
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    return response
