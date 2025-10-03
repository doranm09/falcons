from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node, ScanRun, AgentCommand, CommandResult, NodeInterface, AgentStatus
import ipaddress
import subprocess
import requests
from django.http import JsonResponse
from .tasks import scan_network_task, launch_openvas_scan_task
from celery.result import AsyncResult
from .models import Node, Link
from .utils import dijkstra, list_interfaces
from django.views.decorators.http import require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import os
from django.conf import settings
from django.db import transaction
from ipaddress import ip_network
import time

SNIFFER_BASE_URL = 'http://localhost:5050'

def home(request):
    nodes = Node.objects.all().values('ip_address', 'name')
    scan_history = ScanRun.objects.all().order_by('-timestamp')[:10]  # limit to last 10
    return render(request, 'dashboard/home.html', {
        'nodes': nodes,
        'scan_history': scan_history,
        'timestamp': now().timestamp()
    })


def start_scan_ajax(request):
    print(f"[DEBUG] Method received: {request.method}")
    if request.method == "POST":
        cidr = request.POST.get("cidr")
        print(f"[DEBUG] Received CIDR: {cidr}")
        task = scan_network_task.delay(cidr)
        print(f"[DEBUG] Task dispatched: {task.id}")
        return JsonResponse({"task_id": task.id})
    else:
        return JsonResponse({"error": "Only POST allowed"}, status=405)


def check_scan_status(request, task_id):
    result = AsyncResult(str(task_id))

    # Fetch all nodes with interfaces
    nodes = Node.objects.all()
    node_data = []
    for node in nodes:
        node_data.append({
            "ip_address": node.ip_address,
            "name": node.name,
            "status": node.status,
            "description": node.description,
            "last_heartbeat": node.last_heartbeat,
            "interfaces": [
                {
                    "name": iface.name,
                    "ip": iface.ip,
                    "mac": iface.mac
                } for iface in node.interfaces.all()
            ]
        })

    response = {
        "state": result.state,
        "nodes": node_data
    }

    if result.state in ['PENDING', 'STARTED']:
        response["progress"] = "Scan is running..."

    if result.ready():
        try:
            result_val = result.result
            if isinstance(result_val, Exception):
                response["result"] = str(result_val)
            else:
                response["result"] = result_val
        except Exception as e:
            response["result"] = f"Error fetching result: {str(e)}"

    return JsonResponse(response)

def shortest_paths(request, start_node_id):
    nodes = Node.objects.all()
    links = Link.objects.all()
    distances = dijkstra(nodes, links, int(start_node_id))

    # Convert keys to strings or extract node info
    distances_serialized = {
        str(node_id): distance for node_id, distance in distances.items()
    }

    return JsonResponse(distances_serialized, encoder=DjangoJSONEncoder, safe=False)

def history(request):
    from .models import Vulnerability
    runs = ScanRun.objects.all().order_by('-timestamp')

    run_data = []
    for run in runs:
        vulns = Vulnerability.objects.filter(scan_run=run)
        run_data.append({
            "run": run,
            "vuln_count": vulns.count(),
        })

    return render(request, 'dashboard/history.html', {'runs': runs})

def graph_data(request):
    latest_scan = ScanRun.objects.order_by('-timestamp').first()
    if not latest_scan:
        return JsonResponse([], safe=False)

    nodes = Node.objects.filter(scan_run=latest_scan)
    links = Link.objects.filter(scan_run=latest_scan)

    elements = []

    for node in nodes:
        # Get cyber template data for enhanced node information
        cyber_data = node.get_cyber_template_data()

        elements.append({
            "data": {
                "id": str(node.id),
                "label": node.name,
                "ip": node.ip_address,
                "status": node.status,
                "cyber_data": cyber_data,
                "has_cyber_data": any(cyber_data.values()),
            }
        })

    for link in links:
        elements.append({
            "data": {
                "source": str(link.source.id),
                "target": str(link.destination.id),
                "weight": f"{link.weight:.2f}",  # for label
                "raw_weight": link.weight        # for color mapping
            }
        })


    return JsonResponse(elements, safe=False)


@require_GET
def node_details(request, node_id):
    """Detailed view for a specific node with cyber template data."""
    try:
        node = Node.objects.get(id=node_id)
    except Node.DoesNotExist:
        return JsonResponse({"error": "Node not found"}, status=404)

    # Get related agent status if available
    agent_status = None
    if node.agent_id:
        try:
            agent_status = AgentStatus.objects.get(agent_id=node.agent_id)
        except AgentStatus.DoesNotExist:
            pass

    node_data = {
        "id": node.id,
        "name": node.name,
        "ip_address": node.ip_address,
        "status": node.status,
        "description": node.description,
        "last_heartbeat": node.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if node.last_heartbeat else "Never",
        "agent_id": node.agent_id,
        "cyber_data": node.get_cyber_template_data(),
        "system_info": {
            "cpu_count": node.cpu_count,
            "memory_total": node.memory_total,
            "platform_info": node.platform_info,
        },
        "interfaces": [
            {
                "name": iface.name,
                "ip": iface.ip,
                "mac": iface.mac
            } for iface in node.interfaces.all()
        ],
        "agent_status": {
            "hostname": agent_status.hostname if agent_status else None,
            "os_type": agent_status.os_type if agent_status else None,
            "os_version": agent_status.os_version if agent_status else None,
            "status": agent_status.status if agent_status else None,
            "last_heartbeat": agent_status.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent_status and agent_status.last_heartbeat else None,
        } if agent_status else None
    }

    return JsonResponse(node_data)

def get_interfaces(request):
    return JsonResponse({'interfaces': list_interfaces()})

@csrf_exempt
def start_listener(request):
    if request.method == 'POST':
        iface = request.POST.get("interface")
        try:
            res = requests.post(f"{SNIFFER_BASE_URL}/start", json={"interface": iface})
            return JsonResponse(res.json(), status=res.status_code)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def stop_listener(request):
    try:
        res = requests.post(f"{SNIFFER_BASE_URL}/stop")
        return JsonResponse(res.json(), status=res.status_code)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@require_GET
def get_scan_history(request):
    recent = ScanRun.objects.all().order_by('-timestamp')[:10]
    history = [{
        "timestamp": run.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "cidr": run.cidr,
        "status": run.status,
        "summary": run.result_summary or "-"
    } for run in recent]
    return JsonResponse({"history": history})

@csrf_exempt
@require_http_methods(["POST"])
def agent_report(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    hostname = data.get("hostname")
    interfaces = data.get("interfaces", [])
    ip = interfaces[0].get("ip", "127.0.0.1") if interfaces else "127.0.0.1"

    # Update or create AgentStatus record
    agent_status, created = AgentStatus.objects.update_or_create(
        agent_id=agent_id,
        defaults={
            "hostname": hostname,
            "ip_address": ip,
            "status": "online",
            "os_type": data.get("os", ""),
            "os_version": data.get("os_version", ""),
            "platform": data.get("platform", ""),
            "cpu_count": data.get("cpu_count"),
            "memory_total": data.get("memory_total"),
            "interfaces": interfaces,
            "agent_version": data.get("agent_version", ""),
            "last_version_check": now(),
        }
    )

    # Record the heartbeat
    agent_status.record_heartbeat(data)

    # Also update/create Node record for backward compatibility
    node, _ = Node.objects.update_or_create(
        agent_id=agent_id,
        defaults={
            "name": hostname,
            "ip_address": ip,
            "description": f"Reported from agent {agent_id}",
            "status": "online",
            "cpu_count": data.get("cpu_count"),
            "memory_total": data.get("memory_total"),
            "platform_info": data.get("platform"),
        }
    )

    # Clear old interfaces
    node.interfaces.all().delete()

    # Save current interfaces
    for iface in interfaces:
        NodeInterface.objects.create(
            node=node,
            name=iface.get("name", "unknown"),
            ip=iface.get("ip", "0.0.0.0"),
            mac=iface.get("mac", "00:00:00:00:00:00")
        )

    return JsonResponse({"status": "ok", "node_id": node.id, "agent_status_id": agent_status.id})


@csrf_exempt
@require_http_methods(["POST"])
def agent_cyber_report(request):
    """Handle cyber template data from agents."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    cyber_data = data.get("cyber_data")

    if not agent_id or not cyber_data:
        return JsonResponse({"error": "agent_id and cyber_data are required"}, status=400)

    try:
        node = Node.objects.get(agent_id=agent_id)
        node.update_cyber_data(cyber_data)
        return JsonResponse({"status": "cyber_data_updated"})
    except Node.DoesNotExist:
        return JsonResponse({"error": "Node not found"}, status=404)

@require_http_methods(["GET"])
def agent_commands(request):
    agent_id = request.GET.get("agent_id")
    commands = AgentCommand.objects.filter(agent_id=agent_id, acknowledged=False)
    serialized = [
        {"id": cmd.id, "action": cmd.action, "parameters": cmd.parameters}
        for cmd in commands
    ]
    # mark them as acknowledged
    commands.update(acknowledged=True)
    return JsonResponse({"commands": serialized})


@csrf_exempt
@require_http_methods(["POST"])
def agent_command_result(request):
    data = json.loads(request.body)
    agent_id = data.get("agent_id")
    command_id = data.get("command_id")
    output = data.get("output")

    try:
        cmd = AgentCommand.objects.get(id=command_id)
    except AgentCommand.DoesNotExist:
        return JsonResponse({"error": "Command not found"}, status=404)

    CommandResult.objects.create(
        agent_id=agent_id,
        command=cmd,
        output=output
    )

    return JsonResponse({"status": "received"})


# -----------------------------
# Agent Monitoring Views
# -----------------------------
def agent_monitoring(request):
    """Main agent monitoring dashboard."""
    agents = AgentStatus.objects.all().order_by('-last_heartbeat')

    # Update status for all agents based on heartbeat timing
    for agent in agents:
        agent.update_status()

    # Get recent command results
    recent_results = CommandResult.objects.all().order_by('-timestamp')[:20]

    # Get pending commands
    pending_commands = AgentCommand.objects.filter(acknowledged=False).order_by('-created')[:10]

    return render(request, 'dashboard/agent_monitoring.html', {
        'agents': agents,
        'recent_results': recent_results,
        'pending_commands': pending_commands,
        'total_agents': agents.count(),
        'online_agents': agents.filter(status='online').count(),
        'offline_agents': agents.filter(status='offline').count(),
    })


@require_GET
def agent_status_api(request):
    """API endpoint for real-time agent status updates."""
    agents = AgentStatus.objects.all().order_by('-last_heartbeat')

    # Update status for all agents
    for agent in agents:
        agent.update_status()

    agent_data = []
    for agent in agents:
        agent_data.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "status": agent.status,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "cpu_count": agent.cpu_count,
            "memory_total": agent.memory_total,
            "agent_version": agent.agent_version or "Unknown",
            "last_heartbeat": agent.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent.last_heartbeat else "Never",
            "uptime": str(agent.get_uptime()) if agent.get_uptime() else "Unknown",
            "consecutive_failures": agent.consecutive_failures,
            "interfaces": agent.interfaces or [],
        })

    return JsonResponse({
        "agents": agent_data,
        "timestamp": now().strftime('%Y-%m-%d %H:%M:%S')
    })


@csrf_exempt
@require_http_methods(["POST"])
def send_agent_command(request):
    """Send a command to a specific agent."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    action = data.get("action")
    parameters = data.get("parameters", {})

    if not agent_id or not action:
        return JsonResponse({"error": "agent_id and action are required"}, status=400)

    # Check if agent exists
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    # Create command
    command = AgentCommand.objects.create(
        agent_id=agent_id,
        action=action,
        parameters=parameters
    )

    # Update agent's last_command_sent timestamp
    agent.last_command_sent = now()
    agent.save(update_fields=["last_command_sent"])

    return JsonResponse({
        "status": "command_sent",
        "command_id": command.id,
        "agent_id": agent_id,
        "action": action
    })


@require_GET
def agent_details(request, agent_id):
    """Detailed view for a specific agent."""
    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
        agent.update_status()  # Update status before displaying
    except AgentStatus.DoesNotExist:
        messages.error(request, f"Agent {agent_id} not found")
        return redirect('dashboard:agent_monitoring')

    # Get command history for this agent
    commands = AgentCommand.objects.filter(agent_id=agent_id).order_by('-created')[:20]
    results = CommandResult.objects.filter(agent_id=agent_id).order_by('-timestamp')[:20]

    return render(request, 'dashboard/agent_details.html', {
        'agent': agent,
        'commands': commands,
        'results': results,
    })


@require_GET
def agent_command_history(request, agent_id):
    """Get command history for a specific agent."""
    commands = AgentCommand.objects.filter(agent_id=agent_id).order_by('-created')[:50]
    results = CommandResult.objects.filter(agent_id=agent_id).order_by('-timestamp')[:50]

    history = []
    for cmd in commands:
        history.append({
            "type": "command",
            "id": cmd.id,
            "action": cmd.action,
            "parameters": cmd.parameters,
            "created": cmd.created.strftime('%Y-%m-%d %H:%M:%S'),
            "acknowledged": cmd.acknowledged,
        })

    for result in results:
        history.append({
            "type": "result",
            "id": result.id,
            "command_id": result.command.id,
            "output": result.output[:200] + "..." if len(result.output) > 200 else result.output,
            "timestamp": result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        })

    # Sort by timestamp
    history.sort(key=lambda x: x.get('created') or x.get('timestamp'), reverse=True)

    return JsonResponse({"history": history[:50]})


def vulnerability_detail(request, scan_id):
    scan = ScanRun.objects.get(id=scan_id)
    vulns = scan.vulnerabilities.all().order_by("-severity")
    return render(request, "dashboard/vulnerabilities.html", {
        "scan": scan,
        "vulnerabilities": vulns
    })

@csrf_exempt
@require_http_methods(["POST"])
def start_openvas_scan(request):
    print("***********start openvas scan")

    # get cidr from form field (your JS uses FormData on vuln-scan-form)
    cidr = request.POST.get("vuln_cidr") or request.POST.get("cidr")
    if not cidr:
        return JsonResponse({"error": "cidr is required (e.g., 10.0.0.0/24)"}, status=400)

    # validate
    try:
        ip_network(cidr, strict=False)
    except ValueError:
        return JsonResponse({"error": f"invalid CIDR: {cidr}"}, status=400)

    with transaction.atomic():
        scan = ScanRun.objects.create(
            cidr=cidr,
            status=ScanRun.Status.IN_PROGRESS,
            scan_type="openvas",
        )
        async_result = launch_openvas_scan_task.delay(cidr=cidr)
        scan.openvas_task_id = async_result.id
        scan.save(update_fields=["openvas_task_id"])  # <-- plural

    return JsonResponse({"scan_id": scan.id, "task_id": async_result.id}, status=202)

def vuln_scan_status(request, task_id):
    async_res = AsyncResult(str(task_id))
    data = {"state": async_res.state}
    if async_res.ready():
        data["result"] = async_res.result
    return JsonResponse(data)


# -----------------------------
# Agent Download and Distribution
# -----------------------------
@require_GET
def agent_download_page(request):
    """Page for downloading the host agent software."""
    from host_agent.agent import AGENT_VERSION, AGENT_NAME

    # Get the latest agent information
    latest_agents = AgentStatus.objects.filter(
        agent_version__isnull=False
    ).order_by('-last_version_check')[:5]

    return render(request, 'dashboard/agent_download.html', {
        'agent_version': AGENT_VERSION,
        'agent_name': AGENT_NAME,
        'latest_agents': latest_agents,
        'download_url': '/agent/download/host_agent.zip'
    })


@require_GET
def download_host_agent(request):
    """Download the host agent as a ZIP file."""
    import zipfile
    import io
    from django.http import HttpResponse

    print(f"[DEBUG] Download request from {request.META.get('REMOTE_ADDR', 'unknown')}")

    # Try to download from GitHub repo release first
    try:
        repo_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'
        release_response = requests.get(repo_url, timeout=10)

        if release_response.status_code == 200:
            release_data = release_response.json()
            zipball_url = release_data.get('zipball_url')

            if zipball_url:
                zip_response = requests.get(zipball_url, timeout=30)
                if zip_response.status_code == 200:
                    print("[DEBUG] Downloaded latest agent ZIP from repo release")
                    tag_name = release_data.get('tag_name', 'latest')
                    response = HttpResponse(zip_response.content, content_type='application/zip')
                    response['Content-Disposition'] = f'attachment; filename="{tag_name}_cyber_host_agent.zip"'
                    response['Cache-Control'] = 'no-cache'
                    print(f"[DEBUG] Download response prepared with repo ZIP")
                    return response
        print("[DEBUG] Could not download from repo release, falling back to local ZIP")

    except Exception as e:
        print(f"[DEBUG] Error downloading from repo: {e}, falling back to local ZIP")

    # Fallback to creating ZIP with local agent files
    zip_buffer = io.BytesIO()

    try:
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add agent files
            agent_files = [
                os.path.join(settings.BASE_DIR, 'host_agent', 'agent.py'),
                os.path.join(settings.BASE_DIR, 'host_agent', 'requirements.txt'),
                os.path.join(settings.BASE_DIR, 'host_agent', 'README.md'),
                os.path.join(settings.BASE_DIR, 'host_agent', 'cyber_data.json'),
                os.path.join(settings.BASE_DIR, 'host_agent', 'agent.spec'),
            ]

            files_added = 0
            for file_path in agent_files:
                try:
                    with open(file_path, 'rb') as f:
                        zip_file.write(file_path, os.path.basename(file_path))
                        files_added += 1
                        print(f"[DEBUG] Added {file_path} to ZIP")
                except FileNotFoundError as e:
                    print(f"[DEBUG] File not found: {file_path} - {e}")
                    continue

            if files_added == 0:
                print("[ERROR] No agent files found for download")
                return HttpResponse("Error: No agent files found", status=404)

        zip_buffer.seek(0)
        print(f"[DEBUG] ZIP file created successfully, size: {len(zip_buffer.getvalue())} bytes")

        # Create HTTP response with ZIP file
        response = HttpResponse(zip_buffer.read(), content_type='application/zip')
        response['Content-Disposition'] = 'attachment; filename="cyber_host_agent.zip"'
        response['Cache-Control'] = 'no-cache'

        print(f"[DEBUG] Download response prepared with local files")
        return response

    except Exception as e:
        print(f"[ERROR] Failed to create download ZIP: {e}")
        return HttpResponse(f"Error creating download: {str(e)}", status=500)


@require_GET
def agent_version_api(request):
    """API endpoint for agent version information."""
    from host_agent.agent import AGENT_VERSION, AGENT_NAME

    # Get version information from all agents
    agents = AgentStatus.objects.filter(
        agent_version__isnull=False
    ).values('agent_id', 'hostname', 'agent_version', 'last_version_check')

    return JsonResponse({
        'current_version': AGENT_VERSION,
        'agent_name': AGENT_NAME,
        'agents': list(agents),
        'total_agents_with_version': agents.count()
    })


# -----------------------------
# Network Metadata and Security Onion-like Monitoring
# -----------------------------
@csrf_exempt
@require_http_methods(["POST"])
def agent_network_metadata(request):
    """Receive detailed network metadata from agents."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    agent_id = data.get("agent_id")
    network_connections = data.get("network_connections", [])
    interface_statistics = data.get("interface_statistics", [])
    active_ports = data.get("active_ports", [])
    interfaces = data.get("interfaces", [])

    if not agent_id:
        return JsonResponse({"error": "agent_id is required"}, status=400)

    try:
        agent = AgentStatus.objects.get(agent_id=agent_id)
    except AgentStatus.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

    # Create network metadata record
    metadata = NetworkMetadata.objects.create(
        agent=agent,
        network_connections=network_connections,
        interface_statistics=interface_statistics,
        active_ports=active_ports,
        interfaces=interfaces,
        total_connections=len(network_connections),
        total_interfaces=len(interface_statistics)
    )

    # Create individual connection records for detailed analysis
    for conn_data in network_connections:
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=agent,
            protocol=conn_data.get("protocol", "TCP"),
            local_address=conn_data.get("local_address"),
            remote_address=conn_data.get("remote_address"),
            status=conn_data.get("status", "UNKNOWN"),
            process_pid=conn_data.get("process", {}).get("pid"),
            process_name=conn_data.get("process", {}).get("name"),
            process_username=conn_data.get("process", {}).get("username"),
            process_cmdline=conn_data.get("process", {}).get("cmdline")
        )

    return JsonResponse({
        "status": "network_metadata_received",
        "metadata_id": metadata.id,
        "connections_recorded": len(network_connections),
        "interfaces_recorded": len(interface_statistics)
    })


@require_GET
def network_monitoring_dashboard(request):
    """Security Onion-like network monitoring dashboard."""
    agents = AgentStatus.objects.filter(status='online').order_by('-last_heartbeat')

    # Get recent network metadata
    recent_metadata = NetworkMetadata.objects.all().order_by('-timestamp')[:20]

    # Get active connections across all agents
    recent_connections = NetworkConnection.objects.all().order_by('-last_seen')[:50]

    # Get interface statistics
    interface_stats = []
    for metadata in recent_metadata:
        if metadata.interface_statistics:
            for iface_stat in metadata.interface_statistics:
                interface_stats.append({
                    'agent': metadata.agent.hostname,
                    'interface': iface_stat.get('interface'),
                    'bytes_sent': iface_stat.get('bytes_sent', 0),
                    'bytes_recv': iface_stat.get('bytes_recv', 0),
                    'packets_sent': iface_stat.get('packets_sent', 0),
                    'packets_recv': iface_stat.get('packets_recv', 0),
                    'timestamp': metadata.timestamp
                })

    return render(request, 'dashboard/network_monitoring.html', {
        'agents': agents,
        'recent_metadata': recent_metadata,
        'recent_connections': recent_connections,
        'interface_stats': interface_stats[:20],  # Limit to 20 for display
        'total_agents': agents.count(),
        'total_connections': recent_connections.count(),
        'total_metadata_records': recent_metadata.count()
    })


@require_GET
def network_metadata_api(request):
    """API endpoint for real-time network metadata."""
    agent_id = request.GET.get('agent_id')
    limit = int(request.GET.get('limit', 20))

    if agent_id:
        # Get metadata for specific agent
        metadata = NetworkMetadata.objects.filter(agent__agent_id=agent_id).order_by('-timestamp')[:limit]
    else:
        # Get recent metadata from all agents
        metadata = NetworkMetadata.objects.all().order_by('-timestamp')[:limit]

    metadata_list = []
    for record in metadata:
        metadata_list.append({
            'id': record.id,
            'agent_id': record.agent.agent_id,
            'hostname': record.agent.hostname,
            'timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'total_connections': record.total_connections,
            'total_interfaces': record.total_interfaces,
            'collection_duration_ms': record.collection_duration_ms,
            'connections': record.network_connections[:10] if record.network_connections else [],  # First 10 connections
            'interface_statistics': record.interface_statistics[:5] if record.interface_statistics else []  # First 5 interfaces
        })

    return JsonResponse({
        'metadata': metadata_list,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


@require_GET
def network_connections_api(request):
    """API endpoint for network connections data."""
    agent_id = request.GET.get('agent_id')
    limit = int(request.GET.get('limit', 50))

    if agent_id:
        # Get connections for specific agent
        connections = NetworkConnection.objects.filter(agent__agent_id=agent_id).order_by('-last_seen')[:limit]
    else:
        # Get recent connections from all agents
        connections = NetworkConnection.objects.all().order_by('-last_seen')[:limit]

    connections_list = []
    for conn in connections:
        connections_list.append({
            'id': conn.id,
            'agent_id': conn.agent.agent_id,
            'hostname': conn.agent.hostname,
            'protocol': conn.protocol,
            'local_address': conn.local_address,
            'local_port': conn.local_port,
            'remote_address': conn.remote_address,
            'remote_port': conn.remote_port,
            'status': conn.status,
            'process_name': conn.process_name or 'Unknown',
            'process_username': conn.process_username or 'Unknown',
            'first_seen': conn.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': conn.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        })

    return JsonResponse({
        'connections': connections_list,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })


@require_GET
def network_topology_api(request):
    """API endpoint for network topology visualization."""
    # Get all agents and their recent connections
    agents = AgentStatus.objects.filter(status='online')

    nodes = []
    edges = []

    # Add agent nodes
    for agent in agents:
        nodes.append({
            'id': agent.agent_id,
            'label': agent.hostname,
            'ip_address': agent.ip_address,
            'type': 'agent',
            'status': agent.status,
            'os_type': agent.os_type,
            'last_heartbeat': agent.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S') if agent.last_heartbeat else 'Never'
        })

    # Get recent connections to build edges
    recent_connections = NetworkConnection.objects.filter(
        agent__status='online',
        last_seen__gte=now().replace(hours=-1)  # Last hour
    ).select_related('agent')

    # Group connections by source/destination to create flows
    flows = {}
    for conn in recent_connections:
        if conn.remote_address and conn.remote_address != '127.0.0.1' and conn.remote_address != 'localhost':
            flow_key = (conn.agent.agent_id, conn.remote_address, conn.protocol)
            if flow_key not in flows:
                flows[flow_key] = {
                    'source': conn.agent.agent_id,
                    'target': conn.remote_address,
                    'protocol': conn.protocol,
                    'connection_count': 0,
                    'total_bytes': 0
                }
            flows[flow_key]['connection_count'] += 1

    # Convert flows to edges
    for flow in flows.values():
        edges.append({
            'from': flow['source'],
            'to': flow['target'],
            'label': f"{flow['protocol']} ({flow['connection_count']} conn)",
            'protocol': flow['protocol'],
            'connection_count': flow['connection_count']
        })

    return JsonResponse({
        'nodes': nodes,
        'edges': edges,
        'timestamp': now().strftime('%Y-%m-%d %H:%M:%S')
    })
