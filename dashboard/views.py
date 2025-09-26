from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node, ScanRun, AgentCommand, CommandResult, NodeInterface
import ipaddress
import subprocess
from django.http import JsonResponse
from .tasks import scan_network_task, launch_openvas_scan_task
from celery.result import AsyncResult
from .models import Node, Link
from .utils import dijkstra
from django.views.decorators.http import require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from django.db import transaction
from ipaddress import ip_network

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
        elements.append({
            "data": {
                "id": str(node.id),
                "label": node.name,
                "ip": node.ip_address,
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

    node, _ = Node.objects.update_or_create(
        agent_id=agent_id,
        defaults={
            "name": hostname,
            "ip_address": ip,
            "description": f"Reported from agent {agent_id}",
            "status": "online"
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

    return JsonResponse({"status": "ok", "node_id": node.id})

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