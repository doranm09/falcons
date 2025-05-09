from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node, ScanRun
import ipaddress
import subprocess
from django.http import JsonResponse
from .tasks import scan_network_task
from celery.result import AsyncResult
from .models import Node, Link
from .utils import dijkstra
from django.views.decorators.http import require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from .models import ScanRun
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt


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
    nodes = Node.objects.all().values('ip_address', 'name', 'status', 'description', 'last_heartbeat')

    response = {
        "state": result.state,
        "nodes": list(nodes),
    }

    # Optional hint during task progress
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
    runs = ScanRun.objects.all().order_by('-timestamp')
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
