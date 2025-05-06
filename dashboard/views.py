from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node
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



def home(request):
    nodes = Node.objects.all().values('ip_address', 'name')
    return render(request, 'dashboard/home.html', {'nodes': nodes})


def start_scan_ajax(request):
    if request.method == "POST":
        cidr = request.POST.get("cidr")
        print(f"[DEBUG] Received CIDR: {cidr}")  # Add this
        task = scan_network_task.delay(cidr)
        return JsonResponse({"task_id": task.id})


def check_scan_status(request, task_id):
    result = AsyncResult(str(task_id))  # Ensure it's a string
    nodes = Node.objects.all().values('ip_address', 'name', 'status', 'description', 'last_heartbeat')

    response = {
        "state": result.state,
        "nodes": list(nodes),
    }

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