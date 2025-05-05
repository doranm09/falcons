from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node
import ipaddress
import subprocess
from django.http import JsonResponse
from .tasks import scan_network_task
from celery.result import AsyncResult


def home(request):
    nodes = Node.objects.all().values('ip_address', 'name')
    return render(request, 'dashboard/home.html', {'nodes': nodes})


def start_scan_ajax(request):
    if request.method == "POST":
        cidr = request.POST.get("cidr")
        task = scan_network_task.delay(cidr)
        return JsonResponse({"task_id": task.id})


def check_scan_status(request, task_id):
    result = AsyncResult(task_id)
    nodes = Node.objects.all().values('ip_address', 'name', 'status', 'description', 'last_heartbeat')

    response = {
        "state": result.state,
        "nodes": list(nodes),
    }

    # Only include result if it's ready and serializable
    if result.ready():
        try:
            result_val = result.result
            if isinstance(result_val, Exception):
                response["result"] = str(result_val)  # Convert exception to string
            else:
                response["result"] = result_val
        except Exception as e:
            response["result"] = f"Error fetching result: {str(e)}"

    return JsonResponse(response)