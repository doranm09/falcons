from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Node
import ipaddress
import subprocess
from django.http import JsonResponse
from .tasks import scan_network_task
from celery.result import AsyncResult


def home(request):
    nodes = Node.objects.all()
    return render(request, 'dashboard/home.html', {'nodes': nodes})

def start_scan_ajax(request):
    if request.method == "POST":
        cidr = request.POST.get("cidr")
        task = scan_network_task.delay(cidr)
        return JsonResponse({"task_id": task.id})

def check_scan_status(request, task_id):
    result = AsyncResult(task_id)
    response = {
        "state": result.state,
        "result": result.result if result.ready() else None
    }
    return JsonResponse(response)
