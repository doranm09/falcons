from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='dashboard-home'),
    path('scan/start/', views.start_scan_ajax, name='start-scan'),
    path('scan/status/<uuid:task_id>/', views.check_scan_status, name='scan-status'),
    path('paths/', views.shortest_paths, name='shortest-paths'),
    path('history/', views.history, name='history'),  # <-- Add this line
]
