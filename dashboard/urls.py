from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='dashboard-home'),
    path('scan/start/', views.start_scan_ajax, name='start-scan'),
    path('scan/status/<uuid:task_id>/', views.check_scan_status, name='scan-status'),
    path('paths/', views.shortest_paths, name='shortest-paths'),
    path('history/', views.history, name='history'),  # <-- Add this line
    path('graph/data/', views.graph_data, name='graph-data'),
    path('sniffer/interfaces/', views.get_interfaces, name='sniffer-interfaces'),
    path('sniffer/start/', views.start_listener, name='sniffer-start'),
    path('sniffer/stop/', views.stop_listener, name='sniffer-stop')
]
