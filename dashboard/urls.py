from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='dashboard-home'),
    path('scan/start/', views.start_scan_ajax, name='start-scan'),
    path('scan/status/<uuid:task_id>/', views.check_scan_status, name='scan-status'),
    path('paths/', views.shortest_paths, name='shortest-paths'),
    path('history/', views.history, name='history'),
    path('graph/data/', views.graph_data, name='graph-data'),
    path('sniffer/interfaces/', views.get_interfaces, name='sniffer-interfaces'),
    path('sniffer/start/', views.start_listener, name='sniffer-start'),
    path('sniffer/stop/', views.stop_listener, name='sniffer-stop'),
    path('scan/history/', views.get_scan_history, name='scan-history'),
    path('agent/report/', views.agent_report, name='agent_report'),
    path('agent/cyber_report/', views.agent_cyber_report, name='agent_cyber_report'),
    path('agent/commands/', views.agent_commands, name='agent_commands'),
    path('agent/command_result/', views.agent_command_result, name='agent_command_result'),
    path('agent/monitoring/', views.agent_monitoring, name='agent_monitoring'),
    path('agent/status/', views.agent_status_api, name='agent_status_api'),
    path('agent/command/send/', views.send_agent_command, name='send_agent_command'),
    path('agent/<str:agent_id>/', views.agent_details, name='agent_details'),
    path('agent/<str:agent_id>/analysis/', views.agent_analysis, name='agent_analysis'),
    path('agent/<str:agent_id>/history/', views.agent_command_history, name='agent_command_history'),
    path('agent/download/host_agent.zip', views.download_host_agent, name='download_host_agent'),
    path('agent/download/', views.agent_download_page, name='agent_download_page'),
    path('agent/versions/', views.agent_version_api, name='agent_version_api'),
    path('node/<int:node_id>/details/', views.node_details, name='node_details'),
    path("vulnerabilities/<int:scan_id>/", views.vulnerability_detail, name="vuln-detail"),
    path('scan/vuln/start/', views.start_openvas_scan, name='start-vuln-scan'),
    path('scan/vuln/status/<uuid:task_id>/', views.vuln_scan_status, name='vuln-scan-status'),
    path('paths/<int:start_node_id>/', views.shortest_paths, name='shortest-paths'),

    # Network monitoring and Security Onion-like features
    path('network/monitoring/', views.network_monitoring_dashboard, name='network_monitoring'),
    path('network/metadata/', views.network_metadata_api, name='network_metadata_api'),
    path('network/connections/', views.network_connections_api, name='network_connections_api'),
    path('network/topology/', views.network_topology_api, name='network_topology_api'),

    # MiniMega Provisioning
    path('minimega/provisions/', views.minimega_provisions, name='minimega_provisions'),

]
