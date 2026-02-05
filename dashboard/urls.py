from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='dashboard-home'),
    path('scans/', views.network_scans, name='network_scans'),
    path('scan/start/', views.start_scan_ajax, name='start-scan'),
    path('scan/status/<uuid:task_id>/', views.check_scan_status, name='scan-status'),
    path('scan/agent/start/', views.start_agent_scan, name='start-agent-scan'),
    path('agent/scan_results/', views.agent_scan_results, name='agent_scan_results'),
    path('paths/', views.shortest_paths, name='shortest-paths'),
    path('history/', views.history, name='history'),
    path('graph/data/', views.graph_data, name='graph-data'),
    path('sniffer/interfaces/', views.get_interfaces, name='sniffer-interfaces'),
    path('sniffer/start/', views.start_listener, name='sniffer-start'),
    path('sniffer/stop/', views.stop_listener, name='sniffer-stop'),
    path('scan/history/', views.get_scan_history, name='scan-history'),
    path('agent/report/', views.agent_report, name='agent_report'),
    path('agent/cyber_report/', views.agent_cyber_report, name='agent_cyber_report'),
    path('sbom/', views.sbom_ingest, name='sbom_ingest'),
    path('agent/commands/', views.agent_commands, name='agent_commands'),
    path('agent/command_result/', views.agent_command_result, name='agent_command_result'),
    path('agent/monitoring/', views.agent_monitoring, name='agent_monitoring'),
    path('agent/status/', views.agent_status_api, name='agent_status_api'),
    path('agent/command/send/', views.send_agent_command, name='send_agent_command'),
    path('agent/download/host_agent.zip', views.download_host_agent, name='download_host_agent'),
    path('agent/download/', views.agent_download_page, name='agent_download_page'),
    path('agent/versions/', views.agent_version_api, name='agent_version_api'),
    path('agent/<str:agent_id>/', views.agent_details, name='agent_details'),
    path('agent/<str:agent_id>/analysis/', views.agent_analysis, name='agent_analysis'),
    path('agent/<str:agent_id>/history/', views.agent_command_history, name='agent_command_history'),
    path('agent/<str:agent_id>/sbom/', views.agent_sbom_export, name='agent_sbom_export'),
    path('agent/<str:agent_id>/sbom/diff/', views.agent_sbom_diff, name='agent_sbom_diff'),
    path('agent/<str:agent_id>/sbom/bundle/', views.agent_sbom_bundle, name='agent_sbom_bundle'),
    path('node/<int:node_id>/details/', views.node_details, name='node_details'),
    path('node/<int:node_id>/', views.node_detail_page, name='node_detail_page'),
    path("vulnerabilities/<int:scan_id>/", views.vulnerability_detail, name="vuln-detail"),
    path('scan/vuln/start/', views.start_openvas_scan, name='start-vuln-scan'),
    path('scan/vuln/status/<int:scan_id>/', views.vuln_scan_status, name='vuln-scan-status'),
    path('paths/<int:start_node_id>/', views.shortest_paths, name='shortest-paths'),

    # Risk assessment (ICS)
    path('risk-assessment/', views.risk_assessment_page, name='risk_assessment'),
    path('risk-assessment/status/', views.risk_assessment_status_api, name='risk_assessment_status'),
    path('risk-assessment/nodes/', views.risk_assessment_nodes_api, name='risk_assessment_nodes'),
    path('risk-assessment/probability/', views.risk_assessment_probability_api, name='risk_assessment_probability'),
    path('risk-assessment/network/compute/', views.risk_assessment_network_compute_api, name='risk_assessment_network_compute'),

    # Network monitoring and Security Onion-like features
    path('network/monitoring/', views.network_monitoring_dashboard, name='network_monitoring'),
    path('network/metadata/', views.network_metadata_api, name='network_metadata_api'),
    path('network/connections/', views.network_connections_api, name='network_connections_api'),
    path('network/topology/', views.network_topology_api, name='network_topology_api'),
    path('digital-twin/', views.digital_twin_page, name='digital_twin_page'),
    path('digital-twin/generate/', views.digital_twin_generate, name='digital_twin_generate'),
    path('digital-twin/export/', views.digital_twin_export, name='digital_twin_export'),
    path('digital-twin/execute/', views.digital_twin_execute, name='digital_twin_execute'),
    path('digital-twin/reset/', views.digital_twin_reset, name='digital_twin_reset'),
    path('digital-twin/kill/', views.digital_twin_kill, name='digital_twin_kill'),
    path('digital-twin/logs/', views.minimega_execution_logs, name='minimega_execution_logs'),

    # MiniMega Provisioning
    path('minimega/provisions/', views.minimega_provisions, name='minimega_provisions'),
    path('minimega/deploy/', views.deploy_minimega_script, name='deploy_minimega_script'),
    path('minimega/stream/', views.stream_minimega_execution, name='stream_minimega_execution'),
    path('minimega/stream/async/', views.stream_minimega_execution_async, name='stream_minimega_execution_async'),

]
