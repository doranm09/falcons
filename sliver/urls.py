from django.urls import path
from . import views

app_name = 'sliver'

urlpatterns = [
    # Dashboard
    path('', views.sliver_dashboard, name='dashboard'),

    # Engagements
    path('engagements/', views.engagement_list, name='engagement_list'),
    path('engagements/new/', views.create_engagement, name='create_engagement'),
    path('engagements/<int:engagement_id>/', views.engagement_detail, name='engagement_detail'),
    path('engagements/<int:engagement_id>/start/', views.start_engagement, name='start_engagement'),
    path('engagements/<int:engagement_id>/stop/', views.stop_engagement, name='stop_engagement'),

    # Sessions
    path('sessions/', views.session_list, name='session_list'),
    path('engagements/<int:engagement_id>/sessions/', views.session_list, name='engagement_sessions'),
    path('sessions/<str:session_id>/', views.session_detail, name='session_detail'),
    path('sessions/<str:session_id>/execute/', views.execute_command, name='execute_command'),
    path('sessions/<str:session_id>/template/', views.run_template_task, name='run_template_task'),
    path('sessions/<str:session_id>/loot/collect/', views.collect_loot, name='collect_loot'),

    # Jobs
    path('jobs/', views.job_list, name='job_list'),
    path('jobs/export/', views.export_jobs, name='job_export'),
    path('jobs/<str:job_id>/', views.job_detail, name='job_detail'),
    path('jobs/<str:job_id>/output/', views.job_output, name='job_output'),
    path('jobs/<str:job_id>/error/', views.job_error, name='job_error'),
    path('jobs/<str:job_id>/retry/', views.retry_job, name='retry_job'),
    path('sessions/<str:session_id>/jobs/', views.job_list, name='session_jobs'),

    # Loot
    path('loot/', views.loot_list, name='loot_list'),
    path('engagements/<int:engagement_id>/loot/', views.loot_list, name='engagement_loot'),
    path('loot/<int:loot_id>/download/', views.download_loot, name='download_loot'),

    # Implant generation
    path('generate-implant/', views.generate_implant, name='generate_implant'),
    path('implants/', views.implant_artifacts, name='implant_artifacts'),
    path('engagements/<int:engagement_id>/implants/', views.implant_artifacts, name='engagement_implants'),
    path('implants/<int:artifact_id>/download/', views.download_implant, name='download_implant'),
    path('implants/<int:artifact_id>/fetch/', views.download_implant_token, name='download_implant_token'),
    path('implants/<int:artifact_id>/deploy/', views.deploy_implant_to_agent, name='deploy_implant_to_agent'),

    # Teamserver management
    path('teamservers/', views.teamserver_list, name='teamserver_list'),
    path('teamservers/new/', views.teamserver_create, name='teamserver_create'),
    path('teamservers/<int:teamserver_id>/edit/', views.teamserver_edit, name='teamserver_edit'),
    path('teamservers/<int:teamserver_id>/delete/', views.teamserver_delete, name='teamserver_delete'),
    path('teamservers/<int:teamserver_id>/test/', views.test_teamserver_connection, name='test_teamserver_connection'),
    path('teamservers/test-all/', views.test_all_teamservers, name='test_all_teamservers'),

    # Templates
    path('templates/', views.task_templates, name='task_templates'),

    # API Endpoints
    path('api/sessions/', views.api_sessions, name='api_sessions'),
    path('api/jobs/', views.api_jobs, name='api_jobs'),
    path('api/events/', views.api_events, name='api_events'),
    path('api/loot/', views.api_loot, name='api_loot'),
    path('api/teamserver-status/', views.api_teamserver_status, name='api_teamserver_status'),

    # Real-time updates (placeholder for WebSocket/Django Channels)
    path('events/stream/', views.events_stream, name='events_stream'),

    # Session refresh
    path('refresh-sessions/', views.refresh_sessions, name='refresh_sessions'),
]
