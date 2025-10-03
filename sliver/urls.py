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

    # Jobs
    path('jobs/', views.job_list, name='job_list'),
    path('sessions/<str:session_id>/jobs/', views.job_list, name='session_jobs'),

    # Loot
    path('loot/', views.loot_list, name='loot_list'),
    path('engagements/<int:engagement_id>/loot/', views.loot_list, name='engagement_loot'),

    # Implant generation
    path('generate-implant/', views.generate_implant, name='generate_implant'),

    # Templates
    path('templates/', views.task_templates, name='task_templates'),

    # API Endpoints
    path('api/sessions/', views.api_sessions, name='api_sessions'),
    path('api/jobs/', views.api_jobs, name='api_jobs'),
    path('api/events/', views.api_events, name='api_events'),
    path('api/teamserver-status/', views.api_teamserver_status, name='api_teamserver_status'),

    # Real-time updates (placeholder for WebSocket/Django Channels)
    path('events/stream/', views.events_stream, name='events_stream'),

    # Session refresh
    path('refresh-sessions/', views.refresh_sessions, name='refresh_sessions'),
]
