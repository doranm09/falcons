from django.urls import re_path
from . import consumers

# WebSocket URL patterns for Sliver real-time features
websocket_urlpatterns = [
    # Dashboard real-time updates
    re_path(r'ws/sliver/dashboard/$', consumers.SliverDashboardConsumer.as_asgi()),

    # Session monitoring for real-time updates
    re_path(r'ws/sliver/sessions/$', consumers.SliverSessionMonitorConsumer.as_asgi()),
    re_path(r'ws/sliver/sessions/(?P<engagement_id>\d+)/$', consumers.SliverSessionMonitorConsumer.as_asgi()),

    # Job monitoring for real-time updates
    re_path(r'ws/sliver/jobs/$', consumers.SliverJobMonitorConsumer.as_asgi()),
]
