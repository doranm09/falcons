from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='dashboard-home'),
    path('scan/start/', views.start_scan_ajax, name='scan-start'),
    path('scan/status/<task_id>/', views.check_scan_status, name='scan-status'),
]
