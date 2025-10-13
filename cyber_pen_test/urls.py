from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls', namespace='dashboard')),  # route root path to dashboard
    path('sliver/', include('sliver.urls', namespace='sliver')),  # sliver C2 operations
]
