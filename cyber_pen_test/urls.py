from django.contrib import admin
from django.urls import path, include  # ✅ include is required

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls')),  # ✅ route root path to dashboard
]
