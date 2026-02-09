from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls', namespace='dashboard')),  # route root path to dashboard
    path('dashboard/', include('dashboard.urls')),  # legacy prefix support
    path('sliver/', include('sliver.urls', namespace='sliver')),  # sliver C2 operations
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
