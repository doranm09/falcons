from __future__ import absolute_import
import os
from celery import Celery

# Default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_pen_test.settings')

celery_app = Celery('cyber_pen_test')

celery_app.config_from_object('django.conf:settings', namespace='CELERY')

celery_app.autodiscover_tasks()

@celery_app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
