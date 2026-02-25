"""
Celery worker entry point.

Run with:
    celery -A celery_worker.celery_app worker --loglevel=info
"""

from app import create_app
from tasks import celery_app, init_celery

flask_app = create_app()
init_celery(flask_app)
