"""Celery application instance for Hawk Scan background tasks."""

from celery import Celery
from hawk_scan.web.config import get_settings

settings = get_settings()

celery = Celery(
    "hawk_scan",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    worker_concurrency=settings.max_concurrent_scans,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)
