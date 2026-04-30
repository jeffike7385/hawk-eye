"""Celery application instance for Hawk Scan background tasks."""

from celery import Celery
from celery.schedules import crontab
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
    include=["hawk_scan.web.tasks"],
    beat_schedule_filename="/tmp/celerybeat-schedule",
)

celery.conf.beat_schedule = {
    "cleanup-expired-scans": {
        "task": "hawk_scan.cleanup_expired",
        "schedule": crontab(hour=2, minute=0),
    },
    "recover-stale-scans": {
        "task": "hawk_scan.recover_stale",
        "schedule": 300.0,
    },
}


@celery.task(name="hawk_scan.cleanup_expired")
def cleanup_expired_task():
    from hawk_scan.web.beat import cleanup_expired_scans
    from hawk_scan.web.tasks import _get_engine
    cleanup_expired_scans(_get_engine())


@celery.task(name="hawk_scan.recover_stale")
def recover_stale_task():
    from hawk_scan.web.beat import recover_stale_scans
    from hawk_scan.web.tasks import _get_engine
    recover_stale_scans(_get_engine())
