"""
ARQ worker settings for background forensic jobs.

Run with:
    arq src.workers.worker.WorkerSettings
or via docker compose (the `worker` service).
"""

import os


def _redis_settings():
    try:
        from arq.connections import RedisSettings
    except ImportError:  # pragma: no cover - optional dependency
        return None
    return RedisSettings(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD") or None,
    )


class WorkerSettings:
    functions = []  # populated by src.workers.worker
    redis_settings = _redis_settings()
    max_jobs = 10
    job_timeout = 600
    keep_result = 3600
    on_startup = None
    on_shutdown = None
