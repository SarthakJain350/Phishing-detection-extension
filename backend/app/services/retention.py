
"""Scheduled scan-history retention cleanup service."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from typing import Callable

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.repository import ScanRepository

logger = logging.getLogger("phishing_detector.retention")


def cleanup_expired_scans(
    db: Session,
    *,
    now: datetime | None = None,
) -> int:
    """Delete scan records older than the configured retention period.

    Args:
        db: Active database session.
        now: Optional timezone-aware reference time, useful for testing.

    Returns:
        Number of expired scan records deleted.
    """
    current_time = now or datetime.now(timezone.utc)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("The reference time must be timezone-aware.")

    cutoff = current_time - timedelta(days=settings.SCAN_RETENTION_DAYS)

    return ScanRepository.delete_expired_scans(
        db,
        older_than=cutoff,
    )


def run_cleanup_once(
    session_factory: Callable[[], Session] | None = None,
    *,
    now: datetime | None = None,
) -> int:
    """Acquire a session from the factory, run cleanup, and ensure session closure.

    Args:
        session_factory: Callable returning a new Session. If None, dynamically
            imports and uses backend.app.db.session.SessionLocal to avoid static binding.
        now: Optional reference timestamp passed to cleanup_expired_scans.

    Returns:
        Count of deleted scan records.
    """
    if session_factory is None:
        from backend.app.db.session import SessionLocal

        session_factory = SessionLocal

    db: Session = session_factory()
    try:
        deleted = cleanup_expired_scans(db, now=now)
        return deleted
    finally:
        db.close()


async def retention_scheduler_worker(
    *,
    interval_seconds: int | None = None,
    initial_delay_seconds: int | None = None,
    session_factory: Callable[[], Session] | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Background worker that periodically executes retention cleanup.

    WORKER SCOPE & CONCURRENCY:
    This scheduler is designed to run once per FastAPI process within its lifespan.
    It does not coordinate across multiple distributed workers or replicas; if running
    with multiple Uvicorn workers, each worker will run cleanup locally. Database-level
    row locking and atomic DELETE statements ensure consistency even if multiple workers
    run concurrent cleanups.

    THREAD CANCELLATION & SHUTDOWN SAFETY:
    When running `run_cleanup_once` via `asyncio.to_thread()`, canceling the outer task
    would normally cause asyncio to abandon the thread task. To guarantee that an in-progress
    database cleanup is not left unmanaged, we create and maintain an explicit reference to
    the cleanup task (`asyncio.create_task`).
    If cancellation or shutdown occurs while a cleanup is in flight, the worker explicitly
    awaits `asyncio.gather(cleanup_task, return_exceptions=True)` before terminating, ensuring
    the database transaction commits/rolls back and the session closes completely.
    """
    interval = (
        interval_seconds
        if interval_seconds is not None
        else settings.RETENTION_CHECK_INTERVAL_SECONDS
    )
    initial_delay = (
        initial_delay_seconds
        if initial_delay_seconds is not None
        else settings.RETENTION_INITIAL_DELAY_SECONDS
    )
    stop = stop_event or asyncio.Event()

    logger.info(
        "Starting scan retention scheduler (interval: %ds, initial delay: %ds, retention: %d days)",
        interval,
        initial_delay,
        settings.SCAN_RETENTION_DAYS,
    )

    cleanup_task: asyncio.Task[int] | None = None

    try:
        if initial_delay > 0:
            try:
                # Wait for initial delay or early stop trigger
                await asyncio.wait_for(stop.wait(), timeout=initial_delay)
                logger.info("Retention scheduler stopped during initial delay.")
                return
            except asyncio.TimeoutError:
                pass  # Initial delay elapsed normally

        while not stop.is_set():
            cleanup_task = asyncio.create_task(
                asyncio.to_thread(run_cleanup_once, session_factory),
                name="retention-cleanup-run",
            )
            try:
                # Use shield so cancelling worker_task does not cancel cleanup_task prematurely;
                # but in the exception handler we explicitly wait for cleanup_task to complete.
                deleted = await asyncio.shield(cleanup_task)
                if deleted > 0:
                    logger.info("Retention cleanup completed: purged %d expired scans", deleted)
            except asyncio.CancelledError:
                # Cancellation occurred while waiting for cleanup_task.
                # Explicitly await the in-flight cleanup task so the thread and DB session finish cleanly.
                await asyncio.gather(cleanup_task, return_exceptions=True)
                logger.info("Retention cleanup in-flight task completed during worker cancellation.")
                raise
            except Exception as exc:
                logger.error(
                    "Retention cleanup encountered an error; will retry at next interval: %s",
                    exc,
                    exc_info=True,
                )
            finally:
                cleanup_task = None

            # If stopped while cleanup was running, exit loop without waiting for next interval
            if stop.is_set():
                break

            # Wait for next interval or stop signal
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                break  # stop was signaled
            except asyncio.TimeoutError:
                continue  # Interval elapsed, run next cleanup
    except asyncio.CancelledError:
        # If cancelled while waiting outside cleanup_task (e.g. during interval wait),
        # ensure cleanup_task is finished if it somehow exists.
        if cleanup_task is not None and not cleanup_task.done():
            await asyncio.gather(cleanup_task, return_exceptions=True)
        logger.info("Retention scheduler worker cancelled cleanly.")
        raise
    finally:
        logger.info("Retention scheduler worker has exited.")
