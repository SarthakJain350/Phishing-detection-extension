
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.core.config import settings
from backend.app.db.models import ScanRecord
from backend.app.services.retention import cleanup_expired_scans


def create_scan(db, created_at):
    record = ScanRecord(
        target_type="website",
        target_reference="retention-test.com",
        classification="likely_legitimate",
        risk_score=10,
        evidence=[],
        tool_statuses={},
        analysis_status="complete",
        source="manual_website",
        created_at=created_at,
    )
    db.add(record)
    db.commit()
    return record


def test_cleanup_deletes_expired_scans(sqlite_session):
    now = datetime.now(timezone.utc)
    retention_days = settings.SCAN_RETENTION_DAYS

    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days + 2),
    )
    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days + 5),
    )

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 2
    assert sqlite_session.query(ScanRecord).count() == 0


def test_cleanup_preserves_recent_scans(sqlite_session):
    now = datetime.now(timezone.utc)
    retention_days = settings.SCAN_RETENTION_DAYS

    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days - 1),
    )

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 0
    assert sqlite_session.query(ScanRecord).count() == 1


def test_cleanup_preserves_record_at_exact_cutoff(sqlite_session):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=settings.SCAN_RETENTION_DAYS)

    create_scan(sqlite_session, cutoff)

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 0
    assert sqlite_session.query(ScanRecord).count() == 1


def test_cleanup_rejects_naive_datetime(sqlite_session):
    naive_now = datetime.now()

    with pytest.raises(ValueError, match="timezone-aware"):
        cleanup_expired_scans(sqlite_session, now=naive_now)


def test_run_cleanup_once_success(sqlite_session):
    from backend.app.services.retention import run_cleanup_once

    now = datetime.now(timezone.utc)
    create_scan(sqlite_session, now - timedelta(days=settings.SCAN_RETENTION_DAYS + 1))
    assert sqlite_session.query(ScanRecord).count() == 1

    closed = False

    class MockSessionWrapper:
        def __init__(self, session):
            self._session = session

        def __getattr__(self, name):
            return getattr(self._session, name)

        def close(self):
            nonlocal closed
            closed = True
            # Don't close sqlite_session to keep fixture valid, just track call

    deleted = run_cleanup_once(session_factory=lambda: MockSessionWrapper(sqlite_session), now=now)
    assert deleted == 1
    assert closed is True
    assert sqlite_session.query(ScanRecord).count() == 0


def test_configuration_validation():
    from pydantic import ValidationError
    from backend.app.core.config import Settings

    # Valid values
    s = Settings(
        RETENTION_CHECK_INTERVAL_SECONDS=10,
        RETENTION_INITIAL_DELAY_SECONDS=0,
        SCAN_RETENTION_DAYS=1,
    )
    assert s.RETENTION_CHECK_INTERVAL_SECONDS == 10
    assert s.RETENTION_INITIAL_DELAY_SECONDS == 0
    assert s.SCAN_RETENTION_DAYS == 1

    # Invalid RETENTION_CHECK_INTERVAL_SECONDS <= 0
    with pytest.raises(ValidationError):
        Settings(RETENTION_CHECK_INTERVAL_SECONDS=0)
    with pytest.raises(ValidationError):
        Settings(RETENTION_CHECK_INTERVAL_SECONDS=-5)

    # Invalid RETENTION_INITIAL_DELAY_SECONDS < 0
    with pytest.raises(ValidationError):
        Settings(RETENTION_INITIAL_DELAY_SECONDS=-1)

    # Invalid SCAN_RETENTION_DAYS <= 0
    with pytest.raises(ValidationError):
        Settings(SCAN_RETENTION_DAYS=0)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_shutdown_during_initial_delay():
    import asyncio
    from backend.app.services.retention import retention_scheduler_worker

    run_counts = 0

    def mock_factory():
        nonlocal run_counts
        run_counts += 1

    stop_event = asyncio.Event()
    worker_task = asyncio.create_task(
        retention_scheduler_worker(
            interval_seconds=10,
            initial_delay_seconds=30,
            session_factory=mock_factory,
            stop_event=stop_event,
        )
    )

    # Allow worker to enter wait_for(stop.wait(), timeout=initial_delay)
    await asyncio.sleep(0.01)
    # Trigger shutdown via stop_event
    stop_event.set()
    await worker_task
    # Cleanup should not have executed
    assert run_counts == 0


@pytest.mark.anyio
async def test_shutdown_between_intervals():
    import asyncio
    from backend.app.services.retention import retention_scheduler_worker

    run_counts = 0

    def mock_factory():
        nonlocal run_counts
        run_counts += 1
        class DummySession:
            def close(self):
                pass
        return DummySession()

    stop_event = asyncio.Event()
    worker_task = asyncio.create_task(
        retention_scheduler_worker(
            interval_seconds=60,
            initial_delay_seconds=0,
            session_factory=mock_factory,
            stop_event=stop_event,
        )
    )

    # Let the first cleanup finish and enter the interval wait
    await asyncio.sleep(0.05)
    assert run_counts == 1

    # Signal stop while waiting between intervals
    stop_event.set()
    await worker_task
    assert run_counts == 1


@pytest.mark.anyio
async def test_shutdown_while_cleanup_is_executing():
    """Verify worker exits cleanly only after in-progress cleanup completes.

    The block is placed inside the mocked cleanup_expired_scans so the test
    genuinely exercises shutdown while the DB operation is executing, not
    merely while the session is being constructed.
    """
    import asyncio
    import threading
    from backend.app.services.retention import retention_scheduler_worker

    cleanup_started = threading.Event()
    allow_cleanup_finish = threading.Event()
    session_closed = threading.Event()
    cleanup_completed = False

    class ControlledSession:
        def close(self):
            session_closed.set()

    _session = ControlledSession()

    def mock_factory():
        # Return the session immediately; blocking happens inside cleanup below.
        return _session

    def mock_cleanup_service(db, *, now=None):
        nonlocal cleanup_completed
        # Signal that the DB operation has started, then block until released.
        cleanup_started.set()
        try:
            allow_cleanup_finish.wait(timeout=5)
            cleanup_completed = True
            return 5
        finally:
            # Safety: ensure event is always released even on unexpected paths.
            allow_cleanup_finish.set()

    import backend.app.services.retention as retention_module
    orig_cleanup = retention_module.cleanup_expired_scans
    retention_module.cleanup_expired_scans = mock_cleanup_service

    try:
        stop_event = asyncio.Event()
        worker_task = asyncio.create_task(
            retention_scheduler_worker(
                interval_seconds=10,
                initial_delay_seconds=0,
                session_factory=mock_factory,
                stop_event=stop_event,
            )
        )

        # Wait until the DB cleanup operation is actively executing in its thread.
        await asyncio.to_thread(cleanup_started.wait, 5)
        assert cleanup_started.is_set()

        # Signal shutdown while cleanup is in progress.
        stop_event.set()

        # Unblock the cleanup thread and let it complete.
        allow_cleanup_finish.set()

        # Worker must finish naturally (not via cancellation) after cleanup completes.
        await worker_task

        assert cleanup_completed is True
        assert session_closed.is_set()
    finally:
        retention_module.cleanup_expired_scans = orig_cleanup


@pytest.mark.anyio
async def test_worker_cancellation_waits_for_in_flight_cleanup():
    """Verify cancellation propagates only after the in-flight cleanup thread finishes.

    The block is placed inside the mocked cleanup_expired_scans so the test
    genuinely exercises cancellation while the DB operation is executing, not
    merely while the session is being constructed.
    """
    import asyncio
    import threading
    from backend.app.services.retention import retention_scheduler_worker

    cleanup_started = threading.Event()
    allow_cleanup_finish = threading.Event()
    session_closed = threading.Event()

    class ControlledSession:
        def close(self):
            session_closed.set()

    _session = ControlledSession()

    def mock_factory():
        # Return the session immediately; blocking happens inside cleanup below.
        return _session

    def mock_cleanup_service(db, *, now=None):
        # Signal that the DB operation has started, then block until released.
        cleanup_started.set()
        try:
            allow_cleanup_finish.wait(timeout=5)
            return 1
        finally:
            # Safety: ensure event is always released even on unexpected paths.
            allow_cleanup_finish.set()

    import backend.app.services.retention as retention_module
    orig_cleanup = retention_module.cleanup_expired_scans
    retention_module.cleanup_expired_scans = mock_cleanup_service

    try:
        stop_event = asyncio.Event()
        worker_task = asyncio.create_task(
            retention_scheduler_worker(
                interval_seconds=10,
                initial_delay_seconds=0,
                session_factory=mock_factory,
                stop_event=stop_event,
            )
        )

        # Wait until the DB cleanup operation is actively executing in its thread.
        await asyncio.to_thread(cleanup_started.wait, 5)
        assert cleanup_started.is_set()

        # Cancel the worker task while cleanup is in flight.
        worker_task.cancel()

        # Unblock the cleanup thread so it can finish cleanly.
        allow_cleanup_finish.set()

        # The worker must propagate CancelledError only after the thread finishes.
        with pytest.raises(asyncio.CancelledError):
            await worker_task

        # Session must have been closed by the time the worker exited.
        assert session_closed.is_set()
    finally:
        retention_module.cleanup_expired_scans = orig_cleanup


@pytest.mark.anyio
async def test_cleanup_exception_allows_orderly_shutdown():
    """Verify a database exception during cleanup is caught and the worker recovers.

    The exception is raised inside the mocked cleanup_expired_scans (not the
    session factory) so the test exercises the exception path that the worker's
    error handler is designed to catch.
    """
    import asyncio
    import threading
    from backend.app.services.retention import retention_scheduler_worker

    cleanup_started = threading.Event()

    class DummySession:
        def close(self):
            pass

    def mock_factory():
        return DummySession()

    def mock_cleanup_service(db, *, now=None):
        # Signal entry then raise to simulate a DB failure mid-cleanup.
        cleanup_started.set()
        raise RuntimeError("Simulated database failure during cleanup")

    import backend.app.services.retention as retention_module
    orig_cleanup = retention_module.cleanup_expired_scans
    retention_module.cleanup_expired_scans = mock_cleanup_service

    try:
        stop_event = asyncio.Event()
        worker_task = asyncio.create_task(
            retention_scheduler_worker(
                interval_seconds=60,
                initial_delay_seconds=0,
                session_factory=mock_factory,
                stop_event=stop_event,
            )
        )

        # Wait until cleanup is entered and throws.
        await asyncio.to_thread(cleanup_started.wait, 5)
        assert cleanup_started.is_set()

        # Worker catches the error, logs it, and continues; signal stop.
        stop_event.set()
        await worker_task
    finally:
        retention_module.cleanup_expired_scans = orig_cleanup


@pytest.mark.anyio
async def test_fastapi_lifespan_starts_and_stops_retention():
    """Verify the FastAPI lifespan starts and fully stops the retention scheduler.

    TestClient runs the lifespan in a separate thread with its own event loop,
    so asyncio.all_tasks() on the test loop cannot observe the retention task.

    Instead we wrap retention_scheduler_worker to set a threading.Event when
    the coroutine exits. Because TestClient.__exit__ blocks until the lifespan
    finally block completes (which awaits retention_task), the event is
    guaranteed to be set before the 'with' block returns.
    """
    import threading
    import unittest.mock
    from fastapi.testclient import TestClient
    import backend.app.main as main_module
    import backend.app.services.retention as retention_module

    worker_exited = threading.Event()
    original_worker = retention_module.retention_scheduler_worker

    async def instrumented_worker(**kwargs):
        try:
            await original_worker(**kwargs)
        finally:
            worker_exited.set()

    with unittest.mock.patch.object(
        main_module, "retention_scheduler_worker", instrumented_worker
    ):
        with TestClient(main_module.app) as client:
            res = client.get("/health")
            assert res.status_code == 200
        # TestClient.__exit__ has returned, meaning the lifespan finally block
        # (which awaits retention_task) has completed. The worker must have exited.

    assert worker_exited.is_set(), (
        "retention_scheduler_worker did not exit during FastAPI lifespan shutdown"
    )
