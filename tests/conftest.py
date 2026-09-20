"""Pin the test database before any test module imports the backend, so a
fixture that drops tables can never touch a developer's real database no
matter which test file is collected first."""
import os
import sys

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite:///./test_secure_vibecode.db")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# SQLite ignores foreign keys unless asked; Postgres (production) enforces them.
# Enforcing them in tests turns "works on SQLite, fails on Postgres" bugs into
# ordinary test failures.
from sqlalchemy import event  # noqa: E402

from backend import db as _db  # noqa: E402

if _db.engine.dialect.name == "sqlite":

    @event.listens_for(_db.engine, "connect")
    def _enforce_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")


# Production runs scans on a background thread pool. Most tests want the deterministic old
# behaviour (the job has finished by the time the request returns), so jobs run inline unless
# a test asks for the real pool with @pytest.mark.real_executor.
import pytest  # noqa: E402

from backend import jobs as _jobs  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "real_executor: run scan jobs on the real background pool")


@pytest.fixture(autouse=True)
def _run_jobs_synchronously(request, monkeypatch):
    if request.node.get_closest_marker("real_executor") is None:
        monkeypatch.setattr(_jobs, "submit", lambda job_id: _jobs.process(job_id))
    yield
