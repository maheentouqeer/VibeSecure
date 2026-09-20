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
