"""Migration tests: fresh upgrade, legacy create_all() stamping, and model/migration drift."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from backend import db

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _cfg():
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "alembic"))
    return cfg


def _head():
    return ScriptDirectory.from_config(_cfg()).get_current_head()


@pytest.fixture()
def temp_engine(tmp_path, monkeypatch):
    eng = create_engine(f"sqlite:///{tmp_path / 'mig.db'}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(db, "engine", eng)
    yield eng
    eng.dispose()


def _version(eng):
    with eng.connect() as conn:
        return conn.execute(text("select version_num from alembic_version")).scalar()


def test_fresh_database_is_migrated_to_head(temp_engine):
    db.init_db()
    tables = set(inspect(temp_engine).get_table_names())
    assert {"scans", "findings", "alembic_version"} <= tables
    assert _version(temp_engine) == _head()


def test_init_db_is_idempotent(temp_engine):
    db.init_db()
    db.init_db()
    assert _version(temp_engine) == _head()


def test_legacy_create_all_database_is_stamped_not_recreated(temp_engine):
    db.Base.metadata.create_all(bind=temp_engine)
    with temp_engine.begin() as conn:
        conn.execute(
            text(
                "insert into scans (id, target, platform, status, created_at, owner_token) "
                "values ('s1', 'https://x.test', 'generic', 'completed', '2026-01-01', 't')"
            )
        )

    db.init_db()

    assert _version(temp_engine) == _head()
    with temp_engine.connect() as conn:
        assert conn.execute(text("select count(*) from scans")).scalar() == 1


def test_models_and_migrations_have_no_drift(temp_engine):
    db.init_db()
    with temp_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), db.Base.metadata)
    assert diff == [], f"models changed without a migration: {diff}"


def test_upgrading_a_populated_0001_database_adds_error_column_and_keeps_data(temp_engine):
    command.upgrade(_cfg(), "0001")
    with temp_engine.begin() as conn:
        conn.execute(
            text(
                "insert into scans (id, target, platform, status, created_at, owner_token) "
                "values ('s1', 'https://x.test', 'generic', 'completed', '2026-01-01', 't')"
            )
        )
    assert "error" not in {c["name"] for c in inspect(temp_engine).get_columns("scans")}

    db.init_db()

    assert "error" in {c["name"] for c in inspect(temp_engine).get_columns("scans")}
    with temp_engine.connect() as conn:
        row = conn.execute(text("select id, error from scans")).one()
    assert tuple(row) == ("s1", None)


def test_downgrade_removes_error_column(temp_engine):
    db.init_db()
    command.downgrade(_cfg(), "0001")
    assert "error" not in {c["name"] for c in inspect(temp_engine).get_columns("scans")}
