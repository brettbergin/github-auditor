"""SQLite engine creation and schema initialization."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.pool import ConnectionPoolEntry

from github_auditor.cache.orm import SCHEMA_VERSION, Base
from github_auditor.exceptions import CacheError


def create_db_engine(db_path: Path | str) -> Engine:
    if isinstance(db_path, Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{db_path}"
    else:
        url = db_path  # allow "sqlite:///:memory:" style URLs (tests)

    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn: DBAPIConnection, _record: ConnectionPoolEntry) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def init_db(engine: Engine) -> None:
    with engine.connect() as conn:
        version = conn.execute(text("PRAGMA user_version")).scalar() or 0
        has_tables = bool(
            conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='repos'")
            ).first()
        )
        if has_tables and version != SCHEMA_VERSION:
            raise CacheError(
                f"Cache schema version {version} does not match expected {SCHEMA_VERSION}. "
                "Run 'gha cache clear' to rebuild the cache."
            )
        Base.metadata.create_all(conn)
        conn.execute(text(f"PRAGMA user_version = {SCHEMA_VERSION}"))
        conn.commit()
