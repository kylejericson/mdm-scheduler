from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine)
    _add_missing_columns()


def _add_missing_columns():
    """Tiny forward-only migration.

    create_all() creates new tables but never alters existing ones, so a
    database written by an older version is missing columns added since. SQLite
    supports ADD COLUMN with a constant default, which covers every column this
    app has added so far. Anything more involved would need a real migration
    tool; this exists so an upgrade never needs one for a simple field.
    """
    additions = {
        "instances": {
            "vendor": "TEXT NOT NULL DEFAULT 'jamf'",
            "api_token_enc": "TEXT NOT NULL DEFAULT ''",
        },
        "branding": {
            "tls_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "tls_hostname": "TEXT NOT NULL DEFAULT ''",
            "tls_email": "TEXT NOT NULL DEFAULT ''",
            "tls_challenge": "TEXT NOT NULL DEFAULT 'http'",
            "tls_dns_provider": "TEXT NOT NULL DEFAULT 'ionos'",
            "tls_dns_token_enc": "TEXT NOT NULL DEFAULT ''",
            "tls_staging": "BOOLEAN NOT NULL DEFAULT 0",
        },
    }
    with engine.begin() as conn:
        for table, columns in additions.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            if not existing:
                continue  # table not created yet; create_all will have handled it
            for name, ddl in columns.items():
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
