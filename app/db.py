from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_database_url


DATABASE_URL = get_database_url()

# ── Sync engine (used by worker, background tasks, CLI) ───────────────────
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,         # detect stale connections
    pool_size=10,               # default pool
    max_overflow=20,            # extra connections under load
    pool_recycle=1800,          # recycle connections every 30 min
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Async engine (used by FastAPI async endpoints, if needed) ────────────
# Only initialised when an async-compatible database URL is provided.
# Convert sync URL → async URL automatically.
def _async_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return url


_async_engine = None
AsyncSessionLocal = None

try:
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker as async_sessionmaker

    _async_url_str = _async_url(DATABASE_URL)
    # Only create async engine if the driver is available and URL is convertible
    if _async_url_str != DATABASE_URL:
        _async_engine = create_async_engine(
            _async_url_str,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
        AsyncSessionLocal = async_sessionmaker(  # type: ignore[call-overload]
            _async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
except Exception:
    # Async drivers not installed — sync-only mode, fully supported
    pass


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Create all tables using the sync engine."""
    Base.metadata.create_all(bind=engine)


async def init_db_async() -> None:
    """Create all tables using the async engine (call once at startup if using async)."""
    if _async_engine is None:
        init_db()
        return
    async with _async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def get_db():
    """FastAPI dependency: yields a sync SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db():
    """FastAPI dependency: yields an async SQLAlchemy session.

    Falls back to sync session wrapped in a threadpool if async engine
    is unavailable (e.g. SQLite without aiosqlite installed).
    """
    if AsyncSessionLocal is not None:
        async with AsyncSessionLocal() as session:
            yield session
    else:
        # Fallback: run sync session (acceptable for dev/SQLite)
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

