# app/database_optimized.py
# Optimized database connection handling with pooling

from sqlmodel import create_engine
from sqlalchemy.pool import QueuePool
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create an optimized database engine with connection pooling
engine = create_engine(
    settings.database_url,
    poolclass=QueuePool,
    pool_size=20,  # Number of connections to maintain in the pool
    max_overflow=30,  # Number of connections that can be created beyond pool_size
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=3600,  # Recycle connections after 1 hour
    echo=False,  # Set to True for SQL debugging
    connect_args={
        "connect_timeout": 10,  # Timeout for establishing connections
    }
)


def get_optimized_session():
    """
    Get a database session with optimized settings
    """
    with engine.begin() as conn:
        yield conn


async def health_check_db():
    """
    Perform a health check on the database connection
    """
    try:
        with engine.connect() as conn:
            # Execute a simple query to test the connection
            result = conn.execute("SELECT 1")
            row = result.fetchone()
            return row is not None
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def get_pool_status():
    """
    Get information about the connection pool status
    """
    pool = engine.pool
    return {
        "pool_size": pool.size(),
        "checked_in_connections": pool.checkedin(),
        "checked_out_connections": pool.checkedout(),
        "overflow_connections": pool.overflow(),
        "pool_hits": getattr(pool, '_pool_gettime', 0),
    }