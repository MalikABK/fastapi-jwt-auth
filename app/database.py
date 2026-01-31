# app/database.py

from sqlmodel import SQLModel, create_engine, Session
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = settings.database_url

try:
    engine = create_engine(
        DATABASE_URL,
        echo=False,   # set True only for debugging
        pool_size=20,  # Number of connections to maintain in the pool
        max_overflow=30,  # Additional connections beyond pool_size
        pool_pre_ping=True,  # Verify connections before use
        pool_recycle=3600,  # Recycle connections after 1 hour
    )
    logger.info(f"Database engine created successfully with URL: {DATABASE_URL[:50]}...")
except Exception as e:
    logger.error(f"Failed to create database engine with URL {DATABASE_URL}: {str(e)}")
    # Fallback to SQLite for development/testing if PostgreSQL driver is missing
    if "postgresql" in DATABASE_URL.lower():
        fallback_db_url = "sqlite:///./fallback_dev.db"
        logger.info(f"Falling back to SQLite: {fallback_db_url}")
        engine = create_engine(fallback_db_url, echo=False)
    else:
        raise e

def get_session():
    with Session(engine) as session:
        yield session
