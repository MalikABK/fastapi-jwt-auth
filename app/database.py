# app/database.py

from sqlmodel import SQLModel, create_engine, Session
from app.core.config import settings

DATABASE_URL = settings.database_url

engine = create_engine(
    DATABASE_URL,
    echo=False,   # set True only for debugging
    pool_size=20,  # Number of connections to maintain in the pool
    max_overflow=30,  # Additional connections beyond pool_size
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
)

def get_session():
    with Session(engine) as session:
        yield session
