"""
Script to create the initial superuser account
Run this once after setting up the database to create the first superuser
"""

import os
import sys
from sqlmodel import SQLModel, Session, select
from app.database import engine
from app.models.user import User, UserRole
from app.auth.security import hash_password
from app.core.config import settings


def create_superuser():
    # Create database tables if they don't exist
    SQLModel.metadata.create_all(bind=engine)
    
    # Create a session
    with Session(engine) as session:
        # Check if a superuser already exists
        existing_superuser = session.exec(
            select(User).where(User.is_superuser == True)
        ).first()
        
        if existing_superuser:
            print(f"A superuser already exists: {existing_superuser.email}")
            return
        
        # Get superuser credentials from environment variables or use defaults
        superuser_email = os.getenv("SUPERUSER_EMAIL", "admin@example.com")
        superuser_password = os.getenv("SUPERUSER_PASSWORD", "AdminPass123!")
        
        # Validate password strength
        if not validate_password(superuser_password):
            print("Superuser password does not meet requirements. Please use a stronger password.")
            return
            
        # Create the superuser
        superuser = User(
            email=superuser_email,
            hashed_password=hash_password(superuser_password),
            full_name="Administrator",
            role=UserRole.SUPERUSER,
            is_superuser=True,
            is_active=True,
            is_verified=True  # Mark as verified since it's created by admin
        )
        
        session.add(superuser)
        session.commit()
        session.refresh(superuser)
        
        print(f"Superuser created successfully!")
        print(f"Email: {superuser.email}")
        print(f"Password: {superuser_password} (change this immediately after first login)")
        print("IMPORTANT: Change the default password immediately after first login!")


def validate_password(password: str) -> bool:
    """Validate password meets minimum requirements"""
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        return False
    return True


if __name__ == "__main__":
    create_superuser()