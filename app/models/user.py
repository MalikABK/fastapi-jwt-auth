# app/models/user.py

from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional
from pydantic import EmailStr, field_validator, ConfigDict
import re

class UserBase(SQLModel):
    email: EmailStr = Field(index=True, unique=True)
    is_active: bool = True
    is_superuser: bool = False

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not v:
            raise ValueError('Email is required')
        return v.lower().strip()

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    full_name: Optional[str] = None
    refresh_token: Optional[str] = None
    failed_login_attempts: int = Field(default=0)  # Track failed login attempts
    locked_until: Optional[datetime] = None  # When the account gets unlocked

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class UserPublic(UserBase):
    id: int
    full_name: Optional[str] = None
    created_at: datetime

class UserCreate(SQLModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('email')
    @classmethod
    def validate_create_email(cls, v):
        if not v:
            raise ValueError('Email is required')
        return v.lower().strip()

    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        if v is not None:
            v = v.strip()
            if len(v) > 100:
                raise ValueError('Full name must not exceed 100 characters')
        return v

class UserUpdate(SQLModel):
    email: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None
    is_superuser: Optional[bool] = None

    @field_validator('password')
    @classmethod
    def validate_update_password(cls, v):
        if v is not None:
            if len(v) < 8:
                raise ValueError('Password must be at least 8 characters long')
            if not re.search(r'[A-Z]', v):
                raise ValueError('Password must contain at least one uppercase letter')
            if not re.search(r'[a-z]', v):
                raise ValueError('Password must contain at least one lowercase letter')
            if not re.search(r'\d', v):
                raise ValueError('Password must contain at least one digit')
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
                raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('email')
    @classmethod
    def validate_update_email(cls, v):
        if v is not None:
            v = v.strip().lower()
        return v

    @field_validator('full_name')
    @classmethod
    def validate_update_full_name(cls, v):
        if v is not None:
            v = v.strip()
            if len(v) > 100:
                raise ValueError('Full name must not exceed 100 characters')
        return v
