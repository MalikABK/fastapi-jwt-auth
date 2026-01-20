from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional


class TokenBlacklist(SQLModel, table=True):
    """
    Model to store blacklisted tokens for revocation.
    This allows us to maintain a list of tokens that should be considered invalid
    even if they haven't expired yet.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True)  # The JWT token to blacklist
    user_id: int = Field(index=True)  # Reference to the user who owns the token
    token_type: str = Field(default="access")  # Type of token: access, refresh
    expires_at: datetime  # When this token was originally set to expire
    blacklisted_at: datetime = Field(default_factory=datetime.utcnow)  # When it was blacklisted
    reason: Optional[str] = Field(default=None)  # Reason for blacklisting (optional)

    class Config:
        arbitrary_types_allowed = True