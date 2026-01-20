from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.auth.jwt import get_current_user, get_current_active_superuser
from app.models.user import User

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["tasks"])

# Example: Any authenticated user
@router.get("/me", response_model=User)
@limiter.limit("60/minute")  # Limit requests from authenticated users
def read_current_user(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    return current_user

# Example: Admin-only route
@router.get("/admin", response_model=User)
@limiter.limit("30/minute")  # Limit requests from admin users
def read_admin_data(
    request: Request,
    current_user: User = Depends(get_current_active_superuser)
):
    return current_user
