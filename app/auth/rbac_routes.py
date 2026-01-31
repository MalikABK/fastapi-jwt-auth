# app/auth/rbac_routes.py
# Routes for role-based access control functionality

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from typing import List

from app.database import get_session
from app.auth.rbac_service import (
    Permission, UserRole, check_permission,
    get_user_permissions, assign_role_to_user,
    remove_role_from_user, get_user_role,
    has_role, has_any_role, has_permission
)
from app.auth.jwt import get_current_user, get_current_active_superuser
from app.models.user import User


router = APIRouter(tags=["rbac"])


def require_permission(permission: Permission):
    """
    Dependency to check if the current user has a specific permission
    """
    def permission_checker(current_user: User = Depends(get_current_user)):
        if not has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return permission_checker


def require_role(role: UserRole):
    """
    Dependency to check if the current user has a specific role
    """
    def role_checker(current_user: User = Depends(get_current_user)):
        if not has_role(current_user, role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role privileges"
            )
        return current_user
    return role_checker


def require_any_role(roles: List[UserRole]):
    """
    Dependency to check if the current user has any of the specified roles
    """
    def role_checker(current_user: User = Depends(get_current_user)):
        if not has_any_role(current_user, roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role privileges"
            )
        return current_user
    return role_checker


@router.get("/permissions/my-permissions")
def get_my_permissions(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Get the permissions of the current user.
    """
    permissions = get_user_permissions(current_user.role)
    return {
        "user_id": current_user.id,
        "role": current_user.role.value,
        "permissions": [perm.value for perm in permissions]
    }


@router.get("/permissions/check/{permission}")
def check_my_permission(
    permission: Permission,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """
    Check if the current user has a specific permission.
    """
    has_perm = has_permission(current_user, permission)
    return {
        "permission": permission.value,
        "has_permission": has_perm
    }


@router.get("/users/{user_id}/role")
def get_user_role_endpoint(
    user_id: int,
    current_user: User = Depends(require_permission(Permission.ADMIN_READ)),
    session: Session = Depends(get_session)
):
    """
    Get the role of a specific user (admin only).
    """
    role = get_user_role(session=session, user_id=user_id)
    return {
        "user_id": user_id,
        "role": role.value
    }


@router.post("/users/{user_id}/assign-role/{role}")
def assign_role_endpoint(
    user_id: int,
    role: UserRole,
    current_user: User = Depends(require_permission(Permission.ADMIN_UPDATE)),
    session: Session = Depends(get_session)
):
    """
    Assign a role to a user (admin only).
    """
    # Prevent assigning roles higher than the current user's role
    if role == UserRole.SUPERUSER and current_user.role != UserRole.SUPERUSER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can assign superuser role"
        )

    return assign_role_to_user(session=session, user_id=user_id, role=role)


@router.post("/users/{user_id}/remove-role")
def remove_role_endpoint(
    user_id: int,
    current_user: User = Depends(require_permission(Permission.ADMIN_UPDATE)),
    session: Session = Depends(get_session)
):
    """
    Remove a user's role (admin only).
    """
    # Prevent removing role from superuser without proper authorization
    user_to_modify = session.get(User, user_id)
    if user_to_modify and user_to_modify.role == UserRole.SUPERUSER and current_user.role != UserRole.SUPERUSER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can modify superuser roles"
        )

    return remove_role_from_user(session=session, user_id=user_id)


@router.get("/admin/users-with-role/{role}")
def get_users_with_role(
    role: UserRole,
    current_user: User = Depends(require_permission(Permission.AUDIT_LOGS)),
    session: Session = Depends(get_session)
):
    """
    Get all users with a specific role (audit/logs permission required).
    """
    statement = select(User).where(User.role == role)
    users = session.exec(statement).all()

    return {
        "role": role.value,
        "users": [
            {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_active": user.is_active,
                "created_at": user.created_at
            } for user in users
        ]
    }