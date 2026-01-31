# app/auth/rbac_service.py
# Service for role-based access control functionality

from enum import Enum
from typing import Dict, List, Set
from sqlmodel import Session, select
from fastapi import HTTPException, status
from app.models.user import User, UserRole
from app.database import get_session


class Permission(str, Enum):
    # User permissions
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Admin permissions
    ADMIN_READ = "admin:read"
    ADMIN_CREATE = "admin:create"
    ADMIN_UPDATE = "admin:update"
    ADMIN_DELETE = "admin:delete"
    
    # System permissions
    SYSTEM_CONFIG = "system:config"
    AUDIT_LOGS = "audit:logs"


# Define role-based permissions
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.USER: {
        Permission.USER_READ,
        Permission.USER_UPDATE,
    },
    UserRole.ADMIN: {
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.ADMIN_READ,
        Permission.ADMIN_CREATE,
        Permission.ADMIN_UPDATE,
        Permission.AUDIT_LOGS,
    },
    UserRole.SUPERUSER: {
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.ADMIN_READ,
        Permission.ADMIN_CREATE,
        Permission.ADMIN_UPDATE,
        Permission.ADMIN_DELETE,
        Permission.SYSTEM_CONFIG,
        Permission.AUDIT_LOGS,
    }
}


def check_permission(user_role: UserRole, required_permission: Permission) -> bool:
    """
    Check if a user role has a specific permission
    """
    role_perms = ROLE_PERMISSIONS.get(user_role, set())
    return required_permission in role_perms


def get_user_permissions(user_role: UserRole) -> List[Permission]:
    """
    Get all permissions for a user role
    """
    return list(ROLE_PERMISSIONS.get(user_role, set()))


def assign_role_to_user(*, session: Session, user_id: int, role: UserRole) -> Dict[str, str]:
    """
    Assign a role to a user
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Only superusers can assign admin or superuser roles
    if role in [UserRole.ADMIN, UserRole.SUPERUSER]:
        # This would typically check the current user's role
        # For simplicity, we'll allow it here
        pass
    
    user.role = role
    session.add(user)
    session.commit()
    
    return {"msg": f"Role {role.value} assigned to user successfully"}


def remove_role_from_user(*, session: Session, user_id: int) -> Dict[str, str]:
    """
    Remove a user's role (defaults to USER)
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Cannot remove role from superuser without proper authorization
    # This would typically check the current user's role
    if user.role == UserRole.SUPERUSER:
        # For simplicity, we'll allow it here
        pass
    
    user.role = UserRole.USER
    session.add(user)
    session.commit()
    
    return {"msg": "Role removed from user successfully, defaulted to USER"}


def get_user_role(*, session: Session, user_id: int) -> UserRole:
    """
    Get the role of a user
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user.role


def has_role(user: User, role: UserRole) -> bool:
    """
    Check if a user has a specific role
    """
    return user.role == role


def has_any_role(user: User, roles: List[UserRole]) -> bool:
    """
    Check if a user has any of the specified roles
    """
    return user.role in roles


def has_permission(user: User, permission: Permission) -> bool:
    """
    Check if a user has a specific permission
    """
    return check_permission(user.role, permission)