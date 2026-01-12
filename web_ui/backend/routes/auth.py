#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Authentication routes.
"""

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

from brsxss.auth import (
    User,
    UserCreate,
    UserUpdate,
    AuthConfig,
    hash_password,
    verify_password,
    create_token,
    verify_token,
)
from brsxss.auth.models import UserLogin, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_user_storage():
    """Get user storage from main storage module"""
    from ..storage import get_storage
    return get_storage()


def _is_auth_enabled() -> bool:
    """Check if authentication is enabled (reads from DB each time)"""
    storage = _get_user_storage()
    config = storage.get_auth_config()
    return config.auth_enabled


def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[User]:
    """Get current user from Authorization header"""
    if not _is_auth_enabled():
        return None  # Auth disabled, allow all
    
    if not authorization:
        return None
    
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            return None
        
        payload = verify_token(token)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        storage = _get_user_storage()
        return storage.get_user(user_id)
        
    except Exception:
        return None


def require_auth(authorization: Optional[str] = Header(None)) -> User:
    """Require authentication - raises 401 if not authenticated"""
    if not _is_auth_enabled():
        # Return dummy admin user when auth is disabled
        return User(
            id="system",
            username="admin",
            is_admin=True,
            is_active=True,
        )
    
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is disabled")
    return user


def require_admin(user: User = Depends(require_auth)) -> User:
    """Require admin privileges"""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Get current user ID if authenticated, None otherwise.
    
    Returns user_id string (not User object) for use in storage queries.
    When auth is disabled, returns None (show all data).
    """
    user = get_current_user(authorization)
    return user.id if user else None


# ============ Auth Config Routes ============

@router.get("/config")
async def get_auth_config() -> AuthConfig:
    """Get authentication configuration"""
    storage = _get_user_storage()
    return storage.get_auth_config()


@router.post("/config/first-run")
async def complete_first_run(
    enable_auth: bool,
    legal_accepted: bool,
    admin_user: Optional[UserCreate] = None,
):
    """
    Complete first run setup.
    - If enable_auth=True, admin_user is required
    - legal_accepted must be True to proceed
    """
    if not legal_accepted:
        raise HTTPException(
            status_code=400,
            detail="You must accept the legal disclaimer to use BRS-XSS"
        )
    
    storage = _get_user_storage()
    config = storage.get_auth_config()
    
    if config.first_run_completed:
        raise HTTPException(status_code=400, detail="First run already completed")
    
    if enable_auth:
        if not admin_user:
            raise HTTPException(
                status_code=400,
                detail="Admin user credentials required when enabling auth"
            )
        
        # Create admin user
        user_id = str(uuid.uuid4())[:8]
        user = User(
            id=user_id,
            username=admin_user.username,
            email=admin_user.email,
            is_admin=True,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        storage.create_user(user, hash_password(admin_user.password))
    
    # Update config
    new_config = AuthConfig(
        auth_enabled=enable_auth,
        first_run_completed=True,
        legal_accepted=True,
    )
    storage.save_auth_config(new_config)
    
    return {"status": "ok", "auth_enabled": enable_auth}


# ============ Login/Logout Routes ============

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login and get JWT token"""
    storage = _get_user_storage()
    config = storage.get_auth_config()
    
    if not config.auth_enabled:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    
    user = storage.get_user_by_username(credentials.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    password_hash = storage.get_user_password_hash(user.id)
    if not verify_password(credentials.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is disabled")
    
    # Update last login
    storage.update_user_last_login(user.id)
    
    # Create token
    token = create_token(user.id, user.username, user.is_admin)
    
    return TokenResponse(
        access_token=token,
        user=user,
    )


@router.get("/me", response_model=User)
async def get_current_user_info(user: User = Depends(require_auth)):
    """Get current user info"""
    return user


# ============ User Management Routes ============

@router.get("/users", response_model=list[User])
async def list_users(authorization: Optional[str] = Header(None)):
    """
    List all users.
    - If no users exist: anyone can access (to create first admin)
    - If users exist and auth enabled: admin only
    - If users exist and auth disabled: anyone can access
    """
    storage = _get_user_storage()
    users = storage.get_all_users()
    config = storage.get_auth_config()
    
    # If no users exist, allow access to create first admin
    if not users:
        return users
    
    # If auth is disabled, allow access
    if not config.auth_enabled:
        return users
    
    # Auth is enabled - require admin
    user = get_current_user(authorization)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    return users


@router.post("/users", response_model=User)
async def create_user(user_data: UserCreate, authorization: Optional[str] = Header(None)):
    """
    Create new user.
    - If no users exist: anyone can create first admin
    - If users exist and auth enabled: admin only
    - If users exist and auth disabled: anyone can create
    """
    storage = _get_user_storage()
    existing_users = storage.get_all_users()
    config = storage.get_auth_config()
    
    # If users exist and auth enabled, require admin
    if existing_users and config.auth_enabled:
        user = get_current_user(authorization)
        if not user or not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin privileges required")
    
    # Check if username exists
    existing = storage.get_user_by_username(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # First user is always admin
    is_first_user = len(existing_users) == 0
    
    user_id = str(uuid.uuid4())[:8]
    user = User(
        id=user_id,
        username=user_data.username,
        email=user_data.email,
        is_admin=user_data.is_admin or is_first_user,  # First user is always admin
        is_active=True,
        created_at=datetime.utcnow(),
    )
    
    storage.create_user(user, hash_password(user_data.password))
    
    # If this is first user and auth was not enabled, enable it now
    if is_first_user and not config.auth_enabled:
        new_config = AuthConfig(
            auth_enabled=True,
            first_run_completed=True,
            legal_accepted=config.legal_accepted,
        )
        storage.save_auth_config(new_config)
    
    return user


@router.put("/users/{user_id}", response_model=User)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    admin: User = Depends(require_admin),
):
    """Update user (admin only)"""
    storage = _get_user_storage()
    
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields
    if user_data.email is not None:
        user.email = user_data.email
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    storage.update_user(user)
    
    # Update password if provided
    if user_data.password:
        storage.update_user_password(user_id, hash_password(user_data.password))
    
    return user


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: User = Depends(require_admin)):
    """Delete user (admin only)"""
    storage = _get_user_storage()
    
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent deleting yourself
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    # Prevent deleting last admin
    all_users = storage.get_all_users()
    admin_count = sum(1 for u in all_users if u.is_admin and u.is_active)
    if user.is_admin and admin_count <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    
    storage.delete_user(user_id)
    return {"status": "ok"}
