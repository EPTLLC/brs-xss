#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Authentication models.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class User(BaseModel):
    """User model"""
    id: str
    username: str
    email: Optional[str] = None
    is_admin: bool = False
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None


class UserCreate(BaseModel):
    """User creation request"""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)
    email: Optional[str] = None
    is_admin: bool = False


class UserUpdate(BaseModel):
    """User update request"""
    email: Optional[str] = None
    password: Optional[str] = Field(None, min_length=1, max_length=128)
    is_active: Optional[bool] = None


class UserLogin(BaseModel):
    """Login request"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    user: User


class AuthConfig(BaseModel):
    """Authentication configuration"""
    auth_enabled: bool = False
    first_run_completed: bool = False
    legal_accepted: bool = False
