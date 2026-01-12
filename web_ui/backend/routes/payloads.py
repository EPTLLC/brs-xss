#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 13:26:17 UTC
Status: Created
Telegram: https://t.me/EasyProTech

User payloads management routes.
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

from .auth import get_current_user
from ..storage import get_storage

router = APIRouter(prefix="/payloads", tags=["payloads"])


class PayloadCreate(BaseModel):
    """Create payload request"""
    payload: str
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    context: Optional[str] = None


class PayloadUpdate(BaseModel):
    """Update payload request"""
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    context: Optional[str] = None


class PayloadResponse(BaseModel):
    """Payload response"""
    id: str
    user_id: Optional[str]
    payload: str
    name: Optional[str]
    description: Optional[str]
    tags: List[str]
    context: Optional[str]
    success_count: int
    fail_count: int
    last_used: Optional[str]
    created_at: str


def _get_user_id(authorization: Optional[str]) -> Optional[str]:
    """Extract user_id from auth header if auth is enabled"""
    storage = get_storage()
    config = storage.get_auth_config()
    if not config.auth_enabled:
        return None
    user = get_current_user(authorization)
    return user.id if user else None


@router.get("", response_model=List[PayloadResponse])
async def list_payloads(authorization: Optional[str] = Header(None)):
    """Get all saved payloads for current user"""
    storage = get_storage()
    user_id = _get_user_id(authorization)
    payloads = storage.get_user_payloads(user_id)
    return payloads


@router.post("", response_model=PayloadResponse)
async def create_payload(
    data: PayloadCreate,
    authorization: Optional[str] = Header(None),
):
    """Save a new payload"""
    storage = get_storage()
    user_id = _get_user_id(authorization)
    
    # Check if payload already exists
    if storage.payload_exists(data.payload, user_id):
        raise HTTPException(status_code=400, detail="Payload already exists")
    
    payload_id = storage.create_user_payload(
        payload=data.payload,
        user_id=user_id,
        name=data.name,
        description=data.description,
        tags=data.tags,
        context=data.context,
    )
    
    # Return created payload
    payloads = storage.get_user_payloads(user_id)
    for p in payloads:
        if p["id"] == payload_id:
            return p
    
    raise HTTPException(status_code=500, detail="Failed to create payload")


@router.put("/{payload_id}", response_model=PayloadResponse)
async def update_payload(
    payload_id: str,
    data: PayloadUpdate,
    authorization: Optional[str] = Header(None),
):
    """Update a saved payload"""
    storage = get_storage()
    user_id = _get_user_id(authorization)
    
    updated = storage.update_user_payload(
        payload_id=payload_id,
        name=data.name,
        description=data.description,
        tags=data.tags,
        context=data.context,
    )
    
    if not updated:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    # Return updated payload
    payloads = storage.get_user_payloads(user_id)
    for p in payloads:
        if p["id"] == payload_id:
            return p
    
    raise HTTPException(status_code=404, detail="Payload not found")


@router.delete("/{payload_id}")
async def delete_payload(
    payload_id: str,
    authorization: Optional[str] = Header(None),
):
    """Delete a saved payload"""
    storage = get_storage()
    user_id = _get_user_id(authorization)
    
    deleted = storage.delete_user_payload(payload_id, user_id)
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    return {"status": "deleted"}


@router.post("/{payload_id}/stats")
async def update_payload_stats(
    payload_id: str,
    success: bool = True,
):
    """Update payload success/fail stats"""
    storage = get_storage()
    storage.increment_payload_stats(payload_id, success)
    return {"status": "updated"}
