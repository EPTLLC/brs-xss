#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - Domain profiles API
Telegram: https://t.me/EasyProTech

API routes for domain profile management (scan history per domain).
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from ..storage import get_storage
from .auth import get_current_user_optional

router = APIRouter(prefix="/api/domains", tags=["domains"])


class DomainProfileResponse(BaseModel):
    """Domain profile response model"""
    id: str
    domain: str
    user_id: Optional[str] = None
    total_scans: int = 0
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    waf_detected: Optional[str] = None
    waf_bypass_methods: list[str] = []
    successful_payloads: list[str] = []
    failed_payloads: list[str] = []
    successful_contexts: list[str] = []
    technologies: list[str] = []
    last_scan_id: Optional[str] = None
    last_scan_at: Optional[str] = None
    first_scan_at: Optional[str] = None
    notes: Optional[str] = None


class DomainProfileSummary(BaseModel):
    """Domain profile summary for list view"""
    id: str
    domain: str
    total_scans: int = 0
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    waf_detected: Optional[str] = None
    last_scan_at: Optional[str] = None
    first_scan_at: Optional[str] = None


class DomainLookupRequest(BaseModel):
    """Request to lookup domain by URL"""
    url: str


@router.get("", response_model=list[DomainProfileSummary])
async def get_domain_profiles(
    limit: int = 50,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Get all domain profiles for current user"""
    storage = get_storage()
    profiles = storage.get_domain_profiles(user_id=user_id, limit=limit)
    return [DomainProfileSummary(**p) for p in profiles]


@router.get("/lookup")
async def lookup_domain(
    url: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """
    Lookup domain profile by URL.
    
    This is called when user enters a URL in the scan form
    to show historical data for that domain.
    """
    from urllib.parse import urlparse
    
    storage = get_storage()
    
    # Extract domain from URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            # Try without scheme
            if "/" in url:
                domain = url.split("/")[0].lower()
            else:
                domain = url.lower()
    except Exception:
        domain = url.lower()
    
    # Get domain profile
    profile = storage.get_domain_profile(domain, user_id=user_id)
    
    if not profile:
        return {
            "found": False,
            "domain": domain,
            "message": "No previous scans for this domain"
        }
    
    # Get recent scans for this domain
    recent_scans = storage.get_domain_scans(domain, user_id=user_id, limit=5)
    
    return {
        "found": True,
        "domain": domain,
        "profile": DomainProfileResponse(**profile),
        "recent_scans": [
            {
                "id": s.id,
                "url": s.url,
                "status": s.status.value,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "vulnerability_count": s.vulnerability_count,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
            }
            for s in recent_scans
        ],
    }


@router.get("/{domain}", response_model=DomainProfileResponse)
async def get_domain_profile(
    domain: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Get domain profile by domain name"""
    storage = get_storage()
    profile = storage.get_domain_profile(domain, user_id=user_id)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Domain profile not found")
    
    return DomainProfileResponse(**profile)


@router.get("/{domain}/scans")
async def get_domain_scans(
    domain: str,
    limit: int = 10,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Get recent scans for a specific domain"""
    storage = get_storage()
    scans = storage.get_domain_scans(domain, user_id=user_id, limit=limit)
    
    return [
        {
            "id": s.id,
            "url": s.url,
            "mode": s.mode.value,
            "status": s.status.value,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": s.duration_seconds,
            "vulnerability_count": s.vulnerability_count,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
        }
        for s in scans
    ]


@router.get("/{domain}/payloads")
async def get_domain_successful_payloads(
    domain: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Get successful payloads for a domain"""
    storage = get_storage()
    profile = storage.get_domain_profile(domain, user_id=user_id)
    
    if not profile:
        return {"payloads": [], "contexts": []}
    
    return {
        "payloads": profile.get("successful_payloads", []),
        "contexts": profile.get("successful_contexts", []),
        "waf_bypass_methods": profile.get("waf_bypass_methods", []),
    }


@router.delete("/{profile_id}")
async def delete_domain_profile(
    profile_id: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Delete a domain profile"""
    storage = get_storage()
    deleted = storage.delete_domain_profile(profile_id, user_id=user_id)
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Domain profile not found")
    
    return {"deleted": True, "id": profile_id}
