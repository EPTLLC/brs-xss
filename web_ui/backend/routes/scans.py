#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Scan management routes.
"""

from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Header
from ..models import ScanRequest, ScanResult, ScanSummary, ScanStatus
from .auth import get_current_user


def register(app: FastAPI, storage, scanner_service):
    """Register scan routes"""

    def _get_user_id(authorization: Optional[str]) -> Optional[str]:
        """Extract user_id from auth header if auth is enabled"""
        config = storage.get_auth_config()
        if not config.auth_enabled:
            return None
        user = get_current_user(authorization)
        return user.id if user else None

    @app.post("/api/scans", response_model=dict)
    async def create_scan(request: ScanRequest, authorization: Optional[str] = Header(None)):
        """Start a new scan"""
        user_id = _get_user_id(authorization)
        scan_id = await scanner_service.start_scan(request, user_id=user_id)
        return {"scan_id": scan_id, "status": "started"}

    @app.get("/api/scans", response_model=list[ScanSummary])
    async def list_scans(
        limit: int = Query(20, le=100),
        status: Optional[ScanStatus] = None,
        authorization: Optional[str] = Header(None),
    ):
        """list recent scans"""
        user_id = _get_user_id(authorization)
        scans = storage.get_recent_scans(limit, user_id=user_id)
        if status:
            scans = [s for s in scans if s.status == status]
        return scans

    @app.get("/api/scans/{scan_id}", response_model=ScanResult)
    async def get_scan(scan_id: str):
        """Get scan details"""
        result = storage.get_scan(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        return result

    @app.delete("/api/scans/{scan_id}")
    async def delete_scan(scan_id: str):
        """Delete a scan"""
        if not storage.delete_scan(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "deleted"}

    @app.post("/api/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str):
        """Cancel a running scan"""
        if scanner_service.cancel_scan(scan_id):
            return {"status": "cancelling"}
        raise HTTPException(status_code=404, detail="Scan not running")

    @app.get("/api/scans/{scan_id}/recon")
    async def get_scan_recon(scan_id: str):
        """Get target reconnaissance profile for scan"""
        profile = storage.get_target_profile(scan_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Reconnaissance data not found")
        return profile

    @app.post("/api/scans/{scan_id}/telegram")
    async def send_scan_to_telegram(scan_id: str):
        """Send completed scan report to Telegram"""
        from brsxss.integrations.telegram_service import telegram_service

        if not telegram_service.is_configured:
            raise HTTPException(status_code=400, detail="Telegram not configured")

        scan = storage.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        status_str = (
            scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        )
        if status_str != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")

        mode_str = scan.mode.value if hasattr(scan.mode, "value") else str(scan.mode)

        profile = storage.get_target_profile(scan_id)
        proxy_used = storage.get_proxy_used(scan_id)
        proxy_str = "Direct IP"
        if proxy_used and proxy_used.get("enabled"):
            country = proxy_used.get("country", "")
            ip = proxy_used.get("ip", "")
            proxy_str = f"{country} ({ip})" if country else ip

        duration = 0
        if scan.started_at and scan.completed_at:
            start_str = str(scan.started_at)
            end_str = str(scan.completed_at)
            try:
                start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                duration = int((end - start).total_seconds())
            except Exception:
                duration = scan.duration_seconds or 0

        # Use count/ module - SINGLE SOURCE OF TRUTH
        from brsxss.count import count_findings, prepare_report_data

        vulns = scan.vulnerabilities or []
        counts = count_findings(vulns)
        report_data = prepare_report_data(vulns)

        await telegram_service.on_scan_completed(
            scan_id=scan_id,
            target=scan.url,
            mode=mode_str,
            duration_seconds=duration,
            proxy=proxy_str,
            total_vulns=counts.total,
            critical=counts.critical,
            high=counts.high,
            medium=counts.medium,
            low=counts.low,
            urls_scanned=scan.urls_scanned or 0,
            payloads_sent=scan.payloads_sent or 0,
            target_profile=profile,
            vulnerabilities=report_data.to_dict(),
        )

        return {"status": "sent", "scan_id": scan_id}
