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
from typing import Optional, Any
from fastapi import FastAPI, HTTPException, Query
from ..models import ScanRequest, ScanResult, ScanSummary, ScanStatus


def register(app: FastAPI, storage, scanner_service):
    """Register scan routes"""

    @app.post("/api/scans", response_model=dict)
    async def create_scan(request: ScanRequest):
        """Start a new scan"""
        scan_id = await scanner_service.start_scan(request)
        return {"scan_id": scan_id, "status": "started"}

    @app.get("/api/scans", response_model=list[ScanSummary])
    async def list_scans(
        limit: int = Query(20, le=100), status: Optional[ScanStatus] = None
    ):
        """list recent scans"""
        scans = storage.get_recent_scans(limit)
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
                duration = (end - start).total_seconds()
            except Exception:
                duration = scan.duration_seconds or 0

        vulns = []
        for v in scan.vulnerabilities or []:
            if hasattr(v, "model_dump"):
                vulns.append(v.model_dump())
            elif hasattr(v, "dict"):
                vulns.append(v.dict())
            elif isinstance(v, dict):
                vulns.append(v)
            else:
                vulns.append(
                    {
                        "severity": getattr(v, "severity", "unknown"),
                        "url": getattr(v, "url", ""),
                        "parameter": getattr(v, "parameter", ""),
                        "payload": getattr(v, "payload", ""),
                        "context_type": getattr(v, "context_type", ""),
                    }
                )

        # v4.0.0 Phase 9: Apply unified normalization
        confirmed_vulns: list[dict[str, Any]] = []
        try:
            from brsxss.core.finding_normalizer import prepare_findings_for_report

            normalized = prepare_findings_for_report(vulns, mode=mode_str)
            confirmed_vulns = normalized.get("confirmed", [])
            normalized.get("potential", [])
        except ImportError:
            confirmed_vulns = vulns
            normalized = {"confirmed": confirmed_vulns, "potential": []}

        critical = sum(1 for v in confirmed_vulns if v.get("severity") == "critical")
        high = sum(1 for v in confirmed_vulns if v.get("severity") == "high")
        medium = sum(1 for v in confirmed_vulns if v.get("severity") == "medium")
        low = sum(1 for v in confirmed_vulns if v.get("severity") == "low")

        await telegram_service.on_scan_completed(
            scan_id=scan_id,
            target=scan.url,
            mode=mode_str,
            duration_seconds=duration,
            proxy=proxy_str,
            total_vulns=len(confirmed_vulns),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            urls_scanned=scan.urls_scanned or 0,
            payloads_sent=scan.payloads_sent or 0,
            target_profile=profile,
            vulnerabilities=normalized,
        )

        return {"status": "sent", "scan_id": scan_id}
