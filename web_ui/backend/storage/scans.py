#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Scans storage module
Telegram: https://t.me/EasyProTech

Scan operations: create, update, get, delete scans.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Any

from ..models import (
    ScanResult,
    ScanSummary,
    ScanStatus,
    ScanMode,
    PerformanceMode,
    VulnerabilityInfo,
    WAFInfo,
    ProxyUsed,
)


class ScansMixin:
    """Mixin for scan operations"""

    db_path: str

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _get_kb_payload_info(self, payload: str) -> dict[str, Any]:
        raise NotImplementedError

    def create_scan(
        self,
        scan_id: str,
        url: str,
        mode: ScanMode,
        performance_mode: str = "standard",
        settings: Optional[dict[str, Any]] = None,
        proxy_used: Optional[dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Create new scan record"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans (id, url, mode, performance_mode, status, started_at, settings, proxy_used, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan_id,
                url,
                mode.value,
                performance_mode,
                ScanStatus.PENDING.value,
                datetime.utcnow().isoformat(),
                json.dumps(settings) if settings else None,
                json.dumps(proxy_used) if proxy_used else None,
                user_id,
            ),
        )

        conn.commit()
        conn.close()
        return scan_id

    def update_scan_status(
        self, scan_id: str, status: ScanStatus, error_message: Optional[str] = None
    ):
        """Update scan status"""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = ["status = ?"]
        values = [status.value]

        if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            updates.append("completed_at = ?")
            values.append(datetime.utcnow().isoformat())

        if error_message:
            updates.append("error_message = ?")
            values.append(error_message)

        values.append(scan_id)

        cursor.execute(
            f"""
            UPDATE scans SET {', '.join(updates)} WHERE id = ?
        """,
            values,
        )

        conn.commit()
        conn.close()

    def update_scan_progress(
        self,
        scan_id: str,
        urls_scanned: int = 0,
        parameters_tested: int = 0,
        payloads_sent: int = 0,
        duration_seconds: float = 0,
    ):
        """Update scan progress metrics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE scans SET
                urls_scanned = ?,
                parameters_tested = ?,
                payloads_sent = ?,
                duration_seconds = ?
            WHERE id = ?
        """,
            (urls_scanned, parameters_tested, payloads_sent, duration_seconds, scan_id),
        )

        conn.commit()
        conn.close()

    def set_waf_info(self, scan_id: str, waf_info: WAFInfo):
        """Set detected WAF info"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE scans SET waf_info = ? WHERE id = ?
        """,
            (waf_info.model_dump_json(), scan_id),
        )

        conn.commit()
        conn.close()

    def set_target_profile(self, scan_id: str, profile: dict[str, Any]):
        """Store target reconnaissance profile"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO target_profiles (scan_id, profile_data, created_at)
            VALUES (?, ?, ?)
        """,
            (scan_id, json.dumps(profile), datetime.utcnow().isoformat()),
        )

        conn.commit()
        conn.close()

    def get_target_profile(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Get target reconnaissance profile"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT profile_data FROM target_profiles WHERE scan_id = ?
        """,
            (scan_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            try:
                return json.loads(row[0])
            except json.JSONDecodeError:
                return None
        return None

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan by ID with vulnerabilities"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, url, mode, status, started_at, completed_at,
                   urls_scanned, parameters_tested, payloads_sent,
                   duration_seconds, waf_info, notes, error_message,
                   performance_mode
            FROM scans WHERE id = ?
        """,
            (scan_id,),
        )

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        cursor.execute(
            """
            SELECT id, url, parameter, context_type, severity, confidence,
                   payload, payload_id, payload_name, payload_description, payload_contexts, payload_tags,
                   evidence, waf_detected, bypass_used, remediation,
                   cwe_id, cvss_score,
                   xss_type, reflection_type, sink, source, payload_class, trigger,
                   impact_scope, confidence_level, authorization_ref, test_mode,
                   found_at
            FROM vulnerabilities WHERE scan_id = ?
            ORDER BY severity, found_at
        """,
            (scan_id,),
        )

        vuln_rows = cursor.fetchall()
        conn.close()

        vulnerabilities = self._parse_vulnerabilities(vuln_rows)

        from brsxss.count import count_findings
        counts = count_findings(vulnerabilities)

        waf_info = None
        if row[10]:
            try:
                waf_info = WAFInfo.model_validate_json(row[10])
            except Exception:
                pass

        return ScanResult(
            id=row[0],
            url=row[1],
            mode=ScanMode(row[2]),
            status=ScanStatus(row[3]),
            started_at=datetime.fromisoformat(row[4]),
            completed_at=datetime.fromisoformat(row[5]) if row[5] else None,
            vulnerabilities=vulnerabilities,
            waf_detected=waf_info,
            urls_scanned=row[6] or 0,
            parameters_tested=row[7] or 0,
            payloads_sent=row[8] or 0,
            critical_count=counts.critical,
            high_count=counts.high,
            medium_count=counts.medium,
            low_count=counts.low,
            duration_seconds=row[9] or 0,
            notes=row[11],
            error_message=row[12],
            performance_mode=PerformanceMode(row[13]) if row[13] else None,
        )

    def _parse_vulnerabilities(self, vuln_rows: list) -> list[VulnerabilityInfo]:
        """Parse vulnerability rows into VulnerabilityInfo objects"""
        vulnerabilities = []
        for v in vuln_rows:
            payload_str = v[6] or ""
            ctx = v[3] or "unknown"
            param = v[2] or "unknown"

            db_xss_type = v[18] if len(v) > 18 else None
            db_reflection_type = v[19] if len(v) > 19 else None
            db_sink = v[20] if len(v) > 20 else None
            db_source = v[21] if len(v) > 21 else None

            is_dom_xss = (
                db_reflection_type == "dom_based"
                or db_xss_type == "DOM-Based XSS"
                or "->" in ctx
                or "DOM" in ctx
                or "dom" in ctx.lower()
            )

            if is_dom_xss and (
                not param
                or param == "N/A"
                or param == "unknown"
                or "N/A (DOM source)" in param
            ):
                if db_source:
                    param = f"DOM source: {db_source}"
                elif "->" in ctx:
                    source = ctx.split("->")[0].strip()
                    param = f"DOM source: {source}"
                else:
                    param = "DOM source: form input"

            found_at_idx = 28

            db_payload_id = v[7] if len(v) > 7 else None
            db_payload_name = v[8] if len(v) > 8 else None
            db_payload_description = v[9] if len(v) > 9 else None
            db_payload_contexts_raw = v[10] if len(v) > 10 else None
            db_payload_tags_raw = v[11] if len(v) > 11 else None
            try:
                db_payload_contexts = (
                    json.loads(db_payload_contexts_raw)
                    if db_payload_contexts_raw
                    else None
                )
            except Exception:
                db_payload_contexts = None
            try:
                db_payload_tags = (
                    json.loads(db_payload_tags_raw) if db_payload_tags_raw else None
                )
            except Exception:
                db_payload_tags = None

            kb_info: dict[str, Any] = {}
            need_kb = (
                not db_payload_id
                or not db_payload_name
                or not db_payload_description
                or db_payload_contexts is None
                or db_payload_tags is None
                or (v[17] is None)
            )
            if need_kb:
                kb_info = self._get_kb_payload_info(payload_str)

            cvss_score = (
                v[17]
                if len(v) > 17 and v[17] is not None
                else kb_info.get("cvss_score")
            )

            vuln_info = VulnerabilityInfo(
                id=v[0],
                url=v[1],
                parameter=param,
                context_type=ctx,
                severity=v[4],
                confidence=v[5],
                payload=payload_str,
                payload_id=db_payload_id or kb_info.get("id"),
                payload_name=db_payload_name or kb_info.get("name"),
                payload_description=db_payload_description
                or kb_info.get("description"),
                payload_contexts=db_payload_contexts or kb_info.get("contexts"),
                payload_tags=db_payload_tags or kb_info.get("tags"),
                cvss_score=cvss_score,
                evidence=v[12],
                waf_detected=v[13],
                bypass_used=v[14],
                remediation=v[15],
                cwe_id=v[16],
                found_at=(
                    datetime.fromisoformat(v[found_at_idx])
                    if len(v) > found_at_idx and v[found_at_idx]
                    else datetime.utcnow()
                ),
            )

            vuln_info.xss_type = db_xss_type or (
                "DOM-Based XSS" if is_dom_xss else "Reflected XSS"
            )
            vuln_info.reflection_type = db_reflection_type or (
                "dom_based" if is_dom_xss else "reflected"
            )
            vuln_info.sink = db_sink or (
                ctx.split("->")[-1].strip() if "->" in ctx else ""
            )
            vuln_info.source = db_source or (
                ctx.split("->")[0].strip() if "->" in ctx else ""
            )

            if len(v) > 22:
                vuln_info.payload_class = v[22] if len(v) > 22 else None
                vuln_info.trigger = v[23] if len(v) > 23 else None
                vuln_info.impact_scope = v[24] if len(v) > 24 else None
                vuln_info.confidence_level = v[25] if len(v) > 25 else None
                vuln_info.authorization_ref = v[26] if len(v) > 26 else None
                vuln_info.test_mode = v[27] if len(v) > 27 else None

            vulnerabilities.append(vuln_info)

        return vulnerabilities

    def get_recent_scans(self, limit: int = 20, user_id: Optional[str] = None) -> list[ScanSummary]:
        """Get recent scans summary"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT s.id, s.url, s.mode, s.performance_mode, s.status, s.started_at, s.completed_at,
                       s.duration_seconds, s.proxy_used,
                       COUNT(v.id) as vuln_count,
                       SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high
                FROM scans s
                LEFT JOIN vulnerabilities v ON s.id = v.scan_id
                WHERE s.user_id = ? OR s.user_id IS NULL
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
            """,
                (user_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT s.id, s.url, s.mode, s.performance_mode, s.status, s.started_at, s.completed_at,
                       s.duration_seconds, s.proxy_used,
                       COUNT(v.id) as vuln_count,
                       SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high
                FROM scans s
                LEFT JOIN vulnerabilities v ON s.id = v.scan_id
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
            """,
                (limit,),
            )

        rows = cursor.fetchall()
        conn.close()

        return self._parse_scan_summaries(rows)

    def _parse_scan_summaries(self, rows: list) -> list[ScanSummary]:
        """Parse scan summary rows"""
        results = []
        for r in rows:
            proxy_data = None
            if r[8]:
                try:
                    proxy_dict = json.loads(r[8])
                    proxy_data = ProxyUsed(**proxy_dict)
                except Exception:
                    pass

            results.append(
                ScanSummary(
                    id=r[0],
                    url=r[1],
                    mode=ScanMode(r[2]),
                    performance_mode=r[3] or "standard",
                    status=ScanStatus(r[4]),
                    started_at=datetime.fromisoformat(r[5]),
                    completed_at=datetime.fromisoformat(r[6]) if r[6] else None,
                    duration_seconds=r[7] or 0,
                    vulnerability_count=r[9] or 0,
                    critical_count=r[10] or 0,
                    high_count=r[11] or 0,
                    proxy_used=proxy_data,
                )
            )

        return results

    def get_proxy_used(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Get proxy_used data for a scan"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT proxy_used FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            try:
                return json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def delete_scan(self, scan_id: str) -> bool:
        """Delete scan and its vulnerabilities"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM scans WHERE id = ?", (scan_id,))
        if not cursor.fetchone():
            conn.close()
            return False

        cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM target_profiles WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

        conn.commit()
        conn.close()

        return True

    def get_user_scans(self, user_id: str, limit: int = 20) -> list[ScanSummary]:
        """Get scans for specific user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT s.id, s.url, s.mode, s.performance_mode, s.status, s.started_at, s.completed_at,
                   s.duration_seconds, s.proxy_used,
                   COUNT(v.id) as vuln_count,
                   SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            WHERE s.user_id = ? OR s.user_id IS NULL
            GROUP BY s.id
            ORDER BY s.started_at DESC
            LIMIT ?
        """,
            (user_id, limit),
        )

        rows = cursor.fetchall()
        conn.close()

        return self._parse_scan_summaries(rows)
