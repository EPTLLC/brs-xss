#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Vulnerabilities storage module
Telegram: https://t.me/EasyProTech

Vulnerability operations and dashboard statistics.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, Any

from ..models import (
    VulnerabilityInfo,
    DashboardStats,
)


class VulnerabilitiesMixin:
    """Mixin for vulnerability operations"""

    db_path: str

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def get_recent_scans(self, limit: int = 20, user_id: Optional[str] = None) -> list:
        raise NotImplementedError

    def add_vulnerability(self, scan_id: str, vuln: VulnerabilityInfo):
        """Add vulnerability to scan"""
        conn = self._get_connection()
        cursor = conn.cursor()

        xss_type = getattr(vuln, "_xss_type", None) or getattr(vuln, "xss_type", None)
        reflection_type = getattr(vuln, "_reflection_type", None) or getattr(
            vuln, "reflection_type", None
        )
        sink = getattr(vuln, "_sink", None) or getattr(vuln, "sink", None)
        source = getattr(vuln, "_source", None) or getattr(vuln, "source", None)
        payload_class = getattr(vuln, "payload_class", None)
        trigger = getattr(vuln, "trigger", None)
        impact_scope = getattr(vuln, "impact_scope", None)
        confidence_level = getattr(vuln, "confidence_level", None)
        authorization_ref = getattr(vuln, "authorization_ref", None)
        test_mode = getattr(vuln, "test_mode", None)

        cursor.execute(
            """
            INSERT INTO vulnerabilities (
                id, scan_id, url, parameter, context_type, severity, confidence,
                payload, payload_id, payload_name, payload_description, payload_contexts, payload_tags,
                evidence, waf_detected, bypass_used, remediation, cwe_id, cvss_score,
                xss_type, reflection_type, sink, source, payload_class, trigger,
                impact_scope, confidence_level, authorization_ref, test_mode,
                found_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                vuln.id,
                scan_id,
                vuln.url,
                vuln.parameter,
                vuln.context_type,
                vuln.severity.value,
                vuln.confidence,
                vuln.payload,
                vuln.payload_id,
                vuln.payload_name,
                vuln.payload_description,
                (
                    json.dumps(vuln.payload_contexts)
                    if vuln.payload_contexts is not None
                    else None
                ),
                (
                    json.dumps(vuln.payload_tags)
                    if vuln.payload_tags is not None
                    else None
                ),
                vuln.evidence,
                vuln.waf_detected,
                vuln.bypass_used,
                vuln.remediation,
                vuln.cwe_id,
                vuln.cvss_score,
                xss_type,
                reflection_type,
                sink,
                source,
                payload_class,
                trigger,
                impact_scope,
                confidence_level,
                authorization_ref,
                test_mode,
                vuln.found_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def get_dashboard_stats(self, user_id: Optional[str] = None) -> DashboardStats:
        """Get dashboard statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        user_condition = "(user_id = ? OR user_id IS NULL)" if user_id else "1=1"

        # Total scans
        if user_id:
            cursor.execute(
                f"SELECT COUNT(*) FROM scans WHERE {user_condition}",
                (user_id,),
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        # Scans today
        today = datetime.utcnow().date().isoformat()
        if user_id:
            cursor.execute(
                f"SELECT COUNT(*) FROM scans WHERE DATE(started_at) = ? AND {user_condition}",
                (today, user_id),
            )
        else:
            cursor.execute(
                "SELECT COUNT(*) FROM scans WHERE DATE(started_at) = ?", (today,)
            )
        scans_today = cursor.fetchone()[0]

        # Scans this week
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        if user_id:
            cursor.execute(
                f"SELECT COUNT(*) FROM scans WHERE started_at >= ? AND {user_condition}",
                (week_ago, user_id),
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM scans WHERE started_at >= ?", (week_ago,))
        scans_week = cursor.fetchone()[0]

        # Total vulnerabilities (this week)
        if user_id:
            cursor.execute(
                f"""
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.started_at >= ? AND {user_condition}
            """,
                (week_ago, user_id),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.started_at >= ?
            """,
                (week_ago,),
            )
        total_vulns = cursor.fetchone()[0]

        # Critical vulnerabilities (this week)
        if user_id:
            cursor.execute(
                f"""
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.severity = 'critical' AND s.started_at >= ? AND {user_condition}
            """,
                (week_ago, user_id),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.severity = 'critical' AND s.started_at >= ?
            """,
                (week_ago,),
            )
        critical_vulns = cursor.fetchone()[0]

        # High vulnerabilities (this week)
        if user_id:
            cursor.execute(
                f"""
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.severity = 'high' AND s.started_at >= ? AND {user_condition}
            """,
                (week_ago, user_id),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.severity = 'high' AND s.started_at >= ?
            """,
                (week_ago,),
            )
        high_vulns = cursor.fetchone()[0]

        # Most common context
        cursor.execute(
            """
            SELECT context_type, COUNT(*) as cnt FROM vulnerabilities
            GROUP BY context_type ORDER BY cnt DESC LIMIT 1
        """
        )
        ctx_row = cursor.fetchone()
        most_common_context = ctx_row[0] if ctx_row else None

        # Average scan duration
        cursor.execute(
            """
            SELECT AVG(duration_seconds) FROM scans WHERE status = 'completed'
        """
        )
        avg_duration = cursor.fetchone()[0] or 0

        conn.close()

        return DashboardStats(
            total_scans=total_scans,
            scans_today=scans_today,
            scans_this_week=scans_week,
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            most_common_context=most_common_context,
            avg_scan_duration_seconds=avg_duration,
            recent_scans=self.get_recent_scans(5),
        )
