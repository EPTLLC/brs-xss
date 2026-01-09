#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SQLite storage for scans and results.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from .models import (
    ScanResult,
    ScanSummary,
    ScanStatus,
    ScanMode,
    PerformanceMode,
    VulnerabilityInfo,
    WAFInfo,
    DashboardStats,
    SettingsModel,
)


class ScanStorage:
    """SQLite storage for scan data"""

    _kb_payload_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, db_path: str = "brsxss_ui.db"):
        self.db_path = db_path
        self._init_db()
        self._recover_stale_scans()

    def _normalize_kb_payload_info(self, raw: Any) -> Dict[str, Any]:
        """Normalize KB analyze response into VulnerabilityInfo-compatible fields."""
        if not raw or not isinstance(raw, dict):
            return {}
        data = raw.get("payload") or raw.get("result") or raw.get("data") or raw
        if not isinstance(data, dict):
            return {}

        payload_id = data.get("id") or data.get("payload_id") or data.get("key")
        payload_name = data.get("name") or data.get("title") or None
        payload_description = data.get("description") or data.get("details") or None
        severity = data.get("severity") or data.get("risk") or None
        cvss_score = data.get("cvss_score") or data.get("cvss") or None
        contexts = data.get("contexts") or data.get("context_types") or None
        tags = data.get("tags") or data.get("labels") or None

        def _norm_list(value):
            if not isinstance(value, list):
                return None
            out = []
            for item in value:
                if isinstance(item, str):
                    v = item.strip()
                    if v:
                        out.append(v)
                elif isinstance(item, dict):
                    v = (
                        item.get("name") or item.get("id") or item.get("key") or ""
                    ).strip()
                    if v:
                        out.append(v)
            return out or None

        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except Exception:
            cvss_score = None

        if isinstance(severity, str):
            severity = severity.strip().lower() or None

        return {
            "id": payload_id,
            "name": payload_name,
            "description": payload_description,
            "severity": severity,
            "cvss_score": cvss_score,
            "contexts": _norm_list(contexts),
            "tags": _norm_list(tags),
        }

    def _get_kb_payload_info(self, payload: str) -> Dict[str, Any]:
        """Get payload metadata from KB (remote) with process cache."""
        payload = payload or ""
        if not payload:
            return {}
        cached = ScanStorage._kb_payload_cache.get(payload)
        if cached is not None:
            return cached

        info: Dict[str, Any] = {}
        try:
            from brsxss.payloads.kb_adapter import get_kb_adapter

            kb = get_kb_adapter()
            if getattr(kb, "is_available", False):
                raw = kb.analyze_payload(payload)
                info = self._normalize_kb_payload_info(raw)
        except Exception:
            info = {}

        ScanStorage._kb_payload_cache[payload] = info
        return info

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Scans table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                mode TEXT NOT NULL,
                performance_mode TEXT DEFAULT 'standard',
                status TEXT NOT NULL,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                urls_scanned INTEGER DEFAULT 0,
                parameters_tested INTEGER DEFAULT 0,
                payloads_sent INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0,
                waf_info TEXT,
                notes TEXT,
                error_message TEXT,
                settings TEXT
            )
        """
        )

        # Add performance_mode column if not exists (migration)
        try:
            cursor.execute(
                "ALTER TABLE scans ADD COLUMN performance_mode TEXT DEFAULT 'standard'"
            )
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Add proxy_used column if not exists (migration)
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN proxy_used TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Vulnerabilities table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                parameter TEXT NOT NULL,
                context_type TEXT,
                severity TEXT NOT NULL,
                confidence REAL DEFAULT 0,
                payload TEXT,
                payload_id TEXT,
                payload_name TEXT,
                payload_description TEXT,
                payload_contexts TEXT,
                payload_tags TEXT,
                evidence TEXT,
                waf_detected TEXT,
                bypass_used TEXT,
                remediation TEXT,
                cwe_id TEXT,
                cvss_score REAL,
                xss_type TEXT,
                reflection_type TEXT,
                sink TEXT,
                source TEXT,
                payload_class TEXT,
                trigger TEXT,
                impact_scope TEXT,
                confidence_level TEXT,
                authorization_ref TEXT,
                test_mode TEXT,
                found_at TIMESTAMP NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """
        )

        # Migrate: ensure columns exist for older DBs
        try:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL")
        except sqlite3.OperationalError:
            pass
        for col_name, col_type in [
            ("payload_id", "TEXT"),
            ("payload_name", "TEXT"),
            ("payload_description", "TEXT"),
            ("payload_contexts", "TEXT"),
            ("payload_tags", "TEXT"),
            ("xss_type", "TEXT"),
            ("reflection_type", "TEXT"),
            ("sink", "TEXT"),
            ("source", "TEXT"),
            ("payload_class", "TEXT"),
            ("trigger", "TEXT"),
            ("impact_scope", "TEXT"),
            ("confidence_level", "TEXT"),
            ("authorization_ref", "TEXT"),
            ("test_mode", "TEXT"),
        ]:
            try:
                cursor.execute(
                    f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Settings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Target profiles table (reconnaissance data)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS target_profiles (
                scan_id TEXT PRIMARY KEY,
                profile_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """
        )

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)"
        )

        conn.commit()
        conn.close()

    def _recover_stale_scans(self):
        """Mark stale 'running' scans as failed on server restart"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE scans 
            SET status = 'failed', 
                error_message = 'Server restarted during scan',
                completed_at = datetime('now')
            WHERE status = 'running'
        """
        )

        recovered = cursor.rowcount
        if recovered > 0:
            print(f"[RECOVERY] Marked {recovered} stale scan(s) as failed")

        conn.commit()
        conn.close()

    # ============ Scan Operations ============

    def create_scan(
        self,
        scan_id: str,
        url: str,
        mode: ScanMode,
        performance_mode: str = "standard",
        settings: Optional[Dict[str, Any]] = None,
        proxy_used: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create new scan record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans (id, url, mode, performance_mode, status, started_at, settings, proxy_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )

        conn.commit()
        conn.close()
        return scan_id

    def update_scan_status(
        self, scan_id: str, status: ScanStatus, error_message: Optional[str] = None
    ):
        """Update scan status"""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE scans SET waf_info = ? WHERE id = ?
        """,
            (waf_info.model_dump_json(), scan_id),
        )

        conn.commit()
        conn.close()

    def set_target_profile(self, scan_id: str, profile: Dict[str, Any]):
        """Store target reconnaissance profile"""
        conn = sqlite3.connect(self.db_path)
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

    def get_target_profile(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get target reconnaissance profile"""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
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

        # Get vulnerabilities (include new metadata columns)
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

        vulnerabilities = []
        for v in vuln_rows:
            payload_str = v[6] or ""

            # Restore metadata from DB or context_type for DOM XSS
            ctx = v[3] or "unknown"
            param = v[2] or "unknown"

            # Get metadata from DB if available (v[18+] after schema expansion)
            db_xss_type = v[18] if len(v) > 18 else None
            db_reflection_type = v[19] if len(v) > 19 else None
            db_sink = v[20] if len(v) > 20 else None
            db_source = v[21] if len(v) > 21 else None

            # Determine if DOM-based from DB metadata or context
            is_dom_xss = (
                db_reflection_type == "dom_based"
                or db_xss_type == "DOM-Based XSS"
                or "->" in ctx
                or "DOM" in ctx
                or "dom" in ctx.lower()
            )

            # Improve parameter field for DOM XSS if needed
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

            # Index mapping (current): v[0-6]=base, v[7-11]=KB fields, v[12-17]=rest, v[18-27]=metadata, v[28]=found_at
            found_at_idx = 28  # found_at is last column

            # KB fields from DB (fallback to kb_cache for older rows)
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

            # Optional enrichment via remote KB (only if data missing)
            kb_info: Dict[str, Any] = {}
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

            # Handle cvss_score: DB first, fallback to KB
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

            # Restore metadata for PDF generation (from DB or derive from context)
            vuln_info._xss_type = db_xss_type or (
                "DOM-Based XSS" if is_dom_xss else "Reflected XSS"
            )
            vuln_info._reflection_type = db_reflection_type or (
                "dom_based" if is_dom_xss else "reflected"
            )
            vuln_info._sink = db_sink or (
                ctx.split("->")[-1].strip() if "->" in ctx else ""
            )
            vuln_info._source = db_source or (
                ctx.split("->")[0].strip() if "->" in ctx else ""
            )

            # Restore other metadata if available (payload_class..test_mode = v[22..27])
            if len(v) > 22:
                vuln_info.payload_class = v[22] if len(v) > 22 else None
                vuln_info.trigger = v[23] if len(v) > 23 else None
                vuln_info.impact_scope = v[24] if len(v) > 24 else None
                vuln_info.confidence_level = v[25] if len(v) > 25 else None
                vuln_info.authorization_ref = v[26] if len(v) > 26 else None
                vuln_info.test_mode = v[27] if len(v) > 27 else None

            vulnerabilities.append(vuln_info)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            if v.severity.value in severity_counts:
                severity_counts[v.severity.value] += 1

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
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            duration_seconds=row[9] or 0,
            notes=row[11],
            error_message=row[12],
            performance_mode=PerformanceMode(row[13]) if row[13] else None,
        )

    def get_recent_scans(self, limit: int = 20) -> List[ScanSummary]:
        """Get recent scans summary"""
        from .models import ProxyUsed

        conn = sqlite3.connect(self.db_path)
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
            GROUP BY s.id
            ORDER BY s.started_at DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

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

    def get_proxy_used(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get proxy_used data for a scan"""
        conn = sqlite3.connect(self.db_path)
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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return deleted

    # ============ Vulnerability Operations ============

    def add_vulnerability(self, scan_id: str, vuln: VulnerabilityInfo):
        """Add vulnerability to scan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Extract metadata from object attributes (if stored)
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

    # ============ Dashboard ============

    def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        # Scans today
        today = datetime.utcnow().date().isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM scans WHERE DATE(started_at) = ?", (today,)
        )
        scans_today = cursor.fetchone()[0]

        # Scans this week
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        cursor.execute("SELECT COUNT(*) FROM scans WHERE started_at >= ?", (week_ago,))
        scans_week = cursor.fetchone()[0]

        # Total vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]

        # Critical vulnerabilities
        cursor.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'"
        )
        critical_vulns = cursor.fetchone()[0]

        # High vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'")
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

    # ============ Settings ============

    def get_settings(self) -> SettingsModel:
        """Get application settings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT key, value FROM settings")
        rows = cursor.fetchall()
        conn.close()

        settings_dict = {r[0]: json.loads(r[1]) for r in rows}

        return SettingsModel(**settings_dict) if settings_dict else SettingsModel()

    def save_settings(self, settings: SettingsModel):
        """Save application settings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for key, value in settings.model_dump().items():
            cursor.execute(
                """
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            """,
                (key, json.dumps(value), datetime.utcnow().isoformat()),
            )

        conn.commit()
        conn.close()
