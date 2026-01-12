#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Domains storage module
Telegram: https://t.me/EasyProTech

Domain profiles, payloads, and workflows.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Any

from ..models import (
    ScanSummary,
    ScanStatus,
    ScanMode,
    VulnerabilityInfo,
    WAFInfo,
    ProxyUsed,
)


class DomainsMixin:
    """Mixin for domain profile operations"""

    db_path: str

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ============ User Payloads ============

    def get_user_payloads(self, user_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Get saved payloads for user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT id, user_id, payload, name, description, tags, context,
                       success_count, fail_count, last_used, created_at
                FROM user_payloads
                WHERE user_id = ? OR user_id IS NULL
                ORDER BY success_count DESC, created_at DESC
            """,
                (user_id,),
            )
        else:
            cursor.execute(
                """
                SELECT id, user_id, payload, name, description, tags, context,
                       success_count, fail_count, last_used, created_at
                FROM user_payloads
                ORDER BY success_count DESC, created_at DESC
            """
            )

        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            tags = []
            if r[5]:
                try:
                    tags = json.loads(r[5])
                except json.JSONDecodeError:
                    tags = [t.strip() for t in r[5].split(",") if t.strip()]

            results.append({
                "id": r[0],
                "user_id": r[1],
                "payload": r[2],
                "name": r[3],
                "description": r[4],
                "tags": tags,
                "context": r[6],
                "success_count": r[7] or 0,
                "fail_count": r[8] or 0,
                "last_used": r[9],
                "created_at": r[10],
            })

        return results

    def create_user_payload(
        self,
        payload: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
        context: Optional[str] = None,
    ) -> str:
        """Create a new saved payload"""
        import uuid

        payload_id = str(uuid.uuid4())[:8]
        conn = self._get_connection()
        cursor = conn.cursor()

        tags_json = json.dumps(tags) if tags else None

        cursor.execute(
            """
            INSERT INTO user_payloads (id, user_id, payload, name, description, tags, context, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                payload_id,
                user_id,
                payload,
                name,
                description,
                tags_json,
                context,
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return payload_id

    def update_user_payload(
        self,
        payload_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[list[str]] = None,
        context: Optional[str] = None,
    ) -> bool:
        """Update a saved payload"""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if context is not None:
            updates.append("context = ?")
            params.append(context)

        if not updates:
            conn.close()
            return False

        params.append(payload_id)
        cursor.execute(
            f"UPDATE user_payloads SET {', '.join(updates)} WHERE id = ?",
            params,
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_user_payload(self, payload_id: str, user_id: Optional[str] = None) -> bool:
        """Delete a saved payload"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "DELETE FROM user_payloads WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
                (payload_id, user_id),
            )
        else:
            cursor.execute("DELETE FROM user_payloads WHERE id = ?", (payload_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def increment_payload_stats(self, payload_id: str, success: bool = True):
        """Increment success or fail count for a payload"""
        conn = self._get_connection()
        cursor = conn.cursor()

        field = "success_count" if success else "fail_count"
        cursor.execute(
            f"""
            UPDATE user_payloads
            SET {field} = {field} + 1, last_used = ?
            WHERE id = ?
        """,
            (datetime.utcnow().isoformat(), payload_id),
        )

        conn.commit()
        conn.close()

    def payload_exists(self, payload: str, user_id: Optional[str] = None) -> bool:
        """Check if payload already exists for user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "SELECT 1 FROM user_payloads WHERE payload = ? AND (user_id = ? OR user_id IS NULL)",
                (payload, user_id),
            )
        else:
            cursor.execute(
                "SELECT 1 FROM user_payloads WHERE payload = ?",
                (payload,),
            )

        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    # ============ Domain Profiles ============

    def get_domain_profile(
        self, domain: str, user_id: Optional[str] = None
    ) -> Optional[dict[str, Any]]:
        """Get domain profile by domain name"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT id, domain, user_id, total_scans, total_vulns,
                       critical_count, high_count, medium_count, low_count,
                       waf_detected, waf_bypass_methods, successful_payloads,
                       failed_payloads, successful_contexts, technologies,
                       last_scan_id, last_scan_at, first_scan_at, notes,
                       created_at, updated_at
                FROM domain_profiles
                WHERE domain = ? AND (user_id = ? OR user_id IS NULL)
            """,
                (domain, user_id),
            )
        else:
            cursor.execute(
                """
                SELECT id, domain, user_id, total_scans, total_vulns,
                       critical_count, high_count, medium_count, low_count,
                       waf_detected, waf_bypass_methods, successful_payloads,
                       failed_payloads, successful_contexts, technologies,
                       last_scan_id, last_scan_at, first_scan_at, notes,
                       created_at, updated_at
                FROM domain_profiles
                WHERE domain = ?
            """,
                (domain,),
            )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        def _parse_json_list(val):
            if not val:
                return []
            try:
                return json.loads(val)
            except json.JSONDecodeError:
                return []

        return {
            "id": row[0],
            "domain": row[1],
            "user_id": row[2],
            "total_scans": row[3] or 0,
            "total_vulns": row[4] or 0,
            "critical_count": row[5] or 0,
            "high_count": row[6] or 0,
            "medium_count": row[7] or 0,
            "low_count": row[8] or 0,
            "waf_detected": row[9],
            "waf_bypass_methods": _parse_json_list(row[10]),
            "successful_payloads": _parse_json_list(row[11]),
            "failed_payloads": _parse_json_list(row[12]),
            "successful_contexts": _parse_json_list(row[13]),
            "technologies": _parse_json_list(row[14]),
            "last_scan_id": row[15],
            "last_scan_at": row[16],
            "first_scan_at": row[17],
            "notes": row[18],
            "created_at": row[19],
            "updated_at": row[20],
        }

    def get_domain_profiles(
        self, user_id: Optional[str] = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Get all domain profiles for user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT id, domain, user_id, total_scans, total_vulns,
                       critical_count, high_count, medium_count, low_count,
                       waf_detected, last_scan_at, first_scan_at
                FROM domain_profiles
                WHERE user_id = ? OR user_id IS NULL
                ORDER BY last_scan_at DESC
                LIMIT ?
            """,
                (user_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT id, domain, user_id, total_scans, total_vulns,
                       critical_count, high_count, medium_count, low_count,
                       waf_detected, last_scan_at, first_scan_at
                FROM domain_profiles
                ORDER BY last_scan_at DESC
                LIMIT ?
            """,
                (limit,),
            )

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": r[0],
                "domain": r[1],
                "user_id": r[2],
                "total_scans": r[3] or 0,
                "total_vulns": r[4] or 0,
                "critical_count": r[5] or 0,
                "high_count": r[6] or 0,
                "medium_count": r[7] or 0,
                "low_count": r[8] or 0,
                "waf_detected": r[9],
                "last_scan_at": r[10],
                "first_scan_at": r[11],
            }
            for r in rows
        ]

    def update_domain_profile_from_scan(
        self,
        domain: str,
        scan_id: str,
        vulnerabilities: list[VulnerabilityInfo],
        waf_info: Optional[WAFInfo] = None,
        technologies: Optional[list[str]] = None,
        user_id: Optional[str] = None,
    ):
        """Update or create domain profile after scan completion"""
        import uuid
        from brsxss.count import count_findings

        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "SELECT id, total_scans, total_vulns, successful_payloads, failed_payloads, "
                "successful_contexts, waf_bypass_methods, first_scan_at "
                "FROM domain_profiles WHERE domain = ? AND (user_id = ? OR user_id IS NULL)",
                (domain, user_id),
            )
        else:
            cursor.execute(
                "SELECT id, total_scans, total_vulns, successful_payloads, failed_payloads, "
                "successful_contexts, waf_bypass_methods, first_scan_at "
                "FROM domain_profiles WHERE domain = ?",
                (domain,),
            )

        existing = cursor.fetchone()
        now = datetime.utcnow().isoformat()

        counts = count_findings(vulnerabilities)

        new_successful_payloads = []
        new_successful_contexts = []
        for v in vulnerabilities:
            if v.payload and v.confidence >= 0.6:
                new_successful_payloads.append(v.payload)
            if v.context_type and v.confidence >= 0.6:
                new_successful_contexts.append(v.context_type)

        waf_name = waf_info.name if waf_info and waf_info.detected else None
        new_bypass_methods = []
        for v in vulnerabilities:
            if v.bypass_used:
                new_bypass_methods.append(v.bypass_used)

        if existing:
            profile_id = existing[0]
            total_scans = (existing[1] or 0) + 1
            total_vulns = (existing[2] or 0) + len(vulnerabilities)

            old_payloads = json.loads(existing[3]) if existing[3] else []
            merged_payloads = list(set(old_payloads + new_successful_payloads))[:100]

            old_contexts = json.loads(existing[5]) if existing[5] else []
            merged_contexts = list(set(old_contexts + new_successful_contexts))[:50]

            old_bypasses = json.loads(existing[6]) if existing[6] else []
            merged_bypasses = list(set(old_bypasses + new_bypass_methods))[:50]

            cursor.execute(
                """
                UPDATE domain_profiles SET
                    total_scans = ?,
                    total_vulns = ?,
                    critical_count = critical_count + ?,
                    high_count = high_count + ?,
                    medium_count = medium_count + ?,
                    low_count = low_count + ?,
                    waf_detected = COALESCE(?, waf_detected),
                    waf_bypass_methods = ?,
                    successful_payloads = ?,
                    successful_contexts = ?,
                    technologies = COALESCE(?, technologies),
                    last_scan_id = ?,
                    last_scan_at = ?,
                    updated_at = ?
                WHERE id = ?
            """,
                (
                    total_scans,
                    total_vulns,
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low,
                    waf_name,
                    json.dumps(merged_bypasses),
                    json.dumps(merged_payloads),
                    json.dumps(merged_contexts),
                    json.dumps(technologies) if technologies else None,
                    scan_id,
                    now,
                    now,
                    profile_id,
                ),
            )
        else:
            profile_id = str(uuid.uuid4())[:8]

            cursor.execute(
                """
                INSERT INTO domain_profiles (
                    id, domain, user_id, total_scans, total_vulns,
                    critical_count, high_count, medium_count, low_count,
                    waf_detected, waf_bypass_methods, successful_payloads,
                    failed_payloads, successful_contexts, technologies,
                    last_scan_id, last_scan_at, first_scan_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    profile_id,
                    domain,
                    user_id,
                    1,
                    len(vulnerabilities),
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low,
                    waf_name,
                    json.dumps(new_bypass_methods),
                    json.dumps(new_successful_payloads),
                    json.dumps([]),
                    json.dumps(new_successful_contexts),
                    json.dumps(technologies) if technologies else None,
                    scan_id,
                    now,
                    now,
                    now,
                    now,
                ),
            )

        conn.commit()
        conn.close()

    def get_domain_scans(
        self, domain: str, user_id: Optional[str] = None, limit: int = 10
    ) -> list[ScanSummary]:
        """Get recent scans for a specific domain"""
        conn = self._get_connection()
        cursor = conn.cursor()

        domain_pattern = f"%{domain}%"

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
                WHERE s.url LIKE ? AND (s.user_id = ? OR s.user_id IS NULL)
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
            """,
                (domain_pattern, user_id, limit),
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
                WHERE s.url LIKE ?
                GROUP BY s.id
                ORDER BY s.started_at DESC
                LIMIT ?
            """,
                (domain_pattern, limit),
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

    def delete_domain_profile(self, profile_id: str, user_id: Optional[str] = None) -> bool:
        """Delete a domain profile"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "DELETE FROM domain_profiles WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
                (profile_id, user_id),
            )
        else:
            cursor.execute("DELETE FROM domain_profiles WHERE id = ?", (profile_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    # ============ Workflows ============

    def get_workflows(
        self, user_id: Optional[str] = None, category: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Get workflows (presets + user custom)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT id, user_id, name, description, category, is_preset,
                   steps, settings, tags, use_count, last_used, created_at
            FROM workflows
            WHERE (is_preset = 1 OR user_id = ? OR user_id IS NULL)
        """
        params: list[Any] = [user_id]

        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY is_preset DESC, use_count DESC, name ASC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            steps = []
            settings = {}
            tags = []
            try:
                steps = json.loads(r[6]) if r[6] else []
            except json.JSONDecodeError:
                pass
            try:
                settings = json.loads(r[7]) if r[7] else {}
            except json.JSONDecodeError:
                pass
            try:
                tags = json.loads(r[8]) if r[8] else []
            except json.JSONDecodeError:
                pass

            results.append({
                "id": r[0],
                "user_id": r[1],
                "name": r[2],
                "description": r[3],
                "category": r[4],
                "is_preset": bool(r[5]),
                "steps": steps,
                "settings": settings,
                "tags": tags,
                "use_count": r[9] or 0,
                "last_used": r[10],
                "created_at": r[11],
            })

        return results

    def get_workflow(self, workflow_id: str) -> Optional[dict[str, Any]]:
        """Get single workflow by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, user_id, name, description, category, is_preset,
                   steps, settings, tags, use_count, last_used, created_at
            FROM workflows WHERE id = ?
        """,
            (workflow_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        steps = []
        settings = {}
        tags = []
        try:
            steps = json.loads(row[6]) if row[6] else []
        except json.JSONDecodeError:
            pass
        try:
            settings = json.loads(row[7]) if row[7] else {}
        except json.JSONDecodeError:
            pass
        try:
            tags = json.loads(row[8]) if row[8] else []
        except json.JSONDecodeError:
            pass

        return {
            "id": row[0],
            "user_id": row[1],
            "name": row[2],
            "description": row[3],
            "category": row[4],
            "is_preset": bool(row[5]),
            "steps": steps,
            "settings": settings,
            "tags": tags,
            "use_count": row[9] or 0,
            "last_used": row[10],
            "created_at": row[11],
        }

    def create_workflow(
        self,
        name: str,
        steps: list[dict[str, Any]],
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
        settings: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        is_preset: bool = False,
    ) -> str:
        """Create a new workflow"""
        import uuid

        workflow_id = str(uuid.uuid4())[:8]
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO workflows (id, user_id, name, description, category, is_preset,
                                   steps, settings, tags, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                workflow_id,
                user_id,
                name,
                description,
                category,
                int(is_preset),
                json.dumps(steps),
                json.dumps(settings) if settings else None,
                json.dumps(tags) if tags else None,
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return workflow_id

    def update_workflow(
        self,
        workflow_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        steps: Optional[list[dict[str, Any]]] = None,
        settings: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        category: Optional[str] = None,
    ) -> bool:
        """Update a workflow"""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = ["updated_at = ?"]
        params: list[Any] = [datetime.utcnow().isoformat()]

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if steps is not None:
            updates.append("steps = ?")
            params.append(json.dumps(steps))
        if settings is not None:
            updates.append("settings = ?")
            params.append(json.dumps(settings))
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if category is not None:
            updates.append("category = ?")
            params.append(category)

        params.append(workflow_id)
        cursor.execute(
            f"UPDATE workflows SET {', '.join(updates)} WHERE id = ? AND is_preset = 0",
            params,
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_workflow(self, workflow_id: str, user_id: Optional[str] = None) -> bool:
        """Delete a workflow (only user workflows, not presets)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "DELETE FROM workflows WHERE id = ? AND is_preset = 0 AND (user_id = ? OR user_id IS NULL)",
                (workflow_id, user_id),
            )
        else:
            cursor.execute(
                "DELETE FROM workflows WHERE id = ? AND is_preset = 0",
                (workflow_id,),
            )

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def increment_workflow_usage(self, workflow_id: str):
        """Increment workflow usage count"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE workflows
            SET use_count = use_count + 1, last_used = ?
            WHERE id = ?
        """,
            (datetime.utcnow().isoformat(), workflow_id),
        )

        conn.commit()
        conn.close()

    def init_preset_workflows(self):
        """Initialize preset workflows if not exist"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM workflows WHERE is_preset = 1")
        if cursor.fetchone()[0] > 0:
            conn.close()
            return

        presets = [
            {
                "id": "preset-ecommerce",
                "name": "E-commerce XSS Audit",
                "description": "Full audit for e-commerce sites",
                "category": "ecommerce",
                "steps": [
                    {"type": "crawl", "target": "forms", "depth": 2},
                    {"type": "scan", "context": "search", "mode": "standard"},
                    {"type": "scan", "context": "cart", "mode": "deep"},
                    {"type": "report", "format": "pdf"},
                ],
                "settings": {"waf_bypass": True, "dom_analysis": True},
                "tags": ["ecommerce", "cart", "checkout"],
            },
            {
                "id": "preset-blog",
                "name": "Blog/CMS Audit",
                "description": "Audit for blogs and CMS",
                "category": "blog",
                "steps": [
                    {"type": "crawl", "target": "all", "depth": 3},
                    {"type": "scan", "context": "comments", "mode": "deep", "blind": True},
                    {"type": "report", "format": "pdf"},
                ],
                "settings": {"waf_bypass": True},
                "tags": ["blog", "cms", "comments"],
            },
            {
                "id": "preset-quick",
                "name": "Quick Recon",
                "description": "Fast reconnaissance scan",
                "category": "recon",
                "steps": [
                    {"type": "crawl", "target": "forms", "depth": 1},
                    {"type": "scan", "context": "all", "mode": "quick"},
                ],
                "settings": {"waf_bypass": False},
                "tags": ["quick", "recon"],
            },
        ]

        for preset in presets:
            cursor.execute(
                """
                INSERT INTO workflows (id, user_id, name, description, category, is_preset,
                                       steps, settings, tags, created_at)
                VALUES (?, NULL, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
                (
                    preset["id"],
                    preset["name"],
                    preset["description"],
                    preset["category"],
                    json.dumps(preset["steps"]),
                    json.dumps(preset["settings"]),
                    json.dumps(preset["tags"]),
                    datetime.utcnow().isoformat(),
                ),
            )

        conn.commit()
        conn.close()
