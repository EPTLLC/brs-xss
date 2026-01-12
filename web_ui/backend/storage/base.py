#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Base storage module
Telegram: https://t.me/EasyProTech

Base storage class with database initialization and migrations.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Any


class BaseStorage:
    """Base storage class with database connection and schema management"""

    _kb_payload_cache: dict[str, dict[str, Any]] = {}

    def __init__(self, db_path: str = "brsxss_ui.db"):
        self.db_path = db_path
        self._init_db()
        self._recover_stale_scans()
        self._cleanup_orphaned_data()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize database schema"""
        conn = self._get_connection()
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

        # Migrations for scans table
        self._migrate_column(cursor, "scans", "performance_mode", "TEXT DEFAULT 'standard'")
        self._migrate_column(cursor, "scans", "proxy_used", "TEXT")
        self._migrate_column(cursor, "scans", "user_id", "TEXT")

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

        # Vulnerability columns migrations
        vuln_columns = [
            ("cvss_score", "REAL"),
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
        ]
        for col_name, col_type in vuln_columns:
            self._migrate_column(cursor, "vulnerabilities", col_name, col_type)

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

        # Target profiles table
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

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """
        )

        # Auth config table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                auth_enabled INTEGER DEFAULT 0,
                first_run_completed INTEGER DEFAULT 0,
                legal_accepted INTEGER DEFAULT 0
            )
        """
        )

        cursor.execute(
            """
            INSERT OR IGNORE INTO auth_config (id, auth_enabled, first_run_completed, legal_accepted)
            VALUES (1, 0, 0, 0)
        """
        )

        # User settings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id TEXT PRIMARY KEY,
                telegram_enabled INTEGER DEFAULT 0,
                telegram_bot_token TEXT,
                telegram_chat_id TEXT,
                proxy_enabled INTEGER DEFAULT 0,
                proxy_host TEXT,
                proxy_port INTEGER,
                proxy_protocol TEXT DEFAULT 'http',
                proxy_username TEXT,
                proxy_password TEXT,
                default_scan_mode TEXT DEFAULT 'quick',
                default_performance_mode TEXT DEFAULT 'standard',
                max_crawl_depth INTEGER DEFAULT 3,
                request_timeout INTEGER DEFAULT 30,
                blind_xss_enabled INTEGER DEFAULT 0,
                blind_xss_url TEXT,
                saved_proxies TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )

        # User payloads table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_payloads (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                payload TEXT NOT NULL,
                name TEXT,
                description TEXT,
                tags TEXT,
                context TEXT,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )

        # Domain profiles table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_profiles (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                user_id TEXT,
                total_scans INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                waf_detected TEXT,
                waf_bypass_methods TEXT,
                successful_payloads TEXT,
                failed_payloads TEXT,
                successful_contexts TEXT,
                technologies TEXT,
                last_scan_id TEXT,
                last_scan_at TIMESTAMP,
                first_scan_at TIMESTAMP,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (last_scan_id) REFERENCES scans(id)
            )
        """
        )

        # Workflows table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT,
                is_preset INTEGER DEFAULT 0,
                steps TEXT NOT NULL,
                settings TEXT,
                tags TEXT,
                use_count INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )

        # Scan strategy paths table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_strategy_paths (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                strategy_tree_id TEXT,
                initial_context TEXT,
                waf_detected INTEGER DEFAULT 0,
                waf_name TEXT,
                actions TEXT NOT NULL,
                visited_nodes TEXT NOT NULL,
                node_statuses TEXT NOT NULL,
                pivots TEXT,
                statistics TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """
        )

        # Strategy trees table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS strategy_trees (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                version TEXT DEFAULT '1.0',
                author TEXT,
                tags TEXT,
                tree_data TEXT NOT NULL,
                total_uses INTEGER DEFAULT 0,
                total_successes INTEGER DEFAULT 0,
                is_default INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )

        # Strategy A/B tests table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS strategy_ab_tests (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                strategy_a_id TEXT NOT NULL,
                strategy_b_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                target_scans INTEGER DEFAULT 10,
                completed_scans_a INTEGER DEFAULT 0,
                completed_scans_b INTEGER DEFAULT 0,
                results_a TEXT,
                results_b TEXT,
                winner TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (strategy_a_id) REFERENCES strategy_trees(id),
                FOREIGN KEY (strategy_b_id) REFERENCES strategy_trees(id)
            )
        """
        )

        # Create indexes
        self._create_indexes(cursor)

        conn.commit()
        conn.close()

    def _migrate_column(self, cursor, table: str, column: str, col_type: str):
        """Add column if not exists"""
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
        except sqlite3.OperationalError:
            pass  # Column already exists

    def _create_indexes(self, cursor):
        """Create database indexes"""
        indexes = [
            ("idx_scans_status", "scans(status)"),
            ("idx_scans_started", "scans(started_at)"),
            ("idx_vulns_scan", "vulnerabilities(scan_id)"),
            ("idx_vulns_severity", "vulnerabilities(severity)"),
            ("idx_users_username", "users(username)"),
            ("idx_user_payloads_user", "user_payloads(user_id)"),
            ("idx_domain_profiles_domain", "domain_profiles(domain)"),
            ("idx_domain_profiles_user", "domain_profiles(user_id)"),
            ("idx_workflows_user", "workflows(user_id)"),
            ("idx_workflows_category", "workflows(category)"),
            ("idx_strategy_paths_scan", "scan_strategy_paths(scan_id)"),
            ("idx_strategy_trees_user", "strategy_trees(user_id)"),
            ("idx_strategy_ab_tests_user", "strategy_ab_tests(user_id)"),
        ]
        for idx_name, idx_def in indexes:
            cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")

    def _recover_stale_scans(self):
        """Mark stale 'running' scans as failed on server restart"""
        conn = self._get_connection()
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

    def _cleanup_orphaned_data(self):
        """Remove orphaned vulnerabilities and target profiles on startup"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM vulnerabilities
            WHERE scan_id NOT IN (SELECT id FROM scans)
        """
        )
        orphaned_vulns = cursor.rowcount

        cursor.execute(
            """
            DELETE FROM target_profiles
            WHERE scan_id NOT IN (SELECT id FROM scans)
        """
        )
        orphaned_profiles = cursor.rowcount

        conn.commit()
        conn.close()

        if orphaned_vulns > 0 or orphaned_profiles > 0:
            print(
                f"[CLEANUP] Removed {orphaned_vulns} orphaned vulnerability(ies), "
                f"{orphaned_profiles} orphaned profile(s)"
            )

    def _normalize_kb_payload_info(self, raw: Any) -> dict[str, Any]:
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

    def _get_kb_payload_info(self, payload: str) -> dict[str, Any]:
        """Get payload metadata from KB (remote) with process cache."""
        payload = payload or ""
        if not payload:
            return {}
        cached = BaseStorage._kb_payload_cache.get(payload)
        if cached is not None:
            return cached

        info: dict[str, Any] = {}
        try:
            from brsxss.detect.payloads.kb_adapter import get_kb_adapter

            kb = get_kb_adapter()
            if getattr(kb, "is_available", False):
                raw = kb.analyze_payload(payload)
                info = self._normalize_kb_payload_info(raw)
        except Exception:
            info = {}

        BaseStorage._kb_payload_cache[payload] = info
        return info
