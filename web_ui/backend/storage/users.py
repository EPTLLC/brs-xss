#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Users storage module
Telegram: https://t.me/EasyProTech

User management, authentication, and settings.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Any

from ..models import SettingsModel
from brsxss.auth.models import User, AuthConfig


class UsersMixin:
    """Mixin for user operations"""

    db_path: str

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ============ Settings ============

    def get_settings(self, user_id: Optional[str] = None) -> SettingsModel:
        """Get application settings (global or per-user)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT telegram_enabled, telegram_bot_token, telegram_chat_id,
                       proxy_enabled, proxy_host, proxy_port, proxy_protocol,
                       proxy_username, proxy_password, default_scan_mode,
                       default_performance_mode, max_crawl_depth, request_timeout,
                       blind_xss_enabled, blind_xss_url, saved_proxies
                FROM user_settings WHERE user_id = ?
            """,
                (user_id,),
            )
            row = cursor.fetchone()
            conn.close()

            if row:
                saved_proxies = []
                if row[15]:
                    try:
                        saved_proxies = json.loads(row[15])
                    except json.JSONDecodeError:
                        pass

                return SettingsModel(
                    telegram_enabled=bool(row[0]),
                    telegram_bot_token=row[1] or "",
                    telegram_chat_id=row[2] or "",
                    proxy_enabled=bool(row[3]),
                    proxy_host=row[4] or "",
                    proxy_port=row[5] or 0,
                    proxy_protocol=row[6] or "http",
                    proxy_username=row[7] or "",
                    proxy_password=row[8] or "",
                    default_scan_mode=row[9] or "quick",
                    default_performance_mode=row[10] or "standard",
                    max_crawl_depth=row[11] or 3,
                    request_timeout=row[12] or 30,
                    blind_xss_enabled=bool(row[13]),
                    blind_xss_url=row[14] or "",
                    saved_proxies=saved_proxies,
                )
            return SettingsModel()

        cursor.execute("SELECT key, value FROM settings")
        rows = cursor.fetchall()
        conn.close()

        settings_dict = {r[0]: json.loads(r[1]) for r in rows}
        return SettingsModel(**settings_dict) if settings_dict else SettingsModel()

    def save_settings(self, settings: SettingsModel, user_id: Optional[str] = None):
        """Save application settings (global or per-user)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                INSERT OR REPLACE INTO user_settings (
                    user_id, telegram_enabled, telegram_bot_token, telegram_chat_id,
                    proxy_enabled, proxy_host, proxy_port, proxy_protocol,
                    proxy_username, proxy_password, default_scan_mode,
                    default_performance_mode, max_crawl_depth, request_timeout,
                    blind_xss_enabled, blind_xss_url, saved_proxies, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    user_id,
                    int(settings.telegram_enabled),
                    settings.telegram_bot_token,
                    settings.telegram_chat_id,
                    int(settings.proxy_enabled),
                    settings.proxy_host,
                    settings.proxy_port,
                    settings.proxy_protocol,
                    settings.proxy_username,
                    settings.proxy_password,
                    settings.default_scan_mode,
                    settings.default_performance_mode,
                    settings.max_crawl_depth,
                    settings.request_timeout,
                    int(settings.blind_xss_enabled),
                    settings.blind_xss_url,
                    json.dumps(settings.saved_proxies) if settings.saved_proxies else None,
                    datetime.utcnow().isoformat(),
                ),
            )
        else:
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

    # ============ User Management ============

    def get_auth_config(self) -> AuthConfig:
        """Get authentication configuration"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT auth_enabled, first_run_completed, legal_accepted FROM auth_config WHERE id = 1"
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return AuthConfig(
                auth_enabled=bool(row[0]),
                first_run_completed=bool(row[1]),
                legal_accepted=bool(row[2]),
            )
        return AuthConfig()

    def save_auth_config(self, config: AuthConfig):
        """Save authentication configuration"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO auth_config (id, auth_enabled, first_run_completed, legal_accepted)
            VALUES (1, ?, ?, ?)
        """,
            (
                int(config.auth_enabled),
                int(config.first_run_completed),
                int(config.legal_accepted),
            ),
        )

        conn.commit()
        conn.close()

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, is_admin, is_active, created_at, last_login
            FROM users WHERE id = ?
        """,
            (user_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return User(
                id=row[0],
                username=row[1],
                email=row[2],
                is_admin=bool(row[3]),
                is_active=bool(row[4]),
                created_at=datetime.fromisoformat(row[5]) if row[5] else datetime.utcnow(),
                last_login=datetime.fromisoformat(row[6]) if row[6] else None,
            )
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, is_admin, is_active, created_at, last_login
            FROM users WHERE username = ?
        """,
            (username,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return User(
                id=row[0],
                username=row[1],
                email=row[2],
                is_admin=bool(row[3]),
                is_active=bool(row[4]),
                created_at=datetime.fromisoformat(row[5]) if row[5] else datetime.utcnow(),
                last_login=datetime.fromisoformat(row[6]) if row[6] else None,
            )
        return None

    def get_user_password_hash(self, user_id: str) -> Optional[str]:
        """Get user password hash"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        return row[0] if row else None

    def get_all_users(self) -> list[User]:
        """Get all users"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, is_admin, is_active, created_at, last_login
            FROM users ORDER BY created_at DESC
        """
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            User(
                id=row[0],
                username=row[1],
                email=row[2],
                is_admin=bool(row[3]),
                is_active=bool(row[4]),
                created_at=datetime.fromisoformat(row[5]) if row[5] else datetime.utcnow(),
                last_login=datetime.fromisoformat(row[6]) if row[6] else None,
            )
            for row in rows
        ]

    def create_user(self, user: User, password_hash: str):
        """Create new user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (id, username, password_hash, email, is_admin, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user.id,
                user.username,
                password_hash,
                user.email,
                int(user.is_admin),
                int(user.is_active),
                user.created_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def update_user(self, user: User):
        """Update user info (not password)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users SET email = ?, is_admin = ?, is_active = ?
            WHERE id = ?
        """,
            (user.email, int(user.is_admin), int(user.is_active), user.id),
        )

        conn.commit()
        conn.close()

    def update_user_password(self, user_id: str, password_hash: str):
        """Update user password"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id),
        )

        conn.commit()
        conn.close()

    def update_user_last_login(self, user_id: str):
        """Update user last login timestamp"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), user_id),
        )

        conn.commit()
        conn.close()

    def delete_user(self, user_id: str):
        """Delete user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        cursor.execute("DELETE FROM user_settings WHERE user_id = ?", (user_id,))

        conn.commit()
        conn.close()

    # ============ User Settings ============

    def get_user_settings(self, user_id: str) -> dict[str, Any]:
        """Get user-specific settings"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT telegram_enabled, telegram_bot_token, telegram_chat_id,
                   proxy_enabled, proxy_host, proxy_port, proxy_protocol,
                   proxy_username, proxy_password,
                   default_scan_mode, default_performance_mode,
                   max_crawl_depth, request_timeout,
                   blind_xss_enabled, blind_xss_url, saved_proxies
            FROM user_settings WHERE user_id = ?
        """,
            (user_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            saved_proxies = []
            if row[15]:
                try:
                    saved_proxies = json.loads(row[15])
                except json.JSONDecodeError:
                    pass

            return {
                "telegram_enabled": bool(row[0]),
                "telegram_bot_token": row[1],
                "telegram_chat_id": row[2],
                "proxy_enabled": bool(row[3]),
                "proxy_host": row[4],
                "proxy_port": row[5],
                "proxy_protocol": row[6] or "http",
                "proxy_username": row[7],
                "proxy_password": row[8],
                "default_scan_mode": row[9] or "quick",
                "default_performance_mode": row[10] or "standard",
                "max_crawl_depth": row[11] or 3,
                "request_timeout": row[12] or 30,
                "blind_xss_enabled": bool(row[13]),
                "blind_xss_url": row[14],
                "saved_proxies": saved_proxies,
            }

        return {
            "telegram_enabled": False,
            "telegram_bot_token": None,
            "telegram_chat_id": None,
            "proxy_enabled": False,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_protocol": "http",
            "proxy_username": None,
            "proxy_password": None,
            "default_scan_mode": "quick",
            "default_performance_mode": "standard",
            "max_crawl_depth": 3,
            "request_timeout": 30,
            "blind_xss_enabled": False,
            "blind_xss_url": None,
            "saved_proxies": [],
        }

    def save_user_settings(self, user_id: str, settings: dict[str, Any]):
        """Save user-specific settings"""
        conn = self._get_connection()
        cursor = conn.cursor()

        saved_proxies_json = json.dumps(settings.get("saved_proxies", []))

        cursor.execute(
            """
            INSERT OR REPLACE INTO user_settings (
                user_id, telegram_enabled, telegram_bot_token, telegram_chat_id,
                proxy_enabled, proxy_host, proxy_port, proxy_protocol,
                proxy_username, proxy_password,
                default_scan_mode, default_performance_mode,
                max_crawl_depth, request_timeout,
                blind_xss_enabled, blind_xss_url, saved_proxies, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                int(settings.get("telegram_enabled", False)),
                settings.get("telegram_bot_token"),
                settings.get("telegram_chat_id"),
                int(settings.get("proxy_enabled", False)),
                settings.get("proxy_host"),
                settings.get("proxy_port"),
                settings.get("proxy_protocol", "http"),
                settings.get("proxy_username"),
                settings.get("proxy_password"),
                settings.get("default_scan_mode", "quick"),
                settings.get("default_performance_mode", "standard"),
                settings.get("max_crawl_depth", 3),
                settings.get("request_timeout", 30),
                int(settings.get("blind_xss_enabled", False)),
                settings.get("blind_xss_url"),
                saved_proxies_json,
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
