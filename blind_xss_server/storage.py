#!/usr/bin/env python3

"""
Project: BRS-XSS Blind XSS Callback Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SQLite storage for Blind XSS callbacks.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from .models import Callback, PayloadInfo, CallbackStats


class CallbackStorage:
    """SQLite-based storage for Blind XSS callbacks"""

    def __init__(self, db_path: str = "blind_xss.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Payloads table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS payloads (
                payload_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                target_url TEXT,
                parameter TEXT,
                context_type TEXT DEFAULT 'unknown',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )
        """
        )

        # Callbacks table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                user_agent TEXT,
                referer TEXT,
                url TEXT,
                cookies TEXT,
                local_storage TEXT,
                session_storage TEXT,
                dom_snapshot TEXT,
                screenshot_path TEXT,
                custom_data TEXT,
                FOREIGN KEY (payload_id) REFERENCES payloads(payload_id)
            )
        """
        )

        # Indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_callbacks_payload ON callbacks(payload_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_callbacks_received ON callbacks(received_at)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_callbacks_ip ON callbacks(source_ip)"
        )

        conn.commit()
        conn.close()

    def register_payload(self, payload_info: PayloadInfo) -> str:
        """Register a new payload for tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO payloads 
            (payload_id, payload, target_url, parameter, context_type, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                payload_info.payload_id,
                payload_info.payload,
                payload_info.target_url,
                payload_info.parameter,
                payload_info.context_type,
                payload_info.created_at.isoformat(),
                payload_info.notes,
            ),
        )

        conn.commit()
        conn.close()

        return payload_info.payload_id

    def get_payload(self, payload_id: str) -> Optional[PayloadInfo]:
        """Get payload info by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT payload_id, payload, target_url, parameter, context_type, created_at, notes
            FROM payloads WHERE payload_id = ?
        """,
            (payload_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return PayloadInfo(
                payload_id=row[0],
                payload=row[1],
                target_url=row[2],
                parameter=row[3],
                context_type=row[4],
                created_at=(
                    datetime.fromisoformat(row[5]) if row[5] else datetime.utcnow()
                ),
                notes=row[6],
            )
        return None

    def store_callback(
        self,
        payload_id: str,
        source_ip: str,
        user_agent: str,
        referer: Optional[str] = None,
        url: Optional[str] = None,
        cookies: Optional[str] = None,
        local_storage: Optional[str] = None,
        session_storage: Optional[str] = None,
        dom_snapshot: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        custom_data: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Store a new callback"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO callbacks 
            (payload_id, source_ip, user_agent, referer, url, cookies, 
             local_storage, session_storage, dom_snapshot, screenshot_path, custom_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                payload_id,
                source_ip,
                user_agent,
                referer,
                url,
                cookies,
                local_storage,
                session_storage,
                dom_snapshot,
                screenshot_path,
                json.dumps(custom_data) if custom_data else None,
            ),
        )

        callback_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return callback_id

    def get_callback(self, callback_id: int) -> Optional[Callback]:
        """Get callback by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, payload_id, received_at, source_ip, user_agent, referer,
                   url, cookies, local_storage, session_storage, dom_snapshot,
                   screenshot_path, custom_data
            FROM callbacks WHERE id = ?
        """,
            (callback_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return self._row_to_callback(row)
        return None

    def get_callbacks_by_payload(self, payload_id: str) -> List[Callback]:
        """Get all callbacks for a specific payload"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, payload_id, received_at, source_ip, user_agent, referer,
                   url, cookies, local_storage, session_storage, dom_snapshot,
                   screenshot_path, custom_data
            FROM callbacks WHERE payload_id = ?
            ORDER BY received_at DESC
        """,
            (payload_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_callback(row) for row in rows]

    def get_recent_callbacks(self, limit: int = 50) -> List[Callback]:
        """Get most recent callbacks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, payload_id, received_at, source_ip, user_agent, referer,
                   url, cookies, local_storage, session_storage, dom_snapshot,
                   screenshot_path, custom_data
            FROM callbacks
            ORDER BY received_at DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_callback(row) for row in rows]

    def get_stats(self) -> CallbackStats:
        """Get callback statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total callbacks
        cursor.execute("SELECT COUNT(*) FROM callbacks")
        total = cursor.fetchone()[0]

        # Unique payloads
        cursor.execute("SELECT COUNT(DISTINCT payload_id) FROM callbacks")
        unique_payloads = cursor.fetchone()[0]

        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM callbacks")
        unique_ips = cursor.fetchone()[0]

        # Callbacks today
        today = datetime.utcnow().date().isoformat()
        cursor.execute(
            """
            SELECT COUNT(*) FROM callbacks 
            WHERE DATE(received_at) = ?
        """,
            (today,),
        )
        today_count = cursor.fetchone()[0]

        # Last callback
        cursor.execute("SELECT MAX(received_at) FROM callbacks")
        last_at = cursor.fetchone()[0]

        conn.close()

        return CallbackStats(
            total_callbacks=total,
            unique_payloads=unique_payloads,
            unique_ips=unique_ips,
            callbacks_today=today_count,
            last_callback_at=datetime.fromisoformat(last_at) if last_at else None,
        )

    def cleanup_old_callbacks(self, retention_days: int = 30) -> int:
        """Remove callbacks older than retention period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()

        cursor.execute(
            """
            DELETE FROM callbacks WHERE received_at < ?
        """,
            (cutoff,),
        )

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        return deleted

    def _row_to_callback(self, row: tuple) -> Callback:
        """Convert database row to Callback model"""
        return Callback(
            id=row[0],
            payload_id=row[1],
            received_at=datetime.fromisoformat(row[2]) if row[2] else datetime.utcnow(),
            source_ip=row[3],
            user_agent=row[4] or "",
            referer=row[5],
            url=row[6],
            cookies=row[7],
            local_storage=row[8],
            session_storage=row[9],
            dom_snapshot=row[10],
            screenshot_path=row[11],
            custom_data=json.loads(row[12]) if row[12] else None,
            payload_info=self.get_payload(row[1]),
        )
