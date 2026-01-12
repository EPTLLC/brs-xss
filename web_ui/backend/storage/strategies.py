#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Strategies storage module
Telegram: https://t.me/EasyProTech

Strategy trees and A/B testing operations.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, Any


class StrategiesMixin:
    """Mixin for strategy operations"""

    db_path: str

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ============ Scan Strategy Paths ============

    def save_scan_strategy_path(
        self,
        scan_id: str,
        strategy_tree_id: str,
        initial_context: str,
        waf_detected: bool,
        waf_name: Optional[str],
        actions: list[dict[str, Any]],
        visited_nodes: list[str],
        node_statuses: dict[str, str],
        pivots: list[dict[str, Any]],
        statistics: dict[str, Any],
    ) -> str:
        """Save strategy execution path for a scan"""
        import uuid

        path_id = str(uuid.uuid4())[:8]
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scan_strategy_paths (
                id, scan_id, strategy_tree_id, initial_context,
                waf_detected, waf_name, actions, visited_nodes,
                node_statuses, pivots, statistics, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                path_id,
                scan_id,
                strategy_tree_id,
                initial_context,
                int(waf_detected),
                waf_name,
                json.dumps(actions),
                json.dumps(visited_nodes),
                json.dumps(node_statuses),
                json.dumps(pivots),
                json.dumps(statistics),
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return path_id

    def get_scan_strategy_path(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Get strategy execution path for a scan"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, scan_id, strategy_tree_id, initial_context,
                   waf_detected, waf_name, actions, visited_nodes,
                   node_statuses, pivots, statistics, created_at
            FROM scan_strategy_paths
            WHERE scan_id = ?
        """,
            (scan_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        def _parse_json(val):
            if not val:
                return None
            try:
                return json.loads(val)
            except json.JSONDecodeError:
                return None

        return {
            "id": row[0],
            "scan_id": row[1],
            "strategy_tree_id": row[2],
            "initial_context": row[3],
            "waf_detected": bool(row[4]),
            "waf_name": row[5],
            "actions": _parse_json(row[6]) or [],
            "visited_nodes": _parse_json(row[7]) or [],
            "node_statuses": _parse_json(row[8]) or {},
            "pivots": _parse_json(row[9]) or [],
            "statistics": _parse_json(row[10]) or {},
            "created_at": row[11],
        }

    def update_scan_strategy_path(
        self,
        scan_id: str,
        actions: Optional[list[dict[str, Any]]] = None,
        visited_nodes: Optional[list[str]] = None,
        node_statuses: Optional[dict[str, str]] = None,
        pivots: Optional[list[dict[str, Any]]] = None,
        statistics: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Update strategy path during scan execution"""
        conn = self._get_connection()
        cursor = conn.cursor()

        updates = []
        params: list[Any] = []

        if actions is not None:
            updates.append("actions = ?")
            params.append(json.dumps(actions))
        if visited_nodes is not None:
            updates.append("visited_nodes = ?")
            params.append(json.dumps(visited_nodes))
        if node_statuses is not None:
            updates.append("node_statuses = ?")
            params.append(json.dumps(node_statuses))
        if pivots is not None:
            updates.append("pivots = ?")
            params.append(json.dumps(pivots))
        if statistics is not None:
            updates.append("statistics = ?")
            params.append(json.dumps(statistics))

        if not updates:
            conn.close()
            return False

        params.append(scan_id)
        cursor.execute(
            f"UPDATE scan_strategy_paths SET {', '.join(updates)} WHERE scan_id = ?",
            params,
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_scan_strategy_path(self, scan_id: str) -> bool:
        """Delete strategy path for a scan"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM scan_strategy_paths WHERE scan_id = ?",
            (scan_id,),
        )

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    # ============ Strategy Trees ============

    def get_strategy_trees(
        self, user_id: Optional[str] = None, include_default: bool = True
    ) -> list[dict[str, Any]]:
        """Get all strategy trees for user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            if include_default:
                cursor.execute(
                    """
                    SELECT id, user_id, name, description, version, author, tags,
                           tree_data, total_uses, total_successes, is_default, is_active,
                           created_at, updated_at
                    FROM strategy_trees
                    WHERE user_id = ? OR user_id IS NULL OR is_default = 1
                    ORDER BY is_default DESC, total_uses DESC, name ASC
                """,
                    (user_id,),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, name, description, version, author, tags,
                           tree_data, total_uses, total_successes, is_default, is_active,
                           created_at, updated_at
                    FROM strategy_trees
                    WHERE user_id = ? OR user_id IS NULL
                    ORDER BY total_uses DESC, name ASC
                """,
                    (user_id,),
                )
        else:
            cursor.execute(
                """
                SELECT id, user_id, name, description, version, author, tags,
                       tree_data, total_uses, total_successes, is_default, is_active,
                       created_at, updated_at
                FROM strategy_trees
                ORDER BY is_default DESC, total_uses DESC, name ASC
            """
            )

        rows = cursor.fetchall()
        conn.close()

        return self._parse_strategy_trees(rows)

    def _parse_strategy_trees(self, rows: list) -> list[dict[str, Any]]:
        """Parse strategy tree rows"""
        results = []
        for r in rows:
            tags = []
            tree_data = {}
            try:
                tags = json.loads(r[6]) if r[6] else []
            except json.JSONDecodeError:
                pass
            try:
                tree_data = json.loads(r[7]) if r[7] else {}
            except json.JSONDecodeError:
                pass

            success_rate = 0.0
            if r[8] and r[8] > 0:
                success_rate = (r[9] or 0) / r[8]

            results.append({
                "id": r[0],
                "user_id": r[1],
                "name": r[2],
                "description": r[3],
                "version": r[4] or "1.0",
                "author": r[5],
                "tags": tags,
                "tree_data": tree_data,
                "total_uses": r[8] or 0,
                "total_successes": r[9] or 0,
                "success_rate": success_rate,
                "is_default": bool(r[10]),
                "is_active": bool(r[11]),
                "created_at": r[12],
                "updated_at": r[13],
            })

        return results

    def get_strategy_tree(self, tree_id: str) -> Optional[dict[str, Any]]:
        """Get single strategy tree by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, user_id, name, description, version, author, tags,
                   tree_data, total_uses, total_successes, is_default, is_active,
                   created_at, updated_at
            FROM strategy_trees WHERE id = ?
        """,
            (tree_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        trees = self._parse_strategy_trees([row])
        return trees[0] if trees else None

    def get_active_strategy_tree(self, user_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Get currently active strategy tree for user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT id FROM strategy_trees
                WHERE is_active = 1 AND (user_id = ? OR user_id IS NULL)
                ORDER BY user_id DESC LIMIT 1
            """,
                (user_id,),
            )
        else:
            cursor.execute(
                "SELECT id FROM strategy_trees WHERE is_active = 1 LIMIT 1"
            )

        row = cursor.fetchone()
        conn.close()

        if row:
            return self.get_strategy_tree(row[0])
        return None

    def create_strategy_tree(
        self,
        name: str,
        tree_data: dict[str, Any],
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        version: str = "1.0",
        author: Optional[str] = None,
        tags: Optional[list[str]] = None,
        is_default: bool = False,
    ) -> str:
        """Create a new strategy tree"""
        import uuid

        tree_id = str(uuid.uuid4())[:8]
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO strategy_trees (
                id, user_id, name, description, version, author, tags,
                tree_data, is_default, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                tree_id,
                user_id,
                name,
                description,
                version,
                author,
                json.dumps(tags) if tags else None,
                json.dumps(tree_data),
                int(is_default),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return tree_id

    def update_strategy_tree(
        self,
        tree_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        tree_data: Optional[dict[str, Any]] = None,
        version: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> bool:
        """Update a strategy tree"""
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
        if tree_data is not None:
            updates.append("tree_data = ?")
            params.append(json.dumps(tree_data))
        if version is not None:
            updates.append("version = ?")
            params.append(version)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))

        params.append(tree_id)
        cursor.execute(
            f"UPDATE strategy_trees SET {', '.join(updates)} WHERE id = ? AND is_default = 0",
            params,
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_strategy_tree(self, tree_id: str, user_id: Optional[str] = None) -> bool:
        """Delete a strategy tree (only user trees, not default)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "DELETE FROM strategy_trees WHERE id = ? AND is_default = 0 AND (user_id = ? OR user_id IS NULL)",
                (tree_id, user_id),
            )
        else:
            cursor.execute(
                "DELETE FROM strategy_trees WHERE id = ? AND is_default = 0",
                (tree_id,),
            )

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def set_active_strategy_tree(self, tree_id: str, user_id: Optional[str] = None) -> bool:
        """Set a strategy tree as active (deactivate others)"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "UPDATE strategy_trees SET is_active = 0 WHERE user_id = ? OR user_id IS NULL",
                (user_id,),
            )
        else:
            cursor.execute("UPDATE strategy_trees SET is_active = 0")

        cursor.execute(
            "UPDATE strategy_trees SET is_active = 1 WHERE id = ?",
            (tree_id,),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def increment_strategy_tree_stats(self, tree_id: str, success: bool = False):
        """Increment strategy tree usage statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if success:
            cursor.execute(
                """
                UPDATE strategy_trees
                SET total_uses = total_uses + 1, total_successes = total_successes + 1,
                    updated_at = ?
                WHERE id = ?
            """,
                (datetime.utcnow().isoformat(), tree_id),
            )
        else:
            cursor.execute(
                """
                UPDATE strategy_trees
                SET total_uses = total_uses + 1, updated_at = ?
                WHERE id = ?
            """,
                (datetime.utcnow().isoformat(), tree_id),
            )

        conn.commit()
        conn.close()

    def clone_strategy_tree(
        self, source_tree_id: str, new_name: str, user_id: Optional[str] = None
    ) -> Optional[str]:
        """Clone an existing strategy tree"""
        source = self.get_strategy_tree(source_tree_id)
        if not source:
            return None

        return self.create_strategy_tree(
            name=new_name,
            tree_data=source["tree_data"],
            user_id=user_id,
            description=f"Cloned from: {source['name']}",
            version="1.0",
            author=source.get("author"),
            tags=source.get("tags", []),
        )

    # ============ Strategy A/B Tests ============

    def get_ab_tests(
        self, user_id: Optional[str] = None, status: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Get A/B tests"""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT t.id, t.user_id, t.name, t.description,
                   t.strategy_a_id, t.strategy_b_id, t.status,
                   t.target_scans, t.completed_scans_a, t.completed_scans_b,
                   t.results_a, t.results_b, t.winner,
                   t.created_at, t.completed_at,
                   sa.name as strategy_a_name, sb.name as strategy_b_name
            FROM strategy_ab_tests t
            LEFT JOIN strategy_trees sa ON t.strategy_a_id = sa.id
            LEFT JOIN strategy_trees sb ON t.strategy_b_id = sb.id
            WHERE 1=1
        """
        params: list[Any] = []

        if user_id:
            query += " AND (t.user_id = ? OR t.user_id IS NULL)"
            params.append(user_id)
        if status:
            query += " AND t.status = ?"
            params.append(status)

        query += " ORDER BY t.created_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return self._parse_ab_tests(rows)

    def _parse_ab_tests(self, rows: list) -> list[dict[str, Any]]:
        """Parse A/B test rows"""
        results = []
        for r in rows:
            results_a = {}
            results_b = {}
            try:
                results_a = json.loads(r[10]) if r[10] else {}
            except json.JSONDecodeError:
                pass
            try:
                results_b = json.loads(r[11]) if r[11] else {}
            except json.JSONDecodeError:
                pass

            results.append({
                "id": r[0],
                "user_id": r[1],
                "name": r[2],
                "description": r[3],
                "strategy_a_id": r[4],
                "strategy_b_id": r[5],
                "status": r[6],
                "target_scans": r[7] or 10,
                "completed_scans_a": r[8] or 0,
                "completed_scans_b": r[9] or 0,
                "results_a": results_a,
                "results_b": results_b,
                "winner": r[12],
                "created_at": r[13],
                "completed_at": r[14],
                "strategy_a_name": r[15],
                "strategy_b_name": r[16],
            })

        return results

    def get_ab_test(self, test_id: str) -> Optional[dict[str, Any]]:
        """Get single A/B test by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.id, t.user_id, t.name, t.description,
                   t.strategy_a_id, t.strategy_b_id, t.status,
                   t.target_scans, t.completed_scans_a, t.completed_scans_b,
                   t.results_a, t.results_b, t.winner,
                   t.created_at, t.completed_at,
                   sa.name as strategy_a_name, sb.name as strategy_b_name
            FROM strategy_ab_tests t
            LEFT JOIN strategy_trees sa ON t.strategy_a_id = sa.id
            LEFT JOIN strategy_trees sb ON t.strategy_b_id = sb.id
            WHERE t.id = ?
        """,
            (test_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        tests = self._parse_ab_tests([row])
        return tests[0] if tests else None

    def create_ab_test(
        self,
        name: str,
        strategy_a_id: str,
        strategy_b_id: str,
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        target_scans: int = 10,
    ) -> str:
        """Create a new A/B test"""
        import uuid

        test_id = str(uuid.uuid4())[:8]
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO strategy_ab_tests (
                id, user_id, name, description, strategy_a_id, strategy_b_id,
                status, target_scans, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
            (
                test_id,
                user_id,
                name,
                description,
                strategy_a_id,
                strategy_b_id,
                target_scans,
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return test_id

    def start_ab_test(self, test_id: str) -> bool:
        """Start an A/B test"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE strategy_ab_tests SET status = 'running' WHERE id = ? AND status = 'pending'",
            (test_id,),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def record_ab_test_result(
        self,
        test_id: str,
        strategy_variant: str,
        scan_result: dict[str, Any],
    ) -> bool:
        """Record a scan result for A/B test"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT completed_scans_a, completed_scans_b, results_a, results_b, target_scans
            FROM strategy_ab_tests WHERE id = ? AND status = 'running'
        """,
            (test_id,),
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return False

        scans_a = row[0] or 0
        scans_b = row[1] or 0
        results_a = json.loads(row[2]) if row[2] else {"vulns": 0, "success": 0, "duration": 0}
        results_b = json.loads(row[3]) if row[3] else {"vulns": 0, "success": 0, "duration": 0}
        target = row[4] or 10

        if strategy_variant.lower() == 'a':
            scans_a += 1
            results_a["vulns"] = results_a.get("vulns", 0) + scan_result.get("vulns_found", 0)
            results_a["success"] = results_a.get("success", 0) + (1 if scan_result.get("vulns_found", 0) > 0 else 0)
            results_a["duration"] = results_a.get("duration", 0) + scan_result.get("duration", 0)
        else:
            scans_b += 1
            results_b["vulns"] = results_b.get("vulns", 0) + scan_result.get("vulns_found", 0)
            results_b["success"] = results_b.get("success", 0) + (1 if scan_result.get("vulns_found", 0) > 0 else 0)
            results_b["duration"] = results_b.get("duration", 0) + scan_result.get("duration", 0)

        status = "running"
        winner = None
        completed_at = None

        if scans_a >= target and scans_b >= target:
            status = "completed"
            completed_at = datetime.utcnow().isoformat()

            score_a = results_a.get("vulns", 0) + results_a.get("success", 0) * 0.5
            score_b = results_b.get("vulns", 0) + results_b.get("success", 0) * 0.5

            if score_a > score_b:
                winner = "a"
            elif score_b > score_a:
                winner = "b"
            else:
                winner = "tie"

        cursor.execute(
            """
            UPDATE strategy_ab_tests SET
                completed_scans_a = ?, completed_scans_b = ?,
                results_a = ?, results_b = ?,
                status = ?, winner = ?, completed_at = ?
            WHERE id = ?
        """,
            (
                scans_a, scans_b,
                json.dumps(results_a), json.dumps(results_b),
                status, winner, completed_at,
                test_id,
            ),
        )

        conn.commit()
        conn.close()
        return True

    def cancel_ab_test(self, test_id: str) -> bool:
        """Cancel an A/B test"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE strategy_ab_tests SET status = 'cancelled' WHERE id = ? AND status IN ('pending', 'running')",
            (test_id,),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def delete_ab_test(self, test_id: str, user_id: Optional[str] = None) -> bool:
        """Delete an A/B test"""
        conn = self._get_connection()
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                "DELETE FROM strategy_ab_tests WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
                (test_id, user_id),
            )
        else:
            cursor.execute("DELETE FROM strategy_ab_tests WHERE id = ?", (test_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def get_running_ab_test(self, user_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Get currently running A/B test for user"""
        tests = self.get_ab_tests(user_id=user_id, status="running")
        return tests[0] if tests else None
