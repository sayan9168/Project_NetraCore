import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

from src.core.crypto_seal import ForensicSeal


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceVault:
    """
    Tamper-evident evidence vault (SQLite + HMAC-SHA256 hash chain).

    Thread-safe: all writes are serialized through an internal lock.
    """

    def __init__(self, db_path="data/netra_vault.db"):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.seal = ForensicSeal()
        self._init_schema()

    def _init_schema(self):
        cursor = self.conn.cursor()
        # PRODUCTION FIX: Use IF NOT EXISTS to prevent data loss on initialization
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                module TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_id ON findings(case_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_module ON findings(module)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'MEDIUM',
                status TEXT NOT NULL DEFAULT 'OPEN',
                findings_count INTEGER NOT NULL DEFAULT 0,
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

    # ─── hash chain core ───────────────────────────────────────────────────
    def _get_last_hash(self, case_id: str) -> str:
        cursor = self.conn.cursor()
        # Use rowid DESC to guarantee strict insertion order
        cursor.execute(
            "SELECT current_hash FROM findings WHERE case_id = ? ORDER BY rowid DESC LIMIT 1",
            (case_id,),
        )
        row = cursor.fetchone()
        return row[0] if row else "GENESIS"

    def store_findings(self, case_id: str, findings: list):
        from src.core.models import finding_to_dict

        with self._lock:
            cursor = self.conn.cursor()
            prev_hash = self._get_last_hash(case_id)

            for f in findings:
                data_dict = (
                    finding_to_dict(f)
                    if hasattr(f, "dict") or hasattr(f, "model_dump")
                    else dict(f)
                )
                raw_json_str = json.dumps(data_dict, sort_keys=True, default=str)

                current_hash, signature = self.seal.seal(data_dict, prev_hash)

                cursor.execute(
                    """
                    INSERT OR IGNORE INTO findings
                    (finding_id, case_id, module, severity, title, raw_json, prev_hash, current_hash, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        str(data_dict.get("finding_id")),
                        case_id,
                        str(data_dict.get("module")),
                        str(data_dict.get("severity")),
                        str(data_dict.get("title")),
                        raw_json_str,
                        prev_hash,
                        current_hash,
                        signature,
                    ),
                )

                prev_hash = current_hash

            cursor.execute(
                "UPDATE cases SET findings_count = findings_count + ?, updated_at = ? WHERE case_id = ?",
                (len(findings), _utcnow_iso(), case_id),
            )
            self.conn.commit()

    def get_case_findings(self, case_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT raw_json FROM findings WHERE case_id = ? ORDER BY rowid ASC", (case_id,)
        )
        return [json.loads(row[0]) for row in cursor.fetchall()]

    def get_case_chain(self, case_id: str) -> list:
        cursor = self.conn.cursor()
        # Use rowid ASC to ensure chain is verified in exact insertion order
        cursor.execute(
            """
            SELECT raw_json, prev_hash, current_hash, signature
            FROM findings WHERE case_id = ? ORDER BY rowid ASC
        """,
            (case_id,),
        )
        return cursor.fetchall()

    def verify_chain(self, case_id: str) -> dict:
        """Verify the full hash chain for a case. Returns status dict."""
        chain = self.get_case_chain(case_id)
        if not chain:
            return {
                "case_id": case_id,
                "chain_status": "EMPTY",
                "court_admissibility": "N/A",
                "records": 0,
            }
        prev = "GENESIS"
        for raw, p, c, sig in chain:
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                data = {}
            if p != prev or not self.seal.verify(data, p, c, sig):
                return {
                    "case_id": case_id,
                    "chain_status": "TAMPERED",
                    "court_admissibility": "REJECTED",
                    "records": len(chain),
                }
            prev = c
        return {
            "case_id": case_id,
            "chain_status": "INTACT",
            "court_admissibility": "VALID",
            "records": len(chain),
        }

    # ─── case registry ─────────────────────────────────────────────────────
    def register_case(
        self,
        case_id: str,
        target_type: str,
        priority: str = "MEDIUM",
        created_by: str | None = None,
    ) -> None:
        now = _utcnow_iso()
        with self._lock:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO cases
                (case_id, target_type, priority, status, findings_count, created_by, created_at, updated_at)
                VALUES (?, ?, ?, 'OPEN', 0, ?, ?, ?)
            """,
                (case_id, target_type, priority, created_by, now, now),
            )
            self.conn.commit()

    def touch_case(self, case_id: str, status: str = "COMPLETED") -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (status, _utcnow_iso(), case_id),
            )
            self.conn.commit()

    def get_case_meta(self, case_id: str) -> dict | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_cases(
        self,
        limit: int = 50,
        offset: int = 0,
        priority: str | None = None,
        target_type: str | None = None,
    ) -> tuple[list, int]:
        clauses, params = [], []
        if priority:
            clauses.append("priority = ?")
            params.append(priority)
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM cases {where}", params)
        total = cursor.fetchone()[0]
        cursor.execute(
            f"SELECT * FROM cases {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [dict(r) for r in cursor.fetchall()], total

    def count_cases(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cases")
        return cursor.fetchone()[0]

    def delete_case(self, case_id: str) -> int:
        """
        Delete a case and its findings. Returns findings removed.
        NOTE: destructive by design — restricted to admin role at the API layer
        and always recorded in the immutable audit log.
        """
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
            removed = cursor.rowcount
            cursor.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            self.conn.commit()
            return removed

    # ─── search / stats / export ───────────────────────────────────────────
    def search_findings(
        self,
        case_id: str,
        query: str | None = None,
        severity: str | None = None,
        module: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        clauses, params = ["case_id = ?"], [case_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if module:
            clauses.append("module = ?")
            params.append(module)
        if query:
            clauses.append("(title LIKE ? OR raw_json LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])
        where = "WHERE " + " AND ".join(clauses)
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM findings {where}", params)
        total = cursor.fetchone()[0]
        cursor.execute(
            f"SELECT raw_json FROM findings {where} ORDER BY rowid ASC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [json.loads(r[0]) for r in cursor.fetchall()], total

    def get_case_stats(self, case_id: str) -> dict:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE case_id = ? GROUP BY severity",
            (case_id,),
        )
        severity = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.execute(
            "SELECT module, COUNT(*) FROM findings WHERE case_id = ? GROUP BY module", (case_id,)
        )
        modules = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (case_id,))
        return {
            "total": cursor.fetchone()[0],
            "severity_breakdown": severity,
            "module_breakdown": modules,
        }

    def global_stats(self) -> dict:
        cursor = self.conn.cursor()
        cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        severity = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) FROM findings")
        findings = cursor.fetchone()[0]
        return {"cases": self.count_cases(), "findings": findings, "severity_breakdown": severity}

    def export_case_bundle(self, case_id: str) -> dict | None:
        """Full evidence bundle: metadata + findings + chain hashes (JSON)."""
        meta = self.get_case_meta(case_id)
        chain = self.get_case_chain(case_id)
        if meta is None and not chain:
            return None
        records = []
        for raw, prev, curr, sig in chain:
            records.append(
                {
                    "finding": json.loads(raw),
                    "prev_hash": prev,
                    "current_hash": curr,
                    "signature": sig,
                }
            )
        verification = self.verify_chain(case_id)
        return {
            "case": meta,
            "exported_at": _utcnow_iso(),
            "verification": verification,
            "records": records,
        }
