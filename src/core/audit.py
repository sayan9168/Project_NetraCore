import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone


class ImmutableAuditLogger:
    """
    Append-only, hash-chained JSONL audit log (chain-of-custody).

    Every entry links to the previous via prev_hash → current_hash,
    so silent edits/deletions are detectable via :meth:`verify_chain`.
    """

    def __init__(self, log_dir: str = "logs/audit"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_dir = log_dir
        self.log_file = os.path.join(
            log_dir, f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        )
        self.logger = logging.getLogger("netra.audit")
        self._lock = threading.Lock()
        self._last_hash = self._recover_tip()

    # ── writing ───────────────────────────────────────────────────────────
    def _recover_tip(self) -> str:
        """Resume the chain tip from disk so restarts don't fork the chain."""
        if not os.path.exists(self.log_file):
            return "GENESIS"
        try:
            last = None
            with open(self.log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = line
            if last:
                return json.loads(last).get("current_hash", "GENESIS")
        except Exception:
            pass
        return "GENESIS"

    def _rollover_if_needed(self) -> None:
        today = os.path.join(
            self.log_dir, f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        )
        if today != self.log_file:
            self.log_file = today
            self._last_hash = "GENESIS"

    def record(
        self, actor: str, action: str, resource_id: str, details: dict, status: str = "SUCCESS"
    ):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "resource_id": resource_id,
            "status": status,
            "details": details,
            "prev_hash": self._last_hash,
        }

        # Chain of Custody Hash
        entry_str = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        entry["current_hash"] = current_hash

        with self._lock:
            self._rollover_if_needed()
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

        self._last_hash = current_hash
        self.logger.info(f"AUDIT | {action} | {resource_id} | {status}")
        return entry

    # ── reading / verification ────────────────────────────────────────────
    def read_entries(self, limit: int = 100, log_file: str | None = None) -> list:
        path = log_file or self.log_file
        if not os.path.exists(path):
            return []
        entries = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries[-limit:]

    def list_log_files(self) -> list:
        if not os.path.isdir(self.log_dir):
            return []
        return sorted(f for f in os.listdir(self.log_dir) if f.endswith(".jsonl"))

    def verify_chain(self, log_file: str | None = None) -> dict:
        """
        Recompute every link in an audit log file.
        Returns {log_file, entries, chain_status, failed_at}.
        """
        path = log_file or self.log_file
        if not os.path.exists(path):
            return {"log_file": path, "entries": 0, "chain_status": "EMPTY", "failed_at": None}
        prev = "GENESIS"
        count = 0
        with open(path) as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return {
                        "log_file": path,
                        "entries": count,
                        "chain_status": "TAMPERED",
                        "failed_at": lineno,
                    }
                if entry.get("prev_hash") != prev:
                    return {
                        "log_file": path,
                        "entries": count,
                        "chain_status": "TAMPERED",
                        "failed_at": lineno,
                    }
                claimed = entry.get("current_hash", "")
                recomputed = hashlib.sha256(
                    json.dumps(
                        {k: v for k, v in entry.items() if k != "current_hash"}, sort_keys=True
                    ).encode()
                ).hexdigest()
                if recomputed != claimed:
                    return {
                        "log_file": path,
                        "entries": count,
                        "chain_status": "TAMPERED",
                        "failed_at": lineno,
                    }
                prev = claimed
        return {
            "log_file": path,
            "entries": count,
            "chain_status": "INTACT" if count else "EMPTY",
            "failed_at": None,
        }
