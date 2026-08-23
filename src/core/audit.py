import json
import logging
import os
import hashlib
from datetime import datetime, timezone

class ImmutableAuditLogger:
    def __init__(self, log_dir: str = "logs/audit"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl")
        self.logger = logging.getLogger("netra.audit")
        self._last_hash = "GENESIS"
        
    def record(self, actor: str, action: str, resource_id: str, details: dict, status: str = "SUCCESS"):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "resource_id": resource_id,
            "status": status,
            "details": details,
            "prev_hash": self._last_hash
        }
        
        # Chain of Custody Hash
        entry_str = json.dumps(entry, sort_keys=True)
        current_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        entry["current_hash"] = current_hash
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        self._last_hash = current_hash
        self.logger.info(f"AUDIT | {action} | {resource_id} | {status}")
