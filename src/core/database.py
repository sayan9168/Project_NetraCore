import sqlite3
import os
import json
from typing import List
from src.core.crypto_seal import ForensicSeal

class EvidenceVault:
    def __init__(self, db_path="data/netra_vault.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.seal = ForensicSeal()
        self._init_schema()

    def _init_schema(self):
        cursor = self.conn.cursor()
        # PRODUCTION FIX: Use IF NOT EXISTS to prevent data loss on initialization
        cursor.execute('''
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
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_case_id ON findings(case_id)')
        self.conn.commit()

    def _get_last_hash(self, case_id: str) -> str:
        cursor = self.conn.cursor()
        # Use rowid DESC to guarantee strict insertion order
        cursor.execute("SELECT current_hash FROM findings WHERE case_id = ? ORDER BY rowid DESC LIMIT 1", (case_id,))
        row = cursor.fetchone()
        return row[0] if row else "GENESIS"

    def store_findings(self, case_id: str, findings: list):
        cursor = self.conn.cursor()
        prev_hash = self._get_last_hash(case_id)
        
        for f in findings:
            data_dict = f.dict() if hasattr(f, 'dict') else f.__dict__
            raw_json_str = json.dumps(data_dict, sort_keys=True, default=str)
            
            current_hash, signature = self.seal.seal(data_dict, prev_hash)
            
            cursor.execute('''
                INSERT OR IGNORE INTO findings 
                (finding_id, case_id, module, severity, title, raw_json, prev_hash, current_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(data_dict.get('finding_id')),
                case_id,
                str(data_dict.get('module')),
                str(data_dict.get('severity')),
                str(data_dict.get('title')),
                raw_json_str,
                prev_hash,
                current_hash,
                signature
            ))
            
            prev_hash = current_hash
            
        self.conn.commit()

    def get_case_findings(self, case_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT raw_json FROM findings WHERE case_id = ? ORDER BY rowid ASC", (case_id,))
        return [json.loads(row[0]) for row in cursor.fetchall()]

    def get_case_chain(self, case_id: str) -> list:
        cursor = self.conn.cursor()
        # Use rowid ASC to ensure chain is verified in exact insertion order
        cursor.execute("""
            SELECT raw_json, prev_hash, current_hash, signature 
            FROM findings WHERE case_id = ? ORDER BY rowid ASC
        """, (case_id,))
        return cursor.fetchall()
