import hmac
import hashlib
import json
import os
import logging

logger = logging.getLogger("netra.crypto")

class ForensicSeal:
    """
    Cryptographic Chain of Custody Engine.
    Uses HMAC-SHA256 to create a tamper-evident Merkle-style hash chain.
    """
    def __init__(self, key_path="data/.forensic_master_key"):
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        
        if not os.path.exists(key_path):
            # Generate a secure 256-bit master key
            self.master_key = os.urandom(32)
            with open(key_path, "wb") as f:
                f.write(self.master_key)
            try:
                os.chmod(key_path, 0o600) # Restrict access to owner only
            except Exception:
                pass
            logger.info("Generated new Forensic Master Key.")
        else:
            with open(key_path, "rb") as f:
                self.master_key = f.read()

    def seal(self, data_dict: dict, prev_hash: str = "GENESIS") -> tuple:
        """
        Signs a finding and chains it to the previous hash.
        Returns (current_hash, signature)
        """
        # Deterministic serialization for consistent hashing
        payload = json.dumps(data_dict, sort_keys=True, default=str).encode('utf-8')
        
        # 1. Compute Chain Hash (Proof of Sequence)
        chain_input = prev_hash.encode('utf-8') + payload
        current_hash = hashlib.sha256(chain_input).hexdigest()
        
        # 2. Compute HMAC Signature (Proof of Authenticity)
        signature = hmac.new(self.master_key, current_hash.encode('utf-8'), hashlib.sha256).hexdigest()
        
        return current_hash, signature

    def verify(self, data_dict: dict, prev_hash: str, claimed_hash: str, claimed_signature: str) -> bool:
        """
        Mathematically verifies if a record has been tampered with.
        """
        payload = json.dumps(data_dict, sort_keys=True, default=str).encode('utf-8')
        chain_input = prev_hash.encode('utf-8') + payload
        expected_hash = hashlib.sha256(chain_input).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_hash, claimed_hash):
            return False
            
        expected_sig = hmac.new(self.master_key, expected_hash.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, claimed_signature)
