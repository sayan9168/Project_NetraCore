import sqlite3
import json
import logging
from src.core.database import EvidenceVault
from src.core.crypto_seal import ForensicSeal

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("tamper_test")

def simulate_tamper_and_verify(case_id: str = "CASE-2026-CHAIN-VALID"):
    """
    Simulates a malicious insider attack by directly modifying
    the raw_json payload in the database, then verifies the chain.
    """
    vault = EvidenceVault()
    
    # 1. Get current chain state BEFORE tampering
    logger.info("=" * 60)
    logger.info("STEP 1: Verifying chain BEFORE tampering...")
    chain_before = vault.get_case_chain(case_id)
    
    if not chain_before:
        logger.error(f"No evidence chain found for case: {case_id}")
        return
        
    prev_hash = "GENESIS"
    is_valid_before = True
    
    for raw_json, db_prev, db_current, db_sig in chain_before:
        data_dict = json.loads(raw_json)
        if not vault.seal.verify(data_dict, db_prev, db_current, db_sig):
            is_valid_before = False
            break
        prev_hash = db_current
        
    logger.info(f"Chain Status BEFORE Tampering: {'INTACT ✅' if is_valid_before else 'TAMPERED ❌'}")
    logger.info(f"Total Records: {len(chain_before)}")
    
    # 2. Simulate Tampering (Malicious Insider Attack)
    logger.info("=" * 60)
    logger.info("STEP 2: Simulating malicious insider attack...")
    logger.info("Modifying severity from 'HIGH' to 'LOW' in database...")
    
    cursor = vault.conn.cursor()
    cursor.execute("""
        UPDATE findings 
        SET raw_json = replace(raw_json, '"severity": "HIGH"', '"severity": "LOW"'),
            raw_json = replace(raw_json, '"severity": "CRITICAL"', '"severity": "LOW"'),
            raw_json = replace(raw_json, '"severity": "MEDIUM"', '"severity": "LOW"')
        WHERE case_id = ?
    """, (case_id,))
    
    rows_affected = cursor.rowcount
    vault.conn.commit()
    
    if rows_affected == 0:
        logger.warning("No rows were updated. The original data might not contain the target strings.")
        logger.info("Attempting alternative tamper: modifying title field...")
        cursor.execute("""
            UPDATE findings 
            SET raw_json = replace(raw_json, '"title":', '"title": "TAMPERED -')
            WHERE case_id = ?
            LIMIT 1
        """, (case_id,))
        rows_affected = cursor.rowcount
        vault.conn.commit()
        
    logger.info(f"Rows modified in database: {rows_affected}")
    
    # 3. Verify chain AFTER tampering
    logger.info("=" * 60)
    logger.info("STEP 3: Verifying chain AFTER tampering...")
    
    chain_after = vault.get_case_chain(case_id)
    prev_hash = "GENESIS"
    is_valid_after = True
    failed_at_record = None
    
    for idx, (raw_json, db_prev, db_current, db_sig) in enumerate(chain_after):
        data_dict = json.loads(raw_json)
        if not vault.seal.verify(data_dict, db_prev, db_current, db_sig):
            is_valid_after = False
            failed_at_record = idx + 1
            break
        prev_hash = db_current
        
    logger.info("=" * 60)
    logger.info("VERIFICATION RESULTS:")
    logger.info(f"Chain Status AFTER Tampering: {'INTACT ❌ (UNEXPECTED)' if is_valid_after else 'TAMPERED ✅ (EXPECTED)'}")
    
    if not is_valid_after:
        logger.info(f"Tampering detected at record #: {failed_at_record}")
        logger.info("Court Admissibility: REJECTED ❌")
    else:
        logger.info("WARNING: Tampering was NOT detected. Cryptographic chain may be compromised.")
        
    logger.info("=" * 60)

if __name__ == "__main__":
    simulate_tamper_and_verify()
