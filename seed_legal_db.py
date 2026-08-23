import sqlite3
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netra.legal_seeder")

def seed_legal_vault(db_path="data/legal_knowledge.db"):
    """
    Seeds the SQLite FTS5 Legal Knowledge Base with BNS and IT Act statutes.
    This creates a highly optimized inverted index for sub-millisecond NLP retrieval.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create FTS5 Virtual Table for High-Performance Text Search
    cursor.execute('''
        CREATE VIRTUAL TABLE IF NOT EXISTS statutes_fts USING fts5(
            act, 
            section, 
            title, 
            description, 
            keywords,
            tokenize='porter unicode61'
        );
    ''')
    
    # Clear previous seeds to ensure idempotency
    cursor.execute("DELETE FROM statutes_fts")
    
    # Production-Grade Legal Corpus (BNS 2023 & IT Act 2000)
    corpus = [
        # IT Act 2000
        ("IT Act 2000", "Section 43", "Damage to computer systems", 
         "Unauthorized access, downloading, extracting, or disrupting any computer resource or network.", 
         "hacking unauthorized access data theft extraction triage"),
         
        ("IT Act 2000", "Section 43A", "Compensation for failure to protect data", 
         "Body corporate negligent in implementing reasonable security practices resulting in wrongful loss or data exposure.", 
         "cloud exposure public bucket s3 negligence security failure misconfiguration"),
         
        ("IT Act 2000", "Section 65", "Tampering with computer source documents", 
         "Concealing, destroying, or altering any computer source code or digital logs.", 
         "tampering source code log wiping anti-forensics destruction alteration"),
         
        ("IT Act 2000", "Section 66", "Computer related offences", 
         "Dishonestly or fraudulently doing any act referred to in section 43 with criminal intent.", 
         "hacking fraud cybercrime unauthorized access malware"),
         
        ("IT Act 2000", "Section 72A", "Breach of confidentiality and privacy", 
         "Disclosure of information obtained under lawful contract or authority without consent.", 
         "privacy breach data leak unauthorized disclosure osint leak"),

        # BNS 2023 (Bharatiya Nyaya Sanhita)
        ("BNS 2023", "Section 336(3)", "Forgery for purpose of cheating", 
         "Electronic forgery, manipulation of digital records, or creating false digital evidence.", 
         "anti-forensics tampering log wiping forgery deepfake manipulation"),
         
        ("BNS 2023", "Section 340", "Forgery for purpose of harming reputation", 
         "Using forged electronic documents or media to harm reputation.", 
         "defamation fake evidence steganography adversarial noise"),
         
        ("BNS 2023", "Section 351(4)", "Criminal intimidation via anonymous communication", 
         "Threats or illicit communication via anonymous channels, hidden payloads, or steganography.", 
         "steganography hidden threat anonymous payload covert channel"),
    ]
    
    cursor.executemany("""
        INSERT INTO statutes_fts (act, section, title, description, keywords) 
        VALUES (?, ?, ?, ?, ?)
    """, corpus)
    
    conn.commit()
    conn.close()
    logger.info(f"Legal Knowledge Base Seeded Successfully with {len(corpus)} statutes at {db_path}")

if __name__ == "__main__":
    seed_legal_vault()
