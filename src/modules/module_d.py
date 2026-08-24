"""
Production Legal NLP Module with Graceful Degradation.
Python 3.14 compatible scoping.

Modes:
  - FULL: Sentence-BERT semantic search (when available)
  - FALLBACK: SQLite FTS5 keyword search (always works)
"""
import asyncio
import logging
import json
import os
import sqlite3
from typing import List
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_d")

# Module-level detection (executed once at import time)
BERT_AVAILABLE = False
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    BERT_AVAILABLE = True
except ImportError:
    pass


class LegalNLPModule:
    """Legal NLP with automatic fallback to FTS5."""

    def __init__(self, db_path="data/legal_knowledge.db"):
        self.db_path = db_path
        self.bert = None
        self.embeddings = None
        self.corpus_meta = None
        self.corpus_texts = None
        
        # Determine mode using module-level constant (no scoping issue)
        if BERT_AVAILABLE:
            self.mode = "FULL"
            logger.info("Module D: Loading Sentence-BERT (may take 1-2 min first run)...")
            try:
                self.bert = SentenceTransformer('all-MiniLM-L6-v2')
                self._build_vector_corpus()
                logger.info(f"Module D ready in {self.mode} mode")
            except Exception as e:
                logger.warning(f"BERT load failed: {e}. Falling back to FTS5.")
                self.mode = "FALLBACK_FTS5"
                self.bert = None
        else:
            self.mode = "FALLBACK_FTS5"
            logger.info("Module D initialized in FALLBACK_FTS5 mode")

    def _build_vector_corpus(self):
        """Build semantic vector index."""
        self.corpus_texts = [
            "Unauthorized access hacking data theft computer network",
            "Cloud misconfiguration public bucket data exposure negligence",
            "Anti-forensics log wiping tampering source code destruction",
            "Electronic forgery image splicing deepfake manipulation",
            "Anonymous threats steganography hidden payload covert channel"
        ]
        self.corpus_meta = [
            {"act": "IT Act 2000", "section": "Section 43"},
            {"act": "IT Act 2000", "section": "Section 43A"},
            {"act": "IT Act 2000", "section": "Section 65"},
            {"act": "BNS 2023", "section": "Section 336(3)"},
            {"act": "BNS 2023", "section": "Section 351(4)"}
        ]
        if self.bert is not None:
            self.embeddings = self.bert.encode(self.corpus_texts, convert_to_numpy=True)

    async def run(self, request: CaseIntakeRequest) -> List[Finding]:
        logger.info(f"Module D: Running in {self.mode} mode for {request.case_id}")
        
        if self.bert is not None and self.mode == "FULL":
            return await self._semantic_search(request)
        else:
            return await self._fts5_search(request)

    async def _semantic_search(self, request: CaseIntakeRequest) -> List[Finding]:
        """Sentence-BERT semantic vector search."""
        query = f"Investigation of {request.target_type} breach priority {request.priority}"
        query_embedding = self.bert.encode([query], convert_to_numpy=True)
        
        similarities = np.dot(self.embeddings, query_embedding.T).flatten()
        top_indices = np.argsort(similarities)[::-1][:2]
        
        findings = []
        for idx in top_indices:
            if similarities[idx] > 0.3:
                meta = self.corpus_meta[idx]
                findings.append(Finding(
                    module="MODULE_D", severity="INFO",
                    title=f"Legal Mapping: {meta['act']} {meta['section']}",
                    description=f"Semantic match score: {similarities[idx]:.3f}",
                    confidence=float(similarities[idx]),
                    raw_data={"act": meta['act'], "section": meta['section'],
                             "mode": "BERT", "score": round(float(similarities[idx]), 3)}
                ))
        return findings

    async def _fts5_search(self, request: CaseIntakeRequest) -> List[Finding]:
        """SQLite FTS5 keyword search (always works)."""
        findings = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            queries = []
            if request.target_type == "android":
                queries = ["unauthorized access extraction", "anti-forensics log wiping"]
            elif request.target_type == "cloud":
                queries = ["cloud exposure public bucket", "data leak negligence"]
            elif request.target_type == "media":
                queries = ["steganography hidden threat", "forgery manipulation"]
            else:
                queries = ["unauthorized access"]

            seen = set()
            for query in queries:
                cursor.execute("""
                    SELECT act, section, title, description 
                    FROM statutes_fts 
                    WHERE statutes_fts MATCH ? 
                    ORDER BY bm25(statutes_fts) 
                    LIMIT 1
                """, (query,))
                match = cursor.fetchone()
                if match:
                    act, section, title, desc = match
                    key = f"{act}-{section}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            module="MODULE_D", severity="INFO",
                            title=f"Legal Mapping: {act} {section}",
                            description=f"{title}. {desc}",
                            confidence=0.85,
                            raw_data={"act": act, "section": section,
                                     "mode": "FTS5", "query": query}
                        ))
            conn.close()
        except Exception as e:
            logger.error(f"FTS5 search failed: {e}")
        
        return findings[:3]
