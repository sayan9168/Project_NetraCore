from sentence_transformers import SentenceTransformer
import numpy as np
import asyncio
import logging
import json
import os
from typing import List
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_d")

class LegalNLPModule:
    """
    Real Semantic Vector Search Engine using Sentence-BERT.
    Maps technical findings to BNS/IT Act using Cosine Similarity.
    """
    def __init__(self, model_name='all-MiniLM-L6-v2', db_path="data/legal_vectors.npy"):
        logger.info(f"Module D: Loading Sentence-BERT Model ({model_name})... This may take a minute on first run.")
        self.model = SentenceTransformer(model_name)
        self.db_path = db_path
        self.corpus, self.embeddings, self.metadata = self._load_or_build_corpus()
        logger.info("Module D: Legal Vector Engine Ready.")

    def _load_or_build_corpus(self):
        if os.path.exists(self.db_path) and os.path.exists(self.db_path + ".meta"):
            embeddings = np.load(self.db_path)
            with open(self.db_path + ".meta", "r") as f:
                meta = json.load(f)
            return meta["texts"], embeddings, meta["data"]
            
        # Build Real Legal Corpus
        corpus_texts = [
            "Unauthorized access, downloading, extracting, or disrupting any computer resource or network. Hacking data theft.",
            "Body corporate negligent in implementing reasonable security practices resulting in wrongful loss or data exposure. Cloud misconfiguration.",
            "Concealing, destroying, or altering any computer source code or digital logs. Anti-forensics tampering.",
            "Electronic forgery, manipulation of digital records, or creating false digital evidence. Deepfake image splicing.",
            "Threats or illicit communication via anonymous channels, hidden payloads, or steganography."
        ]
        metadata = [
            {"act": "IT Act 2000", "section": "Section 43", "title": "Damage to computer systems"},
            {"act": "IT Act 2000", "section": "Section 43A", "title": "Compensation for failure to protect data"},
            {"act": "IT Act 2000", "section": "Section 65", "title": "Tampering with computer source documents"},
            {"act": "BNS 2023", "section": "Section 336(3)", "title": "Forgery for purpose of cheating"},
            {"act": "BNS 2023", "section": "Section 351(4)", "title": "Criminal intimidation via anonymous communication"}
        ]
        
        embeddings = self.model.encode(corpus_texts, convert_to_numpy=True)
        np.save(self.db_path, embeddings)
        with open(self.db_path + ".meta", "w") as f:
            json.dump({"texts": corpus_texts, "data": metadata}, f)
            
        return corpus_texts, embeddings, metadata

    async def run(self, request: CaseIntakeRequest) -> List[Finding]:
        logger.info(f"Module D: Executing Semantic Vector Search for {request.case_id}...")
        
        # Generate query based on case context
        query_text = f"Investigation of {request.target_type} breach. Evidence URI: {request.evidence_uri}. Priority: {request.priority}."
        query_embedding = self.model.encode([query_text], convert_to_numpy=True)
        
        # Cosine Similarity Search
        similarities = np.dot(self.embeddings, query_embedding.T).flatten()
        top_indices = np.argsort(similarities)[::-1][:2] # Top 2 matches
        
        findings = []
        for idx in top_indices:
            if similarities[idx] > 0.3: # Semantic threshold
                meta = self.metadata[idx]
                findings.append(Finding(
                    module="MODULE_D", severity="INFO",
                    title=f"Legal Mapping: {meta['act']} {meta['section']}",
                    description=f"{meta['title']}. (Semantic Match Score: {similarities[idx]:.2f})",
                    confidence=float(similarities[idx]),
                    raw_data={"act": meta['act'], "section": meta['section'], "model": "all-MiniLM-L6-v2"}
                ))
        return findings
