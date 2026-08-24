"""
RSA-4096 Digital Signature Engine for Court-Admissible PDF Reports.
Complies with Indian IT Act 2000 Section 3 (Electronic Signature) requirements.
"""
import os
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class PDFSigner:
    """Generates RSA-4096 signatures for forensic PDF reports."""

    def __init__(self, key_path: str = "data/signing_keys/forensic_rsa.pem"):
        self.key_path = key_path
        self._ensure_keys()

    def _ensure_keys(self):
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)

        if os.path.exists(self.key_path) and os.path.exists(self.key_path + ".pub"):
            with open(self.key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            with open(self.key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self.key_path + ".pub", "wb") as f:
                f.write(self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            try:
                os.chmod(self.key_path, 0o600)
            except Exception:
                pass

    def sign_document(self, pdf_path: str) -> dict:
        """Signs a PDF file and returns signature metadata."""
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        sha256_hash = hashlib.sha256(pdf_bytes).hexdigest()

        signature = self.private_key.sign(
            pdf_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sig_b64 = base64.b64encode(signature).decode("utf-8")

        return {
            "algorithm": "RSA-4096 + PSS + SHA256",
            "document_sha256": sha256_hash,
            "signature_b64": sig_b64,
            "signature_length_bytes": len(signature),
            "signed_at": datetime.utcnow().isoformat() + "Z",
            "signer": "Project Netra-Core Forensic Engine"
        }

    def verify_signature(self, pdf_path: str, signature_b64: str) -> bool:
        """Verifies a signature against a PDF file using the public key."""
        try:
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            with open(self.key_path + ".pub", "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )

            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature, pdf_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                           salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def get_public_key_pem(self) -> str:
        with open(self.key_path + ".pub", "r") as f:
            return f.read()
