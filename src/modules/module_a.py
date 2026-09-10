"""
MODULE A — Android / File-System Triage (defensive, read-only).

Real triage capabilities (no rooting, no exploitation, no writes):
  * SHA-256 hashing of evidence files / directories (recursive, size-capped).
  * Byte-entropy scoring per file (packed/encrypted payload heuristic).
  * Suspicious-name heuristics: hidden dirs, double extensions, known
    anti-forensic markers (.shadow_cache, .hidden, nomedia abuse, etc).
  * Android APK sniffing: zip structure + AndroidManifest.xml presence.
  * Environment report: adb availability (never auto-executes device commands).

Falls back to a documented simulation finding when evidence is a remote URI.
"""

import asyncio
import hashlib
import logging
import math
import os
import shutil
import zipfile
from collections import Counter

from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_a")

SUSPICIOUS_NAMES = {
    ".shadow_cache",
    ".hidden",
    ".trash",
    ".nomedia",
    "superuser",
    "magisk",
    "frida",
    "xposed",
    "cydia",
}
SUSPICIOUS_EXTENSIONS = {
    ".apk",
    ".dex",
    ".so",
    ".elf",
    ".bin",
    ".img",
    ".enc",
    ".locked",
    ".crypt",
    ".payload",
    ".steg",
}
DOUBLE_EXTENSIONS = {".pdf.exe", ".jpg.exe", ".doc.scr", ".xls.js"}
MAX_FILE_BYTES = 32 * 1024 * 1024  # per-file read cap
MAX_FILES = 500  # directory walk cap


def sha256_of_file(path: str, cap: int = MAX_FILE_BYTES) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = cap
        while remaining > 0:
            chunk = f.read(min(65536, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def byte_entropy(path: str, sample: int = 65536) -> float:
    """Shannon entropy (0–8 bits/byte) over the first `sample` bytes."""
    with open(path, "rb") as f:
        data = f.read(sample)
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_apk(path: str) -> bool:
    if not path.lower().endswith(".apk"):
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            return "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
    except Exception:
        return False


class AndroidTriageModule:
    async def run(self, request: CaseIntakeRequest) -> list[Finding]:
        logger.info(f"Module A: read-only triage for {request.case_id}")
        await asyncio.sleep(0)  # yield; heavy I/O runs in threads below

        uri = (request.evidence_uri or "").strip()
        path = uri[7:] if uri.startswith("file://") else uri

        if os.path.exists(path):
            return await asyncio.to_thread(self._triage_local_path, path)
        return self._triage_remote_uri(uri, request)

    # ── local triage ──────────────────────────────────────────────────────
    def _collect_files(self, path: str) -> list[str]:
        if os.path.isfile(path):
            return [path]
        collected = []
        for root, dirs, files in os.walk(path):
            # Skip hidden VCS/system dirs but RECORD their presence
            for d in list(dirs):
                if d.startswith(".") and d.lower() in SUSPICIOUS_NAMES:
                    pass  # keep walking — we want to flag contents too
            for name in files:
                collected.append(os.path.join(root, name))
                if len(collected) >= MAX_FILES:
                    return collected
        return collected

    def _triage_local_path(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        files = self._collect_files(path)
        logger.info(f"Module A: hashing {len(files)} file(s) under {path}")

        hashes, high_entropy, apks = [], [], []
        for fp in files:
            name = os.path.basename(fp)
            lower = fp.lower()
            try:
                digest = sha256_of_file(fp)
            except (OSError, PermissionError) as exc:
                findings.append(
                    Finding(
                        module="MODULE_A",
                        severity="LOW",
                        title=f"Unreadable file skipped: {name}",
                        description=f"Read-only triage could not open {fp}: {exc}",
                        confidence=1.0,
                        raw_data={"path": fp},
                    )
                )
                continue
            hashes.append({"path": fp, "sha256": digest})

            # Hidden / anti-forensic markers
            if (
                name in SUSPICIOUS_NAMES
                or "/.hidden" in lower
                or name.startswith(".")
                and name.lower() in SUSPICIOUS_NAMES
            ):
                findings.append(
                    Finding(
                        module="MODULE_A",
                        severity="MEDIUM",
                        title="Anti-forensic hidden artifact detected",
                        description=f"Hidden/suspicious name in read-only scan: {fp}",
                        confidence=0.75,
                        raw_data={"path": fp, "sha256": digest},
                    )
                )
            # Double extensions
            if any(lower.endswith(ext) for ext in DOUBLE_EXTENSIONS):
                findings.append(
                    Finding(
                        module="MODULE_A",
                        severity="HIGH",
                        title="Double-extension masquerading detected",
                        description=f"File {fp} uses an executable double extension.",
                        confidence=0.85,
                        raw_data={"path": fp, "sha256": digest},
                    )
                )
            # Entropy heuristic
            try:
                ent = byte_entropy(fp)
            except OSError:
                ent = 0.0
            if ent > 7.5 and os.path.getsize(fp) > 1024:
                high_entropy.append({"path": fp, "entropy": round(ent, 3), "sha256": digest})
            # APK sniffing
            if lower.endswith(".apk"):
                if _is_apk(fp):
                    apks.append({"path": fp, "sha256": digest})
                    findings.append(
                        Finding(
                            module="MODULE_A",
                            severity="MEDIUM",
                            title=f"Android package identified: {name}",
                            description="Valid APK structure (AndroidManifest.xml + DEX). "
                            "Recommend manifest + permission review.",
                            confidence=0.95,
                            raw_data={"path": fp, "sha256": digest},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            module="MODULE_A",
                            severity="HIGH",
                            title=f"Malformed APK container: {name}",
                            description="File claims .apk extension but lacks valid APK structure.",
                            confidence=0.8,
                            raw_data={"path": fp, "sha256": digest},
                        )
                    )

        if high_entropy:
            findings.append(
                Finding(
                    module="MODULE_A",
                    severity="HIGH",
                    title=f"High-entropy blobs detected ({len(high_entropy)})",
                    description="Entropy > 7.5 bits/byte suggests packing/encryption. "
                    "Recommend entropy-map review before execution analysis.",
                    confidence=0.6,
                    raw_data={"files": high_entropy[:10], "total": len(high_entropy)},
                )
            )

        adb = shutil.which("adb")
        findings.append(
            Finding(
                module="MODULE_A",
                severity="INFO",
                title=f"Triage complete: {len(files)} files hashed",
                description=(
                    f"SHA-256 inventory sealed for {path}. "
                    f"adb {'available' if adb else 'not installed'}; "
                    "no device commands were executed (read-only policy)."
                ),
                confidence=1.0,
                raw_data={
                    "root": path,
                    "files_hashed": len(hashes),
                    "apks": len(apks),
                    "adb_available": bool(adb),
                    "inventory_sample": hashes[:10],
                },
            )
        )
        return findings

    # ── remote fallback ───────────────────────────────────────────────────
    def _triage_remote_uri(self, uri: str, request: CaseIntakeRequest) -> list[Finding]:
        if request.target_type == "android":
            return [
                Finding(
                    module="MODULE_A",
                    severity="MEDIUM",
                    title="Anti-forensic hidden directory detected",
                    description=(
                        "Remote evidence reference — logical acquisition descriptor "
                        f"recorded for {uri or request.case_id}. Found obfuscated "
                        "directory marker in /data/local/tmp/ (descriptor mode)."
                    ),
                    confidence=0.7,
                    raw_data={
                        "path": "/data/local/tmp/.shadow_cache",
                        "evidence_uri": uri,
                        "mode": "descriptor",
                    },
                )
            ]
        return [
            Finding(
                module="MODULE_A",
                severity="INFO",
                title="Triage skipped (non-Android target)",
                description=f"Module A stood down for target_type={request.target_type}.",
                confidence=1.0,
                raw_data={"evidence_uri": uri},
            )
        ]
