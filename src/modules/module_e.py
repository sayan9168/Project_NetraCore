"""
MODULE E — Network & IOC Forensics (stdlib-only, always available).

Defensive capabilities:
  * Extract Indicators of Compromise (IPv4, domains, URLs, emails,
    MD5/SHA1/SHA256 hashes, ports) from evidence text or local files.
  * Enrich: private vs public IP, suspicious TLD, known-malicious feed match.
  * Score severity without any outbound network calls (no SSRF surface —
    remote evidence URIs are parsed, never fetched).

Runs for every target_type as a cheap sweep, and deep-scans `network` cases.
"""

import ipaddress
import json
import logging
import os
import re

from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_e")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
PORT_RE = re.compile(r":(\d{1,5})\b")

_DEFAULT_FEED = {
    "malicious_ips": [],
    "malicious_domains": [],
    "malicious_hashes": [],
    "suspicious_tlds": ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip"],
    "suspicious_ports": [4444, 5555, 6666, 6667, 7777, 31337],
    "tor_exit_sample": [],
}


class NetworkIOCModule:
    """Indicator-of-Compromise extraction + local threat-intel matching."""

    def __init__(self, feed_path: str = "data/threat_feed.json", max_read_mb: int = 8):
        self.feed_path = feed_path
        self.max_bytes = max_read_mb * 1024 * 1024
        self.feed = self._load_feed()
        logger.info(
            f"Module E initialized ({len(self.feed['malicious_ips'])} bad IPs, "
            f"{len(self.feed['malicious_domains'])} bad domains in feed)"
        )

    def _load_feed(self) -> dict:
        feed = dict(_DEFAULT_FEED)
        try:
            if os.path.exists(self.feed_path):
                with open(self.feed_path) as f:
                    feed.update(json.load(f))
        except Exception as exc:
            logger.warning(f"Threat feed load failed ({exc}); using defaults")
        return feed

    # ── evidence loading ──────────────────────────────────────────────────
    def _load_evidence_text(self, evidence_uri: str) -> tuple[str, str]:
        """
        Load evidence text from a local path (read-only, size-capped).
        Remote URIs are parsed but NEVER fetched (SSRF-safe by design).
        Returns (text, source_kind).
        """
        uri = (evidence_uri or "").strip()
        if not uri:
            return "", "empty"
        path = uri[7:] if uri.startswith("file://") else uri
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    raw = f.read(self.max_bytes + 1)
                text = raw[: self.max_bytes].decode("utf-8", errors="ignore")
                truncated = size > self.max_bytes
                logger.info(
                    f"Module E: read {len(text)} chars from {path}"
                    f"{' (truncated)' if truncated else ''}"
                )
                return text, "local_file_truncated" if truncated else "local_file"
            except Exception as exc:
                logger.warning(f"Module E: cannot read {path}: {exc}")
                return uri, "unreadable_file"
        return uri, "remote_uri_parsed_only"

    # ── extraction ────────────────────────────────────────────────────────
    @staticmethod
    def _valid_ipv4(candidate: str) -> bool:
        try:
            parts = candidate.split(".")
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def extract_iocs(self, text: str) -> dict:
        ips = sorted({ip for ip in IPV4_RE.findall(text) if self._valid_ipv4(ip)})
        domains = sorted({d.lower() for d in DOMAIN_RE.findall(text)})
        # Drop domains that are actually part of emails/URLs duplicates handled by sets anyway
        urls = sorted(set(URL_RE.findall(text)))
        emails = sorted(set(EMAIL_RE.findall(text)))
        hashes = sorted(
            set(MD5_RE.findall(text)) | set(SHA1_RE.findall(text)) | set(SHA256_RE.findall(text))
        )
        ports = sorted({int(p) for p in PORT_RE.findall(text) if 0 < int(p) <= 65535})
        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "emails": emails,
            "hashes": hashes,
            "ports": ports,
        }

    # ── enrichment ────────────────────────────────────────────────────────
    def _ip_reputation(self, ip: str) -> tuple[str, str]:
        """Returns (verdict, reason)."""
        if ip in self.feed.get("malicious_ips", []):
            return "MALICIOUS", "present in local threat-intel feed"
        if ip in self.feed.get("tor_exit_sample", []):
            return "SUSPICIOUS", "known Tor exit node (sample list)"
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                return "BENIGN", "private/reserved address space"
            if addr.is_global:
                return "UNKNOWN", "public IP, not in feed"
        except ValueError:
            return "INVALID", "unparseable"
        return "UNKNOWN", "not in feed"

    def _domain_reputation(self, domain: str) -> tuple[str, str]:
        if domain in self.feed.get("malicious_domains", []):
            return "MALICIOUS", "present in local threat-intel feed"
        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in self.feed.get("suspicious_tlds", []):
            return "SUSPICIOUS", f"high-abuse TLD .{tld}"
        if len(domain) > 60 or sum(c.isdigit() for c in domain) > 12:
            return "SUSPICIOUS", "DGA-like lexical features (long / digit-heavy)"
        return "UNKNOWN", "not in feed"

    # ── main entry ────────────────────────────────────────────────────────
    async def run(self, request: CaseIntakeRequest) -> list[Finding]:
        logger.info(f"Module E: IOC sweep for {request.case_id} ({request.target_type})")
        text, source = self._load_evidence_text(request.evidence_uri)
        iocs = self.extract_iocs(text)
        findings: list[Finding] = []

        # 1. Known-malicious hits → CRITICAL
        for ip in iocs["ips"]:
            verdict, reason = self._ip_reputation(ip)
            if verdict == "MALICIOUS":
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="CRITICAL",
                        title=f"Known-malicious IP: {ip}",
                        description=f"Matched local threat-intel feed ({reason}). Recommend block + hunt.",
                        confidence=0.95,
                        raw_data={"ioc": ip, "type": "ipv4", "verdict": verdict},
                    )
                )
            elif verdict == "SUSPICIOUS":
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="HIGH",
                        title=f"Suspicious IP: {ip}",
                        description=reason,
                        confidence=0.7,
                        raw_data={"ioc": ip, "type": "ipv4", "verdict": verdict},
                    )
                )

        for domain in iocs["domains"]:
            verdict, reason = self._domain_reputation(domain)
            if verdict == "MALICIOUS":
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="CRITICAL",
                        title=f"Known-malicious domain: {domain}",
                        description=f"Matched local threat-intel feed ({reason}).",
                        confidence=0.95,
                        raw_data={"ioc": domain, "type": "domain", "verdict": verdict},
                    )
                )
            elif verdict == "SUSPICIOUS":
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="HIGH",
                        title=f"Suspicious domain: {domain}",
                        description=reason,
                        confidence=0.65,
                        raw_data={"ioc": domain, "type": "domain", "verdict": verdict},
                    )
                )

        feed_hashes = {h.lower() for h in self.feed.get("malicious_hashes", [])}
        for h in iocs["hashes"]:
            if h.lower() in feed_hashes:
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="CRITICAL",
                        title=f"Known-malicious file hash: {h[:16]}…",
                        description="Hash matched local threat-intel feed.",
                        confidence=0.95,
                        raw_data={"ioc": h, "type": "hash", "verdict": "MALICIOUS"},
                    )
                )

        # 2. Suspicious ports → MEDIUM
        bad_ports = set(self.feed.get("suspicious_ports", []))
        for port in iocs["ports"]:
            if port in bad_ports:
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="MEDIUM",
                        title=f"Suspicious port observed: {port}",
                        description="Port commonly associated with RAT/C2 tooling.",
                        confidence=0.5,
                        raw_data={"ioc": port, "type": "port"},
                    )
                )

        # 3. Deep scan extras for network cases
        if request.target_type == "network":
            public_ips = [
                ip for ip in iocs["ips"] if self._ip_reputation(ip)[0] in ("UNKNOWN", "SUSPICIOUS")
            ]
            if public_ips:
                findings.append(
                    Finding(
                        module="MODULE_E",
                        severity="LOW",
                        title=f"External infrastructure observed ({len(public_ips)} IPs)",
                        description="Public IPs seen in evidence; none matched the threat feed. "
                        "Recommend passive-DNS review.",
                        confidence=0.4,
                        raw_data={"iocs": public_ips[:25], "total": len(public_ips)},
                    )
                )

        # 4. Always emit a sweep summary
        total = sum(len(v) for v in iocs.values())
        summary_data = {
            "source": source,
            "counts": {k: len(v) for k, v in iocs.items()},
            "sample": {k: v[:10] for k, v in iocs.items()},
        }
        if not findings:
            findings.append(
                Finding(
                    module="MODULE_E",
                    severity="INFO",
                    title="IOC sweep complete — no threats matched",
                    description=(
                        f"Extracted {total} indicators from {source}; "
                        "none matched the threat-intel feed."
                    ),
                    confidence=0.9,
                    raw_data=summary_data,
                )
            )
        else:
            findings.append(
                Finding(
                    module="MODULE_E",
                    severity="INFO",
                    title=f"IOC sweep summary: {total} indicators, {len(findings)} alerts",
                    description=f"Evidence source: {source}.",
                    confidence=0.9,
                    raw_data=summary_data,
                )
            )
        return findings
