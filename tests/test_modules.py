import asyncio
import json

from tests.conftest import make_case


def _run(coro):
    return (
        asyncio.get_event_loop().run_until_complete(coro)
        if False
        else asyncio.new_event_loop().run_until_complete(coro)
    )


def test_module_e_extracts_iocs(tmp_path):
    from src.modules.module_e import NetworkIOCModule

    mod = NetworkIOCModule(feed_path=str(tmp_path / "missing.json"))
    iocs = mod.extract_iocs(
        "contact evil@malware.example, see http://malware.example:4444/x "
        "44d88612fea8a8f36de82e1278abb02f from 203.0.113.45"
    )
    assert "203.0.113.45" in iocs["ips"]
    assert "malware.example" in iocs["domains"]
    assert iocs["hashes"] and iocs["ports"] == [4444]
    assert "evil@malware.example" in iocs["emails"]


def test_module_e_flags_malicious_feed_hits(tmp_path):
    from src.modules.module_e import NetworkIOCModule

    feed = {
        "malicious_ips": ["203.0.113.45"],
        "malicious_domains": ["c2-server.example"],
        "malicious_hashes": [],
        "suspicious_tlds": ["tk"],
        "suspicious_ports": [4444],
        "tor_exit_sample": [],
    }
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(json.dumps(feed))
    mod = NetworkIOCModule(feed_path=str(feed_path))
    req = make_case(evidence_uri="beacon to 203.0.113.45 and c2-server.example over :4444")
    findings = _run(mod.run(req))
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities  # feed hits
    assert "MEDIUM" in severities  # suspicious port


def test_module_e_reads_local_file(tmp_path):
    from src.modules.module_e import NetworkIOCModule

    ev = tmp_path / "evidence.log"
    ev.write_text("connection from 198.51.100.23 failed login")
    mod = NetworkIOCModule(feed_path=str(tmp_path / "missing.json"))
    findings = _run(mod.run(make_case(evidence_uri=str(ev))))
    assert any(
        "198.51.100.23" in f.description or "198.51.100.23" in json.dumps(f.raw_data)
        for f in findings
    )


def test_module_e_remote_uri_never_fetched():
    from src.modules.module_e import NetworkIOCModule

    mod = NetworkIOCModule(feed_path="missing.json")
    text, source = mod._load_evidence_text("https://10.0.0.1:8443/c2")
    assert source == "remote_uri_parsed_only" and "10.0.0.1" in text


def test_module_a_hashes_local_files(tmp_path):
    from src.modules.module_a import AndroidTriageModule, sha256_of_file

    target = tmp_path / "case_files"
    target.mkdir()
    (target / "note.txt").write_text("hello forensics")
    (target / "run.pdf.exe").write_text("MZ fake")
    findings = _run(
        AndroidTriageModule().run(make_case(target_type="android", evidence_uri=str(target)))
    )
    titles = [f.title for f in findings]
    assert any("Double-extension" in t for t in titles)
    assert any("files hashed" in t for t in titles)
    assert sha256_of_file(str(target / "note.txt"))


def test_module_a_hidden_marker(tmp_path):
    from src.modules.module_a import AndroidTriageModule

    target = tmp_path / "triage"
    target.mkdir()
    (target / ".shadow_cache").write_text("x")
    findings = _run(
        AndroidTriageModule().run(make_case(target_type="android", evidence_uri=str(target)))
    )
    assert any("hidden artifact" in f.title.lower() for f in findings)


def test_module_d_fts5_fallback(isolated_workdir):
    from src.modules.module_d import LegalNLPModule

    mod = LegalNLPModule(db_path=str(isolated_workdir / "legal.db"))
    # Force fallback path regardless of BERT availability
    mod.bert = None
    mod.mode = "FALLBACK_FTS5"
    findings = _run(mod.run(make_case(target_type="cloud")))
    assert len(findings) >= 1
    assert all(f.module == "MODULE_D" for f in findings)


def test_module_c_simulation_without_role():
    from src.modules.module_c import CloudAuditModule

    mod = CloudAuditModule()
    mod.role_arn = None
    findings = _run(mod.run(make_case(target_type="cloud")))
    assert len(findings) == 1 and findings[0].module == "MODULE_C"
