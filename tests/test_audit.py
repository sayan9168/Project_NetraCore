from src.core.audit import ImmutableAuditLogger


def test_record_and_verify(tmp_path):
    log = ImmutableAuditLogger(log_dir=str(tmp_path / "audit"))
    log.record("agent", "CASE_STARTED", "C1", {})
    log.record("agent", "CASE_COMPLETED", "C1", {"n": 1})
    result = log.verify_chain()
    assert result["chain_status"] == "INTACT"
    assert result["entries"] == 2


def test_tamper_detected(tmp_path):
    log = ImmutableAuditLogger(log_dir=str(tmp_path / "audit"))
    log.record("agent", "A", "C1", {})
    log.record("agent", "B", "C1", {})
    with open(log.log_file, "r+") as f:
        lines = f.readlines()
        lines[0] = lines[0].replace("CASE_STARTED", "HACKED").replace('"A"', '"HACKED"')
        f.seek(0)
        f.writelines(lines)
        f.truncate()
    result = log.verify_chain()
    assert result["chain_status"] == "TAMPERED"
    assert result["failed_at"] == 1


def test_chain_resumes_after_restart(tmp_path):
    d = str(tmp_path / "audit")
    ImmutableAuditLogger(log_dir=d).record("a", "A", "C1", {})
    log2 = ImmutableAuditLogger(log_dir=d)  # new process, same day
    log2.record("a", "B", "C1", {})
    assert log2.verify_chain()["chain_status"] == "INTACT"


def test_read_entries_limit(tmp_path):
    log = ImmutableAuditLogger(log_dir=str(tmp_path / "audit"))
    for i in range(5):
        log.record("a", f"A{i}", "C1", {})
    assert len(log.read_entries(limit=2)) == 2
