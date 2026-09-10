from src.core.models import Finding


def _finding(severity="HIGH", module="MODULE_E", title="t"):
    return Finding(module=module, severity=severity, title=title, description="d", confidence=0.9)


def test_store_and_verify_chain(vault):
    vault.register_case("C1", "network", "HIGH", created_by="tester")
    vault.store_findings("C1", [_finding("HIGH"), _finding("LOW")])
    result = vault.verify_chain("C1")
    assert result["chain_status"] == "INTACT"
    assert result["court_admissibility"] == "VALID"
    assert result["records"] == 2


def test_tamper_detected_in_chain(vault):
    vault.store_findings("C2", [_finding("CRITICAL")])
    cur = vault.conn.cursor()
    cur.execute(
        "UPDATE findings SET raw_json = replace(raw_json, 'CRITICAL', 'LOW') WHERE case_id = 'C2'"
    )
    vault.conn.commit()
    assert vault.verify_chain("C2")["chain_status"] == "TAMPERED"


def test_case_registry_and_listing(vault):
    vault.register_case("C-A", "android", "LOW", created_by="a1")
    vault.register_case("C-B", "cloud", "CRITICAL", created_by="a2")
    rows, total = vault.list_cases()
    assert total == 2
    rows, total = vault.list_cases(priority="CRITICAL")
    assert total == 1 and rows[0]["case_id"] == "C-B"
    assert vault.get_case_meta("C-A")["target_type"] == "android"


def test_search_and_pagination(vault):
    vault.store_findings(
        "C3",
        [
            _finding("HIGH", title="ssh exposure"),
            _finding("LOW", title="banner note"),
            _finding("HIGH", title="ssh key leak"),
        ],
    )
    items, total = vault.search_findings("C3", severity="HIGH")
    assert total == 2
    items, total = vault.search_findings("C3", query="ssh", limit=1, offset=1)
    assert total == 2 and len(items) == 1
    stats = vault.get_case_stats("C3")
    assert stats["total"] == 3 and stats["severity_breakdown"]["HIGH"] == 2


def test_delete_case(vault):
    vault.register_case("C4", "media")
    vault.store_findings("C4", [_finding()])
    assert vault.delete_case("C4") == 1
    assert vault.get_case_meta("C4") is None


def test_export_bundle(vault):
    vault.register_case("C5", "network", created_by="op")
    vault.store_findings("C5", [_finding()])
    bundle = vault.export_case_bundle("C5")
    assert bundle["verification"]["chain_status"] == "INTACT"
    assert len(bundle["records"]) == 1
    assert bundle["case"]["case_id"] == "C5"
    assert vault.export_case_bundle("NOPE") is None
