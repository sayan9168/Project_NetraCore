import os

from src.core.crypto_seal import ForensicSeal


def test_seal_and_verify_roundtrip(tmp_path):
    seal = ForensicSeal(key_path=str(tmp_path / ".key"))
    data = {"finding_id": "1", "severity": "HIGH"}
    curr, sig = seal.seal(data, "GENESIS")
    assert seal.verify(data, "GENESIS", curr, sig) is True


def test_tamper_detected(tmp_path):
    seal = ForensicSeal(key_path=str(tmp_path / ".key"))
    data = {"finding_id": "1", "severity": "HIGH"}
    curr, sig = seal.seal(data, "GENESIS")
    tampered = dict(data, severity="LOW")
    assert seal.verify(tampered, "GENESIS", curr, sig) is False


def test_chain_linking_breaks_on_reorder(tmp_path):
    seal = ForensicSeal(key_path=str(tmp_path / ".key"))
    h1, s1 = seal.seal({"n": 1}, "GENESIS")
    h2, s2 = seal.seal({"n": 2}, h1)
    # Wrong prev_hash must fail even with correct payload
    assert seal.verify({"n": 2}, "GENESIS", h2, s2) is False
    assert seal.verify({"n": 2}, h1, h2, s2) is True


def test_key_file_permissions(tmp_path):
    key = str(tmp_path / ".key")
    ForensicSeal(key_path=key)
    assert os.path.exists(key)
    if os.name == "posix":
        assert oct(os.stat(key).st_mode & 0o777) == "0o600"
