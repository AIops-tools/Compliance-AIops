"""Bundle signing, export (csv/json), listing, and the signing-key lookup.

Covers the write-path branches of ops/bundle not hit by the smoke suite:
HMAC signing through the encrypted store, CSV/JSON export, and directory
listing (including a corrupt-file skip). The secret store is redirected under
tmp_path so signing never touches the real ~/.compliance-aiops.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

import compliance_aiops.secretstore as ss

pytestmark = pytest.mark.unit

_ROWS = [
    ("2026-07-01T09:00:00+00:00", "nutanix-aiops", "vm_list", "ok", "low", ""),
    ("2026-07-01T10:00:00+00:00", "ceph-aiops", "osd_purge", "ok", "high", ""),
]


def _make_audit_db(path):
    from compliance_aiops.governance.audit import AuditEngine

    AuditEngine(str(path))
    conn = sqlite3.connect(str(path))
    for ts, skill, tool, status, risk, approver in _ROWS:
        conn.execute(
            "INSERT INTO audit_log (ts,skill,tool,params,result,status,duration_ms,"
            "agent,workflow_id,user,risk_level,rationale,approved_by,risk_tier) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, skill, tool, "{}", "{}", status, 10, "claude", "", "alice",
             risk, "why", approver, ""),
        )
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.connection import AuditReader

    # Redirect the secret store into tmp so signing is fully isolated.
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "pw")

    db = _make_audit_db(tmp_path / "audit.db")
    source = AuditSource(name="testsrc", path=db)
    reader = AuditReader([source])
    cfg = AppConfig(sources=(source,), organization="Acme", bundle_dir=tmp_path / "bundles")
    return reader, cfg, tmp_path


def _store_signing_key(key="sign-key-material"):
    ss.SecretStore.unlock("pw").set("signing-key", key)


# ── signing ───────────────────────────────────────────────────────────────


def test_generate_with_sign_embeds_hmac_signature(env):
    from compliance_aiops import hashchain
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    _store_signing_key()
    res = ops.generate_evidence_bundle(
        reader, cfg, "soc2", out_path=str(tmp_path / "bundles" / "b.json"), sign=True)
    assert res["signed"] is True

    bundle = json.loads((tmp_path / "bundles" / "b.json").read_text())
    sig = bundle["seal"]["signature"]
    assert sig["alg"] == "HMAC-SHA256"
    assert hashchain.verify_signature(res["chainHead"], sig["value"], "sign-key-material")


def test_sign_bundle_attaches_signature_to_existing_bundle(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    path = tmp_path / "bundles" / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "hipaa", out_path=str(path))
    assert json.loads(path.read_text())["seal"]["signature"] is None

    _store_signing_key()
    out = ops.sign_bundle(cfg, str(path))
    assert out["signed"] is True
    assert json.loads(path.read_text())["seal"]["signature"]["alg"] == "HMAC-SHA256"


def test_sign_bundle_without_key_raises(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    path = tmp_path / "bundles" / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "hipaa", out_path=str(path))
    with pytest.raises(ValueError, match="No signing key configured"):
        ops.sign_bundle(cfg, str(path))


def test_generate_with_sign_but_no_key_stays_unsigned(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env  # no key stored
    res = ops.generate_evidence_bundle(
        reader, cfg, "soc2", out_path=str(tmp_path / "bundles" / "b.json"), sign=True)
    assert res["signed"] is False


# ── export csv / json / unknown ───────────────────────────────────────────


def test_export_csv_and_json(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    path = tmp_path / "bundles" / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(path))

    csv_out = ops.export_bundle(str(path), fmt="csv")
    assert csv_out["format"] == "csv"
    csv_text = (tmp_path / "bundles" / "b.csv").read_text()
    assert csv_text.splitlines()[0] == "controlId,title,strength,evidenceCount,covered,gap"

    json_out = ops.export_bundle(str(path), fmt="json")
    assert json_out["format"] == "json"
    reparsed = json.loads((tmp_path / "bundles" / "b.json").with_suffix(".json").read_text())
    assert "seal" in reparsed


def test_export_unknown_format_raises(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    path = tmp_path / "bundles" / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(path))
    with pytest.raises(ValueError, match="Unknown format"):
        ops.export_bundle(str(path), fmt="pdf")


# ── list_bundles ──────────────────────────────────────────────────────────


def test_list_bundles_empty_when_dir_absent(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, _ = env
    assert ops.list_bundles(cfg) == []  # bundle_dir not created yet


def test_list_bundles_lists_seals_and_skips_corrupt(env):
    from compliance_aiops.ops import bundle as ops

    reader, cfg, tmp_path = env
    ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(tmp_path / "bundles" / "a.json"))
    ops.generate_evidence_bundle(reader, cfg, "gdpr", out_path=str(tmp_path / "bundles" / "b.json"))
    (tmp_path / "bundles" / "broken.json").write_text("{ not json", "utf-8")

    listed = ops.list_bundles(cfg)
    frameworks = {b["framework"] for b in listed}
    assert frameworks == {"soc2", "gdpr"}  # corrupt file skipped
    assert all(b["recordCount"] == len(_ROWS) for b in listed)
    assert all(b["chainHead"] for b in listed)
