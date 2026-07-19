"""Smoke + ops tests for compliance-aiops.

Unlike the platform tools, this one has NO external dependency — its data source
is local SQLite audit DBs whose schema we own — so these tests exercise the REAL
production code path end-to-end, deterministically and offline. Highlights: a
synthetic audit DB built via the REAL ``AuditEngine`` (so the reader can't drift
from the harness schema), a golden reproducible ``chainHead``, and tamper tests
that assert ``verify_bundle`` catches a modified evidence row.
"""

import importlib
import json
import re
import sqlite3

import pytest
from typer.testing import CliRunner

EXPECTED_TOOLS = {
    "list_audit_sources", "query_audit_events", "activity_timeline",
    "list_frameworks", "coverage_summary", "control_evidence", "gap_analysis",
    "approval_report", "exceptions_report",
    "verify_source_chain", "verify_bundle",
    "generate_evidence_bundle", "sign_bundle", "export_bundle", "list_bundles",
    "bundle_schedule_hint",
}


# ── synthetic audit DB (real schema via the harness AuditEngine) ─────────

_ROWS = [
    # (ts, skill, tool, status, risk_level, approved_by)
    ("2026-07-01T09:00:00+00:00", "nutanix-aiops", "vm_list", "ok", "low", ""),
    ("2026-07-01T09:05:00+00:00", "nutanix-aiops", "vm_power_on", "ok", "low", ""),
    ("2026-07-01T10:00:00+00:00", "nutanix-aiops", "vm_delete", "ok", "high", "alice"),
    ("2026-07-01T11:00:00+00:00", "ceph-aiops", "osd_purge", "ok", "high", ""),  # unapproved!
    ("2026-07-01T12:00:00+00:00", "ceph-aiops", "pool_delete", "denied", "high", ""),
    ("2026-07-01T13:00:00+00:00", "k8s-aiops", "scale", "error", "medium", ""),
    ("2026-07-01T14:00:00+00:00", "k8s-aiops", "list_pods", "budget_exceeded", "low", ""),
]


def _make_audit_db(path, rows=_ROWS):
    """Create a real-schema audit.db (via AuditEngine) then insert controlled rows."""
    from compliance_aiops.governance.audit import AuditEngine

    AuditEngine(str(path))  # runs the real _CREATE_TABLE schema
    conn = sqlite3.connect(str(path))
    for ts, skill, tool, status, risk, approver in rows:
        conn.execute(
            "INSERT INTO audit_log (ts,skill,tool,params,result,status,duration_ms,"
            "agent,workflow_id,user,risk_level,rationale,approved_by,risk_tier) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, skill, tool, "{}", "{}", status, 10, "claude", "", "alice",
             risk, "why", approver, "dual" if approver else ""),
        )
    conn.commit()
    conn.close()
    return path


def _reader(path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    return AuditReader([AuditSource(name="testsrc", path=path)])


@pytest.fixture()
def audit_db(tmp_path):
    return _make_audit_db(tmp_path / "audit.db")


# ── smoke ────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_all_modules_import():
    for name in (
        "compliance_aiops", "compliance_aiops.config", "compliance_aiops.connection",
        "compliance_aiops.doctor", "compliance_aiops.secretstore",
        "compliance_aiops.frameworks", "compliance_aiops.hashchain",
        "compliance_aiops.ops.events", "compliance_aiops.ops.controls",
        "compliance_aiops.ops.reports", "compliance_aiops.ops.integrity",
        "compliance_aiops.ops.bundle", "compliance_aiops.ops.overview",
        "compliance_aiops.cli", "compliance_aiops.cli._root", "compliance_aiops.cli.init",
        "compliance_aiops.cli.report", "compliance_aiops.cli.bundle",
        "mcp_server.server", "mcp_server._shared",
        "mcp_server.tools.events", "mcp_server.tools.controls", "mcp_server.tools.reports",
        "mcp_server.tools.integrity", "mcp_server.tools.bundle",
    ):
        importlib.import_module(name)


@pytest.mark.unit
def test_version_matches_pyproject():
    """__version__ is single-sourced from package metadata; it must track
    pyproject.toml so a release bump can never ship a stale self-report."""
    import tomllib
    from pathlib import Path

    import compliance_aiops

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(pyproject.read_text("utf-8"))["project"]["version"]
    assert compliance_aiops.__version__ == expected


@pytest.mark.unit
def test_cli_app_builds_and_help_works():
    from compliance_aiops.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for sub in ("report", "bundle", "secret", "init", "overview", "doctor", "mcp"):
        assert sub in result.output


@pytest.mark.unit
def test_cli_leaf_help():
    from compliance_aiops.cli import app

    runner = CliRunner()
    for cmd in (
        ["report", "--help"], ["bundle", "--help"], ["secret", "--help"],
        ["doctor", "--help"], ["overview", "--help"], ["init", "--help"],
        ["report", "coverage", "--help"], ["report", "gaps", "--help"],
        ["bundle", "generate", "--help"], ["bundle", "verify", "--help"],
        ["bundle", "schedule", "--help"],
    ):
        result = runner.invoke(app, cmd)
        assert result.exit_code == 0, f"{cmd} failed: {result.output}"


@pytest.mark.unit
def test_mcp_exposes_and_governs_all_tools():
    from mcp_server import _shared
    from mcp_server.server import mcp  # noqa: F401 — registers tools

    tools = _shared.mcp._tool_manager._tools
    assert EXPECTED_TOOLS <= set(tools), f"missing: {EXPECTED_TOOLS - set(tools)}"
    for name, tool in tools.items():
        fn = getattr(tool, "fn", None)
        assert getattr(fn, "_is_governed_tool", False), f"{name} not governed"


@pytest.mark.unit
def test_risk_tiers():
    from mcp_server.tools import bundle as b

    assert b.generate_evidence_bundle._risk_level == "medium"  # writes a file to disk
    assert b.sign_bundle._risk_level == "medium"  # touches the secret store


# ── reader (real schema) ─────────────────────────────────────────────────


@pytest.mark.unit
def test_reader_reads_and_filters(audit_db):
    reader = _reader(audit_db)
    assert len(reader.query()) == len(_ROWS)
    assert len(reader.query(status="denied")) == 1
    assert len(reader.query(risk_level="high")) == 3
    approved = reader.query(approved=True)
    assert len(approved) == 1 and approved[0]["tool"] == "vm_delete"
    assert reader.query(approved=False)  # the rest


@pytest.mark.unit
def test_reader_readonly_never_writes(tmp_path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    missing = tmp_path / "nope.db"
    AuditReader([AuditSource(name="x", path=missing)]).query()
    assert not missing.exists()  # a missing source is skipped, never created


# ── controls / gap analysis ──────────────────────────────────────────────


@pytest.mark.unit
def test_coverage_and_gap_flag_unapproved_high_risk(audit_db):
    from compliance_aiops.ops import controls as ops

    reader = _reader(audit_db)
    cov = ops.coverage_summary(reader, "soc2")
    cc8 = next(c for c in cov["controls"] if c["controlId"] == "CC8.1")
    assert cc8["gap"] and "without an approver" in cc8["gap"]  # osd_purge unapproved

    gaps = ops.gap_analysis(reader, "soc2")
    assert any("without an approver" in g["reason"] for g in gaps["findings"])
    assert gaps["note"]  # honest design-vs-operating caveat present


@pytest.mark.unit
def test_control_evidence_and_frameworks(audit_db):
    from compliance_aiops.ops import controls as ops

    reader = _reader(audit_db)
    ev = ops.control_evidence(reader, "pci_dss", "10.2")
    assert ev["populationSize"] == len(_ROWS)  # audit_trail selector = all events
    assert {f["framework"] for f in ops.list_frameworks()} == {
        "hipaa", "pci_dss", "soc2", "gdpr", "iso27001", "djcp_l3"
    }


# ── hash chain ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_hashchain_deterministic_and_tamper_evident():
    from compliance_aiops import hashchain

    recs = [{"a": 1, "tool": "x"}, {"a": 2, "tool": "y"}]
    c1 = hashchain.chain(recs)
    c2 = hashchain.chain(recs)
    assert c1["head"] == c2["head"]  # deterministic
    assert hashchain.verify_chain(c1["records"])["valid"]
    tampered = [dict(r) for r in c1["records"]]
    tampered[0] = {**tampered[0], "tool": "HACKED"}
    v = hashchain.verify_chain(tampered)
    assert v["valid"] is False and v["brokenAtSeq"] == 0


# ── bundle: golden chainHead + tamper detection ──────────────────────────


@pytest.mark.unit
def test_generate_bundle_reproducible_and_verifies(audit_db, tmp_path):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops
    from compliance_aiops.ops import integrity

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)

    b1 = ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(tmp_path / "b1.json"))
    b2 = ops.generate_evidence_bundle(reader, cfg, "soc2", out_path=str(tmp_path / "b2.json"))
    assert b1["chainHead"] == b2["chainHead"]  # golden: reproducible for same inputs
    assert b1["recordCount"] == len(_ROWS)

    verdict = integrity.verify_bundle(str(tmp_path / "b1.json"))
    assert verdict["verdict"] == "intact" and verdict["headMatches"] is True


@pytest.mark.unit
def test_verify_bundle_detects_tampering(audit_db, tmp_path):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops
    from compliance_aiops.ops import integrity

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)
    path = tmp_path / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "hipaa", out_path=str(path))

    bundle = json.loads(path.read_text())
    bundle["records"][1]["tool"] = "SILENTLY_CHANGED"  # tamper a payload, not its hash
    path.write_text(json.dumps(bundle))

    verdict = integrity.verify_bundle(str(path))
    assert verdict["verdict"] == "TAMPERED_OR_MODIFIED"
    assert verdict["chainValid"] is False


@pytest.mark.unit
def test_export_bundle_markdown(audit_db, tmp_path):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)
    path = tmp_path / "b.json"
    ops.generate_evidence_bundle(reader, cfg, "gdpr", out_path=str(path))
    out = ops.export_bundle(str(path), fmt="markdown")
    text = (tmp_path / "b.md").read_text()
    assert out["format"] == "markdown" and "Compliance evidence bundle" in text


# ── integrity: id-gap detection ──────────────────────────────────────────


@pytest.mark.unit
def test_verify_source_chain_detects_id_gap(tmp_path):
    from compliance_aiops.governance.audit import AuditEngine
    from compliance_aiops.ops import integrity

    path = tmp_path / "audit.db"
    AuditEngine(str(path))
    conn = sqlite3.connect(str(path))
    for rid in (1, 2, 5):  # a deleted 3,4 → gap
        conn.execute(
            "INSERT INTO audit_log (id,ts,skill,tool,params,result,status) "
            "VALUES (?,?,?,?,?,?,?)",
            (rid, f"2026-07-01T0{rid}:00:00+00:00", "s", "t", "{}", "{}", "ok"),
        )
    conn.commit()
    conn.close()

    out = integrity.verify_source_chain(_reader(path), "testsrc")
    assert out["idContiguous"] is False
    assert out["gaps"] and out["gaps"][0]["missing"] == 2


# ── new frameworks: ISO 27001 + 等保2.0 (djcp_l3) ─────────────────────────

_NEW_FRAMEWORKS = ("iso27001", "djcp_l3")


@pytest.mark.unit
def test_new_frameworks_listed_with_controls():
    from compliance_aiops.ops import controls as ops

    listed = {f["framework"]: f for f in ops.list_frameworks()}
    for name in _NEW_FRAMEWORKS:
        assert name in listed, f"{name} missing from list_frameworks"
        assert listed[name]["controls"] > 0
        assert listed[name]["title"]  # display title present
    assert listed["djcp_l3"]["title"] == "等保2.0 (DJCP L3)"
    assert "27001" in listed["iso27001"]["title"]


@pytest.mark.unit
@pytest.mark.parametrize("framework", _NEW_FRAMEWORKS)
def test_new_framework_controls_resolve_to_selectors(framework):
    """Every control on a new framework must name a known selector."""
    from compliance_aiops import frameworks as fw

    controls = fw.controls_for(framework)
    assert controls
    for c in controls:
        assert c.selector in fw.SELECTORS, f"{c.control_id} → unknown selector {c.selector}"
        assert c.control_id and c.title and c.requirement
        # control ids stay ASCII even when titles are localized
        assert c.control_id.isascii(), f"non-ASCII control id: {c.control_id!r}"


@pytest.mark.unit
@pytest.mark.parametrize("framework", _NEW_FRAMEWORKS)
def test_new_framework_produces_bundle(framework, audit_db, tmp_path):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops
    from compliance_aiops.ops import integrity

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)
    path = tmp_path / f"{framework}.json"
    res = ops.generate_evidence_bundle(reader, cfg, framework, out_path=str(path))
    assert res["recordCount"] == len(_ROWS)
    assert res["controlsTotal"] > 0

    bundle = json.loads(path.read_text())
    if framework == "djcp_l3":  # seal renders the localized framework name
        assert bundle["seal"]["frameworkTitle"] == "等保2.0 (DJCP L3)"
    verdict = integrity.verify_bundle(str(path))
    assert verdict["verdict"] == "intact"


@pytest.mark.unit
def test_iso27001_flags_unapproved_privileged_change(audit_db):
    """The change-selector ISO controls must flag the unapproved high-risk write
    (osd_purge) exactly as SOC2 CC8.1 does — same gap model, new mapping."""
    from compliance_aiops.ops import controls as ops

    reader = _reader(audit_db)
    cov = ops.coverage_summary(reader, "iso27001")
    a832 = next(c for c in cov["controls"] if c["controlId"] == "A.8.32")
    assert a832["gap"] and "without an approver" in a832["gap"]

    gaps = ops.gap_analysis(reader, "iso27001")
    assert any("without an approver" in g["reason"] for g in gaps["findings"])
    # localized 等保 framework also resolves + reports coverage
    djcp = ops.coverage_summary(reader, "djcp_l3")
    assert djcp["frameworkTitle"] == "等保2.0 (DJCP L3)"
    assert djcp["controlsTotal"] == 3


@pytest.mark.unit
def test_chainhead_identical_across_all_frameworks(audit_db, tmp_path):
    """The chain is over the ordered records only, so chainHead is framework-
    independent for the same audit rows — determinism unchanged by new mappings."""
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)
    heads = {
        f: ops.generate_evidence_bundle(reader, cfg, f, out_path=str(tmp_path / f"{f}.json"))[
            "chainHead"
        ]
        for f in ("hipaa", "soc2", "iso27001", "djcp_l3")
    }
    assert len(set(heads.values())) == 1, f"chainHead diverged across frameworks: {heads}"


# ── scheduling hint (writes nothing) ──────────────────────────────────────

_CRON_5_FIELD = re.compile(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$")


@pytest.mark.unit
def test_schedule_hint_returns_valid_cron_and_command():
    from compliance_aiops.ops import bundle as ops

    hint = ops.bundle_schedule_hint("iso27001", cron="30 3 * * 0", period="7d", sign=True)
    assert hint["writesNothing"] is True
    assert _CRON_5_FIELD.match(hint["cron"])
    assert len(hint["cron"].split()) == 5
    assert hint["command"] == "compliance-aiops bundle generate iso27001 --period 7d --sign"
    assert hint["cron"] in hint["cronLine"] and hint["command"] in hint["cronLine"]
    assert hint["masterPasswordEnv"] == "COMPLIANCE_AIOPS_MASTER_PASSWORD"


@pytest.mark.unit
def test_schedule_hint_rejects_bad_cron_and_framework():
    from compliance_aiops.ops import bundle as ops

    with pytest.raises(ValueError, match="5-field"):
        ops.bundle_schedule_hint("soc2", cron="0 2 * *")  # 4 fields
    with pytest.raises(ValueError):
        ops.bundle_schedule_hint("not_a_framework")


@pytest.mark.unit
def test_resolve_period_windows_and_generate_period(audit_db, tmp_path):
    from compliance_aiops.config import AppConfig, AuditSource
    from compliance_aiops.ops import bundle as ops

    since, until = ops.resolve_period("7d")
    assert since and until and since < until
    assert ops.resolve_period(None) == (None, None)
    with pytest.raises(ValueError):
        ops.resolve_period("banana")

    reader = _reader(audit_db)
    cfg = AppConfig(sources=(AuditSource(name="testsrc", path=audit_db),),
                    organization="Acme", bundle_dir=tmp_path)
    # a wide window still seals successfully (records here predate "now")
    res = ops.generate_evidence_bundle(
        reader, cfg, "soc2", out_path=str(tmp_path / "p.json"), period="520w")
    assert res["recordCount"] == len(_ROWS)
