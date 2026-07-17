"""CLI command bodies driven end-to-end through Typer's CliRunner.

Every sub-command's real body runs against an isolated config.yaml + synthetic
real-schema audit.db under tmp_path (this tool is offline/deterministic). Also
covers the shared helpers (cli_errors teaching-error translation, get_reader,
double_confirm) and the ``mcp`` launcher.
"""

from __future__ import annotations

import json
import sqlite3

import pytest
import typer
from typer.testing import CliRunner

import compliance_aiops.config as config_mod
import compliance_aiops.secretstore as ss

pytestmark = pytest.mark.unit

runner = CliRunner()

_ROWS = [
    ("2026-07-01T09:00:00+00:00", "nutanix-aiops", "vm_list", "ok", "low", ""),
    ("2026-07-01T10:00:00+00:00", "ceph-aiops", "osd_purge", "ok", "high", ""),  # unapproved
    ("2026-07-01T12:00:00+00:00", "ceph-aiops", "pool_delete", "denied", "high", ""),
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
def cli_home(tmp_path, monkeypatch):
    """Isolate config.yaml + the audit source + bundle dir under tmp_path."""
    db = _make_audit_db(tmp_path / "audit.db")
    bundle_dir = tmp_path / "bundles"
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "organization: Acme Corp\n"
        f"bundle_dir: {bundle_dir}\n"
        "sources:\n"
        f"  - name: testsrc\n    path: {db}\n    environment: prod\n",
        "utf-8",
    )
    # get_reader() -> load_config(None) reads config.CONFIG_FILE at call time.
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "BUNDLE_DIR", bundle_dir)
    return tmp_path, db, bundle_dir


def _app():
    from compliance_aiops.cli import app

    return app


# ── report ────────────────────────────────────────────────────────────────


def test_report_sources(cli_home):
    res = runner.invoke(_app(), ["report", "sources"])
    assert res.exit_code == 0, res.output
    assert "testsrc" in res.output


def test_report_coverage_and_gaps(cli_home):
    cov = runner.invoke(_app(), ["report", "coverage", "soc2"])
    assert cov.exit_code == 0, cov.output
    assert "controlsTotal" in cov.output

    gaps = runner.invoke(_app(), ["report", "gaps", "soc2"])
    assert gaps.exit_code == 0, gaps.output
    assert "findings" in gaps.output


def test_report_approvals_and_exceptions(cli_home):
    appr = runner.invoke(_app(), ["report", "approvals"])
    assert appr.exit_code == 0, appr.output

    exc = runner.invoke(_app(), ["report", "exceptions"])
    assert exc.exit_code == 0, exc.output
    assert "pool_delete" in exc.output  # the denied op is in the exceptions trail


def test_report_coverage_unknown_framework_teaches_and_exits_1(cli_home):
    res = runner.invoke(_app(), ["report", "coverage", "not_a_framework"])
    assert res.exit_code == 1
    assert "Error:" in res.output  # cli_errors translated the ValueError


# ── bundle ────────────────────────────────────────────────────────────────


def test_bundle_generate_list_verify_export_roundtrip(cli_home):
    _, _, bundle_dir = cli_home

    gen = runner.invoke(_app(), ["bundle", "generate", "soc2"])
    assert gen.exit_code == 0, gen.output
    payload = json.loads(gen.output)
    path = payload["bundlePath"]
    assert payload["recordCount"] == len(_ROWS)

    lst = runner.invoke(_app(), ["bundle", "list"])
    assert lst.exit_code == 0, lst.output
    assert "soc2" in lst.output

    ver = runner.invoke(_app(), ["bundle", "verify", path])
    assert ver.exit_code == 0, ver.output
    assert "intact" in ver.output

    exp = runner.invoke(_app(), ["bundle", "export", path, "--format", "markdown"])
    assert exp.exit_code == 0, exp.output
    assert "markdown" in exp.output


def test_bundle_generate_with_period(cli_home):
    res = runner.invoke(_app(), ["bundle", "generate", "hipaa", "--period", "520w"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["recordCount"] == len(_ROWS)


def test_bundle_schedule_prints_cron_line(cli_home):
    res = runner.invoke(_app(), ["bundle", "schedule", "iso27001", "--period", "7d"])
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert out["writesNothing"] is True
    assert out["command"].startswith("compliance-aiops bundle generate iso27001")


def test_bundle_schedule_bad_cron_exits_1(cli_home):
    res = runner.invoke(_app(), ["bundle", "schedule", "soc2", "--cron", "0 2 * *"])
    assert res.exit_code == 1
    assert "Error:" in res.output


# ── overview ──────────────────────────────────────────────────────────────


def test_overview_command(cli_home):
    res = runner.invoke(_app(), ["overview"])
    assert res.exit_code == 0, res.output
    assert "frameworks" in res.output
    assert "readableSources" in res.output


# ── undo (list only — empty store) ────────────────────────────────────────


def test_undo_list_empty(cli_home, tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLIANCE_AIOPS_HOME", str(tmp_path / "gov"))
    import compliance_aiops.governance.undo as undo_mod

    undo_mod.reset_undo_store()
    res = runner.invoke(_app(), ["undo", "list"])
    assert res.exit_code == 0, res.output
    assert '"count": 0' in res.output
    undo_mod.reset_undo_store()


# ── secret ────────────────────────────────────────────────────────────────


@pytest.fixture
def secret_home(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "master-pw")
    return tmp_path


def test_secret_set_list_rm_cycle(secret_home):
    setr = runner.invoke(_app(), ["secret", "set", "signing-key", "--value", "abc123"])
    assert setr.exit_code == 0, setr.output
    assert "Stored encrypted" in setr.output

    lst = runner.invoke(_app(), ["secret", "list"])
    assert lst.exit_code == 0, lst.output
    assert "signing-key" in lst.output

    rm = runner.invoke(_app(), ["secret", "rm", "signing-key"])
    assert rm.exit_code == 0, rm.output
    assert "Deleted" in rm.output


def test_secret_list_empty_hint(secret_home):
    res = runner.invoke(_app(), ["secret", "list"])
    assert res.exit_code == 0, res.output
    assert "No secrets stored yet" in res.output


def test_secret_migrate_noop(secret_home):
    res = runner.invoke(_app(), ["secret", "migrate"])
    assert res.exit_code == 0, res.output
    assert "Nothing to migrate" in res.output


def test_secret_migrate_imports_legacy_env(secret_home):
    (secret_home / ".env").write_text("COMPLIANCE_NAS1_SECRET=legacy-val\n", "utf-8")
    res = runner.invoke(_app(), ["secret", "migrate"])
    assert res.exit_code == 0, res.output
    assert "Imported 1 secret" in res.output


def test_secret_rotate_password_mismatch_aborts(secret_home, monkeypatch):
    runner.invoke(_app(), ["secret", "set", "k", "--value", "v"])
    answers = iter(["new-pw", "different-pw"])
    monkeypatch.setattr(
        "compliance_aiops.cli.secret.getpass.getpass", lambda prompt="": next(answers)
    )
    res = runner.invoke(_app(), ["secret", "rotate-password"])
    assert res.exit_code == 1
    assert "did not match" in res.output


def test_secret_rotate_password_success(secret_home, monkeypatch):
    runner.invoke(_app(), ["secret", "set", "k", "--value", "v"])
    answers = iter(["new-pw", "new-pw"])
    monkeypatch.setattr(
        "compliance_aiops.cli.secret.getpass.getpass", lambda prompt="": next(answers)
    )
    res = runner.invoke(_app(), ["secret", "rotate-password"])
    assert res.exit_code == 0, res.output
    assert "rotated" in res.output


def test_secret_set_prompts_when_value_omitted(secret_home, monkeypatch):
    monkeypatch.setattr(
        "compliance_aiops.cli.secret.getpass.getpass", lambda prompt="": "prompted-key"
    )
    res = runner.invoke(_app(), ["secret", "set", "signing-key"])
    assert res.exit_code == 0, res.output
    assert ss.SecretStore.unlock("master-pw").get("signing-key") == "prompted-key"


# ── shared helpers ────────────────────────────────────────────────────────


def test_cli_errors_translates_keyerror():
    from compliance_aiops.cli._common import cli_errors

    @cli_errors
    def boom():
        raise KeyError("MY_ENV")

    with pytest.raises(typer.Exit) as ei:
        boom()
    assert ei.value.exit_code == 1


def test_double_confirm_runs_two_prompts(monkeypatch):
    from compliance_aiops.cli import _common

    calls: list[str] = []
    monkeypatch.setattr(_common.typer, "confirm", lambda msg, abort=False: calls.append(msg))
    _common.double_confirm("delete", "widget-1")
    assert len(calls) == 2


def test_dry_run_print_smoke():
    from compliance_aiops.cli._common import dry_run_print

    # exercises the parameter-rendering loop; no assertion needed beyond no-raise
    dry_run_print(operation="op", api_call="call()", parameters={"a": 1, "b": 2})


# ── mcp launcher ──────────────────────────────────────────────────────────


def test_mcp_command_invokes_server_main(monkeypatch):
    import mcp_server.server as server

    called: list[bool] = []
    monkeypatch.setattr(server, "main", lambda: called.append(True))
    res = runner.invoke(_app(), ["mcp"])
    assert res.exit_code == 0, res.output
    assert called == [True]
