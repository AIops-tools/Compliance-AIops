"""Tests for ``compliance_aiops.doctor.run_doctor``.

compliance-aiops has no remote API — its doctor resolves local **audit
sources** (sibling tools' audit.db files). Every path is redirected to a tmp
dir (HOME included, so ``~/.*-aiops`` auto-discovery can never see the real
machine) and sources are synthetic SQLite files, so no test ever touches a
real audit trail or the real ``~/.compliance-aiops``.
"""

from __future__ import annotations

import sqlite3

import pytest
import yaml

import compliance_aiops.config as config_mod
import compliance_aiops.doctor as doctor_mod
import compliance_aiops.secretstore as ss
from compliance_aiops.doctor import run_doctor

pytestmark = pytest.mark.unit

MASTER_PW = "test-master-pw"


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Redirect config/secret paths AND $HOME (source auto-discovery globs
    ``~/.*-aiops/audit.db``) at a throwaway directory."""
    config_file = tmp_path / "config.yaml"
    secrets_file = tmp_path / "secrets.enc"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("COMPLIANCE_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, MASTER_PW)
    # Module constants are import-time snapshots of ops_home(); patch them.
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(doctor_mod, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    return tmp_path


def _make_audit_db(path, rows: int = 3) -> None:
    """A minimal sibling audit.db: the shared audit_log table + a few rows."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TEXT, tool TEXT, status TEXT)"
    )
    for i in range(rows):
        conn.execute(
            "INSERT INTO audit_log (ts, tool, status) VALUES (?, ?, ?)",
            (f"2026-07-16T0{i}:00:00Z", "vm_list", "ok"),
        )
    conn.commit()
    conn.close()


def _write_config(home, sources: list[dict], organization: str = "Acme Corp") -> None:
    doc = {"organization": organization, "sources": sources}
    (home / "config.yaml").write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")


def _source(home, name: str = "nutanix-aiops", rows: int = 3) -> dict:
    db = home / f"{name}-audit.db"
    _make_audit_db(db, rows)
    return {"name": name, "path": str(db), "environment": "prod"}


def test_missing_config_and_no_siblings_fails_with_init_hint(isolated_home, capsys):
    # No config.yaml and nothing under $HOME/.*-aiops -> nothing to audit.
    assert run_doctor() == 1
    out = " ".join(capsys.readouterr().out.split())
    assert "No audit sources found" in out
    assert "compliance-aiops init" in out


def test_config_load_failure_reported_not_raised(isolated_home, capsys):
    (isolated_home / "config.yaml").write_text("sources: [unclosed", "utf-8")
    assert run_doctor() == 1
    assert "Config load failed" in capsys.readouterr().out


def test_all_sources_readable_exits_zero_with_row_counts(isolated_home, capsys):
    _write_config(
        isolated_home,
        [_source(isolated_home, "nutanix-aiops", rows=3),
         _source(isolated_home, "ceph-aiops", rows=5)],
    )
    assert run_doctor() == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "2 audit source(s) resolved" in out
    assert "nutanix-aiops — 3 audit rows" in out
    assert "ceph-aiops — 5 audit rows" in out


def test_missing_source_file_is_a_problem(isolated_home, capsys):
    missing = isolated_home / "gone-audit.db"  # never created
    _write_config(
        isolated_home,
        [{"name": "veeam-aiops", "path": str(missing), "environment": ""}],
    )
    assert run_doctor() == 1
    out = " ".join(capsys.readouterr().out.split())
    assert "veeam-aiops — path missing" in out
    assert "No readable audit sources" in out


def test_unreadable_source_file_is_a_problem(isolated_home, capsys):
    garbage = isolated_home / "corrupt-audit.db"
    garbage.write_text("this is not a sqlite database", "utf-8")
    _write_config(
        isolated_home,
        [{"name": "k8s-aiops", "path": str(garbage), "environment": ""}],
    )
    assert run_doctor() == 1
    out = " ".join(capsys.readouterr().out.split())
    assert "k8s-aiops — present but unreadable/incompatible" in out


def test_one_broken_source_does_not_hide_the_readable_one(isolated_home, capsys):
    _write_config(
        isolated_home,
        [_source(isolated_home, "nutanix-aiops", rows=2),
         {"name": "veeam-aiops", "path": str(isolated_home / "gone.db"),
          "environment": ""}],
    )
    assert run_doctor() == 1  # the missing one is still a problem
    out = " ".join(capsys.readouterr().out.split())
    assert "nutanix-aiops — 2 audit rows" in out
    assert "veeam-aiops — path missing" in out


def test_no_secret_store_is_optional_not_a_problem(isolated_home, capsys):
    _write_config(isolated_home, [_source(isolated_home)])
    assert run_doctor() == 0  # a signing key is optional
    out = " ".join(capsys.readouterr().out.split())
    assert "No secret store" in out
    assert "unsigned" in out


def test_secret_store_present_reported_with_permission_warning(isolated_home, capsys):
    _write_config(isolated_home, [_source(isolated_home)])
    ss.SecretStore.unlock(MASTER_PW).set("signing-key", "sekrit")
    (isolated_home / "secrets.enc").chmod(0o644)
    assert run_doctor() == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Encrypted secret store present" in out
    assert "should be 600" in out


def test_cli_doctor_command_exits_with_doctor_code(isolated_home):
    from typer.testing import CliRunner

    from compliance_aiops.cli import app

    _write_config(isolated_home, [_source(isolated_home)])
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "audit source(s) resolved" in " ".join(result.output.split())
