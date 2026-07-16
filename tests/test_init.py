"""Tests for the ``compliance-aiops init`` onboarding wizard.

Unlike the platform tools, this wizard collects an **organization name** and
registers discovered sibling **audit sources** — there is no TLS prompt and the
secret store holds only an *optional* bundle-signing key. The wizard is driven
end-to-end through Typer's CliRunner with every path (config.yaml, secrets.enc,
rules.yaml) isolated under tmp_path; source discovery is patched so nothing on
the real machine ever leaks in.
"""

from __future__ import annotations

import getpass as getpass_mod

import pytest
import yaml
from typer.testing import CliRunner

import compliance_aiops.cli.init as init_mod
import compliance_aiops.config as config_mod
import compliance_aiops.doctor as doctor_mod
import compliance_aiops.secretstore as ss
from compliance_aiops.config import AuditSource

pytestmark = pytest.mark.unit

MASTER_PW = "init-master-pw"
SIGNING_KEY = "bundle-signing-key-material"

# Wizard answers: organization, include the one discovered source, tag it
# "prod", skip the signing key (default No), decline the trailing doctor run.
WIZARD_INPUT = "Acme Corp\ny\nprod\nn\nn\n"


@pytest.fixture
def init_home(tmp_path, monkeypatch):
    """Isolate config + secret store + governance home under tmp_path."""
    config_file = tmp_path / "config.yaml"
    secrets_file = tmp_path / "secrets.enc"
    monkeypatch.setenv("HOME", str(tmp_path))  # neuter ~/.*-aiops discovery
    monkeypatch.setenv("COMPLIANCE_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, MASTER_PW)
    monkeypatch.setattr(init_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(init_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", secrets_file)
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    # One synthetic discovered sibling source by default.
    db = tmp_path / "nutanix-audit.db"
    db.write_text("", "utf-8")
    monkeypatch.setattr(
        init_mod,
        "discover_sources",
        lambda: (AuditSource(name="nutanix-aiops", path=db),),
    )
    # The hidden signing-key prompt bypasses CliRunner stdin.
    monkeypatch.setattr(getpass_mod, "getpass", lambda prompt="": SIGNING_KEY)
    return tmp_path


def _run_init(input_text: str = WIZARD_INPUT):
    from compliance_aiops.cli import app

    return CliRunner().invoke(app, ["init"], input=input_text)


def test_init_writes_config_with_organization_and_sources(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["organization"] == "Acme Corp"
    assert raw["sources"] == [
        {
            "name": "nutanix-aiops",
            "path": str(init_home / "nutanix-audit.db"),
            "environment": "prod",
        }
    ]


def test_init_excluded_source_left_out_of_config(init_home, monkeypatch):
    db_a = init_home / "a-audit.db"
    db_b = init_home / "b-audit.db"
    monkeypatch.setattr(
        init_mod,
        "discover_sources",
        lambda: (AuditSource(name="proxmox-aiops", path=db_a),
                 AuditSource(name="veeam-aiops", path=db_b)),
    )
    # Include the first (tag "lab"), exclude the second; skip key + doctor.
    result = _run_init("Acme Corp\ny\nlab\nn\nn\nn\n")
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert [s["name"] for s in raw["sources"]] == ["proxmox-aiops"]
    assert raw["sources"][0]["environment"] == "lab"


def test_init_no_discovered_sources_still_writes_config(init_home, monkeypatch):
    monkeypatch.setattr(init_mod, "discover_sources", lambda: ())
    # organization, (no per-source prompts), skip key, decline doctor.
    result = _run_init("Acme Corp\nn\nn\n")
    assert result.exit_code == 0, result.output
    assert "No sibling audit DBs found" in " ".join(result.output.split())
    raw = yaml.safe_load((init_home / "config.yaml").read_text("utf-8"))
    assert raw["organization"] == "Acme Corp"
    assert raw["sources"] == []


def test_init_signing_key_declined_by_default_no_secret_store(init_home):
    result = _run_init()  # explicit "n" on the signing-key confirm
    assert result.exit_code == 0, result.output
    assert not (init_home / "secrets.enc").exists()


def test_init_signing_key_accepted_stored_encrypted(init_home):
    # organization, include source, tag, accept signing key, decline doctor.
    result = _run_init("Acme Corp\ny\nprod\ny\nn\n")
    assert result.exit_code == 0, result.output
    # Key is readable back through the secret store API...
    assert ss.SecretStore.unlock(MASTER_PW).get("signing-key") == SIGNING_KEY
    # ...and never lands in plaintext in config.yaml or secrets.enc.
    assert SIGNING_KEY not in (init_home / "config.yaml").read_text("utf-8")
    assert SIGNING_KEY not in (init_home / "secrets.enc").read_text("utf-8")


def test_init_seeds_default_rules_with_dual_control_tier(init_home):
    result = _run_init()
    assert result.exit_code == 0, result.output
    rules = yaml.safe_load((init_home / "rules.yaml").read_text("utf-8"))
    tiers = {r["name"]: r for r in rules["risk_tiers"]}
    assert "high-risk-requires-approver" in tiers
    assert tiers["high-risk-requires-approver"]["tier"] == "dual"
    assert tiers["high-risk-requires-approver"]["min_risk_level"] == "high"


def test_init_rerun_does_not_clobber_existing_rules(init_home):
    sentinel = "# operator-authored rules — must survive re-init\nrisk_tiers: []\n"
    (init_home / "rules.yaml").write_text(sentinel, "utf-8")
    result = _run_init()
    assert result.exit_code == 0, result.output
    assert (init_home / "rules.yaml").read_text("utf-8") == sentinel


def test_init_declining_doctor_confirm_skips_doctor(init_home, monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr(doctor_mod, "run_doctor", lambda: calls.append(True) or 0)
    result = _run_init()  # WIZARD_INPUT ends with an explicit "n"
    assert result.exit_code == 0, result.output
    assert calls == []


def test_init_accepting_doctor_confirm_runs_doctor(init_home, monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr(doctor_mod, "run_doctor", lambda: calls.append(True) or 0)
    # Empty last answer accepts the confirm's default=True.
    result = _run_init("Acme Corp\ny\nprod\nn\n\n")
    assert result.exit_code == 0, result.output
    assert calls == [True]
