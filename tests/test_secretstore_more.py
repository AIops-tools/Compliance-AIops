"""Additional secret-store coverage: module convenience API, permission warning,
version/corruption guards, and the non-interactive master-password resolution.

All paths are redirected under tmp_path so nothing touches ~/.compliance-aiops.
"""

from __future__ import annotations

import json

import pytest

import compliance_aiops.secretstore as ss

pytestmark = pytest.mark.unit


@pytest.fixture
def store_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(ss, "SECRETS_FILE", tmp_path / "secrets.enc")
    monkeypatch.setattr(ss, "LEGACY_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ss, "_cached", None)
    monkeypatch.delenv(ss.MASTER_PASSWORD_ENV, raising=False)
    return tmp_path


# ── module convenience API ────────────────────────────────────────────────


def test_open_store_caches_per_process(store_dir, monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "pw")
    monkeypatch.setattr(ss, "_cached", None)
    s1 = ss.open_store()
    s2 = ss.open_store()
    assert s1 is s2  # cached when password is None

    # an explicit password bypasses the cache and returns a fresh store
    s3 = ss.open_store("pw", use_cache=False)
    assert s3 is not s1


def test_get_secret_and_has_store_roundtrip(store_dir, monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "pw")
    assert ss.has_store() is False
    ss.SecretStore.unlock("pw").set("signing-key", "material")
    assert ss.has_store() is True
    monkeypatch.setattr(ss, "_cached", None)
    assert ss.get_secret("signing-key") == "material"


# ── permission warning ────────────────────────────────────────────────────


def test_check_permissions_none_when_absent_or_600(store_dir):
    assert ss.check_permissions() is None  # no store yet
    ss.SecretStore.unlock("pw").set("a", "1")
    assert ss.check_permissions() is None  # persisted 600


def test_check_permissions_warns_when_group_or_world_readable(store_dir):
    ss.SecretStore.unlock("pw").set("a", "1")
    (store_dir / "secrets.enc").chmod(0o644)
    warning = ss.check_permissions()
    assert warning and "should be 600" in warning
    assert "chmod 600" in warning


# ── corruption / version guards ───────────────────────────────────────────


def test_unlock_unreadable_json_raises_teaching_error(store_dir):
    (store_dir / "secrets.enc").write_text("{ not valid json", "utf-8")
    with pytest.raises(ss.SecretStoreError, match="Could not read secret store"):
        ss.SecretStore.unlock("pw")


def test_unlock_unsupported_version_raises(store_dir):
    (store_dir / "secrets.enc").write_text(
        json.dumps({"version": 999, "salt": "AAAA", "ciphertext": "x"}), "utf-8"
    )
    with pytest.raises(ss.SecretStoreError, match="Unsupported secret store version"):
        ss.SecretStore.unlock("pw")


def test_delete_missing_and_with_password_empty_reject(store_dir):
    store = ss.SecretStore.unlock("pw").set("a", "1")
    with pytest.raises(ss.SecretStoreError, match="to delete"):
        store.delete("nope")
    with pytest.raises(ss.SecretStoreError, match="must not be empty"):
        store.with_password("")


# ── master password resolution ────────────────────────────────────────────


def test_resolve_master_password_from_env(store_dir, monkeypatch):
    monkeypatch.setenv(ss.MASTER_PASSWORD_ENV, "from-env")
    assert ss.resolve_master_password() == "from-env"


def test_resolve_master_password_no_tty_no_env_raises(store_dir, monkeypatch):
    monkeypatch.delenv(ss.MASTER_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(ss.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ss.MasterPasswordError, match="Master password not set"):
        ss.resolve_master_password()


def test_resolve_master_password_interactive_prompt_and_confirm(store_dir, monkeypatch):
    monkeypatch.delenv(ss.MASTER_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(ss.sys.stdin, "isatty", lambda: True)

    answers = iter(["secret-pw", "secret-pw"])
    monkeypatch.setattr(ss.getpass, "getpass", lambda prompt="": next(answers))
    # confirm_if_new asks twice when no store exists; matching → returns it
    assert ss.resolve_master_password(confirm_if_new=True) == "secret-pw"


def test_resolve_master_password_empty_and_mismatch(store_dir, monkeypatch):
    monkeypatch.delenv(ss.MASTER_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(ss.sys.stdin, "isatty", lambda: True)

    monkeypatch.setattr(ss.getpass, "getpass", lambda prompt="": "")
    with pytest.raises(ss.MasterPasswordError, match="Empty master password"):
        ss.resolve_master_password()

    mismatch = iter(["one", "two"])
    monkeypatch.setattr(ss.getpass, "getpass", lambda prompt="": next(mismatch))
    with pytest.raises(ss.MasterPasswordError, match="did not match"):
        ss.resolve_master_password(confirm_if_new=True)


def test_migrate_legacy_env_noop_when_no_file(store_dir):
    assert ss.migrate_legacy_env("COMPLIANCE_", "_SECRET", "pw") == []
