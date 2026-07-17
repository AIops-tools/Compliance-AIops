"""Read-only audit-DB reader resilience + config loading.

The reader must open every source strictly read-only (never create/write a
source), union rows across sources, skip missing/corrupt/locked sources with a
warning instead of failing the whole query, and detect row-id gaps. Config must
load from YAML and auto-discover, and never leak the real machine's home.
"""

from __future__ import annotations

import sqlite3

import pytest

pytestmark = pytest.mark.unit


def _make_audit_db(path, rows):
    from compliance_aiops.governance.audit import AuditEngine

    AuditEngine(str(path))
    conn = sqlite3.connect(str(path))
    for rid, ts, tool in rows:
        conn.execute(
            "INSERT INTO audit_log (id,ts,skill,tool,params,result,status) "
            "VALUES (?,?,?,?,?,?,?)",
            (rid, ts, "s", tool, "{}", "{}", "ok"),
        )
    conn.commit()
    conn.close()
    return path


# ── read-only opening & resilience ────────────────────────────────────────


def test_query_unions_multiple_sources_newest_first(tmp_path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    a = _make_audit_db(tmp_path / "a.db", [(1, "2026-07-01T09:00:00+00:00", "a1")])
    b = _make_audit_db(tmp_path / "b.db", [(1, "2026-07-02T09:00:00+00:00", "b1")])
    reader = AuditReader([AuditSource(name="a", path=a), AuditSource(name="b", path=b)])
    rows = reader.query()
    assert [r["tool"] for r in rows] == ["b1", "a1"]  # newest ts first, across sources
    assert {r["source"] for r in rows} == {"a", "b"}


def test_source_filter_and_missing_source_skipped(tmp_path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    a = _make_audit_db(tmp_path / "a.db", [(1, "2026-07-01T09:00:00+00:00", "a1")])
    missing = tmp_path / "gone.db"
    reader = AuditReader([AuditSource(name="a", path=a), AuditSource(name="m", path=missing)])
    assert [r["source"] for r in reader.query()] == ["a"]  # missing skipped
    assert reader.query(source="a")  # source filter selects only a
    assert reader.query(source="m") == []  # filter to the missing source → empty
    assert not missing.exists()  # never created by a read


def test_corrupt_source_is_skipped_not_fatal(tmp_path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    good = _make_audit_db(tmp_path / "good.db", [(1, "2026-07-01T09:00:00+00:00", "g1")])
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database at all")
    reader = AuditReader([AuditSource(name="g", path=good), AuditSource(name="c", path=corrupt)])
    rows = reader.query()  # must not raise
    assert [r["source"] for r in rows] == ["g"]

    status = reader.sources_status()
    by = {s["name"]: s for s in status}
    assert by["g"]["readable"] is True and by["g"]["rowCount"] == 1
    assert by["c"]["exists"] is True and by["c"]["readable"] is False
    assert by["c"]["rowCount"] is None


def test_ordered_ids_and_gap_helpers(tmp_path):
    from compliance_aiops.config import AuditSource
    from compliance_aiops.connection import AuditReader

    db = _make_audit_db(
        tmp_path / "a.db",
        [(1, "t1", "x"), (2, "t2", "y"), (5, "t3", "z")],  # 3,4 deleted
    )
    reader = AuditReader([AuditSource(name="a", path=db)])
    assert reader.ordered_ids("a") == [1, 2, 5]
    assert reader.ordered_ids("nope") == []  # unknown source → empty, no raise


def test_query_readonly_mode_rejects_writes_to_source(tmp_path):
    """The reader opens ``mode=ro`` — a write through that handle must fail,
    proving evidence derivation can never mutate a source of truth."""
    from compliance_aiops.connection import _connect_ro

    db = _make_audit_db(tmp_path / "a.db", [(1, "t1", "x")])
    conn = _connect_ro(str(db))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO audit_log (id,ts,skill,tool) VALUES (99,'t','s','w')")
    conn.close()


# ── config ────────────────────────────────────────────────────────────────


def test_load_config_from_yaml_with_sources(tmp_path):
    import compliance_aiops.config as cfg_mod

    db = tmp_path / "src.db"
    db.write_text("", "utf-8")
    yaml_path = tmp_path / "config.yaml"
    yaml_path.write_text(
        "organization: Acme Corp\n"
        "bundle_dir: " + str(tmp_path / "out") + "\n"
        "sources:\n"
        f"  - name: nutanix-aiops\n    path: {db}\n    environment: prod\n",
        "utf-8",
    )
    cfg = cfg_mod.load_config(yaml_path)
    assert cfg.organization == "Acme Corp"
    assert cfg.bundle_dir == tmp_path / "out"
    assert len(cfg.sources) == 1
    src = cfg.sources[0]
    assert src.name == "nutanix-aiops" and src.environment == "prod" and src.exists


def test_load_config_missing_file_autodiscovers_home(tmp_path, monkeypatch):
    import compliance_aiops.config as cfg_mod

    monkeypatch.setenv("HOME", str(tmp_path))
    # a sibling tool's audit.db + this tool's own (which must be excluded)
    (tmp_path / ".nutanix-aiops").mkdir()
    (tmp_path / ".nutanix-aiops" / "audit.db").write_text("", "utf-8")
    (tmp_path / ".compliance-aiops").mkdir()
    (tmp_path / ".compliance-aiops" / "audit.db").write_text("", "utf-8")

    found = {s.name for s in cfg_mod.discover_sources()}
    assert found == {"nutanix-aiops"}  # own tool excluded

    cfg = cfg_mod.load_config(tmp_path / "does-not-exist.yaml")
    assert {s.name for s in cfg.sources} == {"nutanix-aiops"}


def test_appconfig_get_source_found_and_missing():
    from compliance_aiops.config import AppConfig, AuditSource

    cfg = AppConfig(sources=(AuditSource(name="a", path=None),))
    assert cfg.get_source("a").name == "a"
    with pytest.raises(KeyError, match="not found"):
        cfg.get_source("missing")
