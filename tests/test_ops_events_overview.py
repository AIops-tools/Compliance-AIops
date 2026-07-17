"""Event query + activity timeline + one-shot posture overview (read-only ops).

These exercise the REAL ops code against a synthetic real-schema audit.db built
through the harness ``AuditEngine`` (offline/deterministic, this tool's only data
source), plus a deliberately-failing fake reader for the overview's degrade path.
"""

from __future__ import annotations

import sqlite3

import pytest

pytestmark = pytest.mark.unit

_ROWS = [
    # (ts, skill, tool, status, risk_level, approved_by)
    ("2026-07-01T09:00:00+00:00", "nutanix-aiops", "vm_list", "ok", "low", ""),
    ("2026-07-01T09:30:00+00:00", "nutanix-aiops", "vm_delete", "ok", "high", "alice"),
    ("2026-07-01T11:00:00+00:00", "ceph-aiops", "osd_purge", "ok", "high", ""),
    ("2026-07-02T12:00:00+00:00", "ceph-aiops", "pool_delete", "denied", "high", ""),
    ("2026-07-02T13:00:00+00:00", "k8s-aiops", "scale", "error", "medium", ""),
]


def _make_audit_db(path, rows=_ROWS):
    from compliance_aiops.governance.audit import AuditEngine

    AuditEngine(str(path))
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


@pytest.fixture
def reader(tmp_path):
    return _reader(_make_audit_db(tmp_path / "audit.db"))


# ── list_sources / query_events ───────────────────────────────────────────


def test_list_sources_reports_readability_and_count(reader):
    from compliance_aiops.ops import events as ops

    srcs = ops.list_sources(reader)
    assert len(srcs) == 1
    assert srcs[0]["name"] == "testsrc"
    assert srcs[0]["readable"] is True
    assert srcs[0]["rowCount"] == len(_ROWS)


def test_query_events_field_filters_and_limit(reader):
    from compliance_aiops.ops import events as ops

    out = ops.query_events(reader, status="denied")
    assert out["count"] == 1 and out["events"][0]["tool"] == "pool_delete"

    # a limit below the match count truncates the returned events list
    capped = ops.query_events(reader, limit=2)
    assert capped["count"] == 2 and len(capped["events"]) == 2

    # limit is floored to >= 1 internally so 0 never means "unbounded"
    assert ops.query_events(reader, limit=0)["count"] == 1


def test_query_events_selector_filters_evidence_class(reader):
    from compliance_aiops.ops import events as ops

    # 'change' selector keeps state-changing (write, risk >= medium) ops — the
    # field filter and the compliance selector compose; read-only vm_list drops.
    changes = ops.query_events(reader, selector="change", limit=100)
    tools = {e["tool"] for e in changes["events"]}
    assert tools == {"vm_delete", "osd_purge", "pool_delete", "scale"}
    assert "vm_list" not in tools  # low-risk read excluded

    # 'enforcement' keeps governance-blocked ops (denied/budget_exceeded)
    enforced = ops.query_events(reader, selector="enforcement", limit=100)
    assert {e["tool"] for e in enforced["events"]} == {"pool_delete"}


def test_query_events_unknown_selector_raises(reader):
    from compliance_aiops.ops import events as ops

    with pytest.raises(ValueError, match="Unknown selector"):
        ops.query_events(reader, selector="not_a_selector")


def test_activity_timeline_buckets_by_day_and_hour(reader):
    from compliance_aiops.ops import events as ops

    by_day = ops.activity_timeline(reader, bucket="day")
    assert by_day["bucket"] == "day"
    assert by_day["total"] == len(_ROWS)
    keys = {b["bucket"] for b in by_day["series"]}
    assert keys == {"2026-07-01", "2026-07-02"}
    counts = {b["bucket"]: b["count"] for b in by_day["series"]}
    assert counts["2026-07-01"] == 3 and counts["2026-07-02"] == 2
    # series is sorted ascending by bucket key
    assert [b["bucket"] for b in by_day["series"]] == sorted(keys)

    by_hour = ops.activity_timeline(reader, bucket="hour")
    assert all(len(b["bucket"]) == 13 for b in by_hour["series"])  # YYYY-MM-DDTHH


def test_activity_timeline_rejects_bad_bucket(reader):
    from compliance_aiops.ops import events as ops

    with pytest.raises(ValueError, match="hour.*day"):
        ops.activity_timeline(reader, bucket="week")


# ── posture overview ──────────────────────────────────────────────────────


def test_posture_overview_folds_sources_and_frameworks(reader):
    from compliance_aiops import frameworks as fw
    from compliance_aiops.ops import overview as ops

    out = ops.posture_overview(reader)
    assert out["auditSources"] == 1
    assert out["readableSources"] == 1
    assert out["errors"] == []
    # every configured framework is summarized with covered/total counts
    names = {f["framework"] for f in out["frameworks"]}
    assert names == set(fw.FRAMEWORKS)
    for f in out["frameworks"]:
        assert 0 <= f["covered"] <= f["total"]
        assert f["title"]


def test_posture_overview_degrades_to_errors_on_failing_subcall():
    from compliance_aiops import frameworks as fw
    from compliance_aiops.ops import overview as ops

    class _Boom:
        def sources_status(self):
            return [{"name": "s", "readable": False}]

        def query(self, **_):
            raise ValueError("audit db unreadable")

    out = ops.posture_overview(_Boom())
    assert out["readableSources"] == 0
    assert out["frameworks"] == []  # every framework degraded
    assert len(out["errors"]) == len(fw.FRAMEWORKS)
    assert all("unreadable" in e for e in out["errors"])
