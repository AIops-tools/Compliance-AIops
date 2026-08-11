"""A change-management gap needs an unapproved CHANGE, not an unapproved attempt.

Found on a real cross-tool audit trail: two high-risk writes failed on a dropped
connection and were still reported as "2 high-risk write op(s) recorded without
an approver — change-approval gap". Asked to produce those two unapproved
changes, the trail would have shown that neither happened. The harness records
the outcome; the reporting layer was discarding it.

The `undetermined` bucket is the one that must never be dropped: a lost response
means the change may well have landed, which is exactly why the harness refuses
to call it a failure.
"""

from __future__ import annotations

import pytest

from compliance_aiops import frameworks as fw
from compliance_aiops.ops import controls as ops

pytestmark = pytest.mark.unit


def _op(status, approver="", risk="high", tool="drop_index"):
    return {"ts": "2026-08-08T00:00:00+00:00", "skill": "postgres-aiops", "tool": tool,
            "status": status, "risk_level": risk, "approved_by": approver,
            "user": "alice", "agent": "claude", "params": "{}", "result": "{}"}


class _Reader:
    def __init__(self, rows):
        self._rows = rows

    def query(self, **kwargs):
        return list(self._rows)

    def scan(self, **kwargs):
        return list(self._rows)

    def sources_status(self):
        return []


@pytest.fixture
def reader_factory(monkeypatch):
    def build(rows):
        reader = _Reader(rows)
        monkeypatch.setattr(ops, "scan", lambda r, **kw: (list(rows), False))
        return reader
    return build


def test_classification_splits_the_three_outcomes():
    events = [
        _op("ok"),                    # a real unapproved change
        _op("unknown"),               # may have landed — must not be dropped
        _op("error"),                 # changed nothing
        _op("denied"),                # changed nothing
        _op("ok", approver="wei"),    # approved: not in any bucket
        _op("ok", risk="low"),        # not a high-risk write
    ]
    split = fw.classify_unapproved_writes(events)
    assert len(split["all"]) == 4
    assert len(split["landed"]) == 1
    assert len(split["undetermined"]) == 1
    assert len(split["didNotLand"]) == 2


def test_only_failed_attempts_are_not_a_change_approval_gap(reader_factory):
    """The exact real-world shape: unapproved high-risk writes that all failed."""
    reader = reader_factory([_op("error"), _op("error")])
    summary = ops.coverage_summary(reader, "soc2")
    change = next(c for c in summary["controls"] if c["controlId"] == "CC8.1")
    assert change["gap"] is None, change["gap"]
    # …but the attempts are still visible at the payload level, not buried.
    assert summary["unapprovedWrites"]["didNotLand"] == 2
    assert summary["unapprovedWrites"]["tookEffect"] == 0


def test_an_unapproved_change_that_landed_is_still_a_gap(reader_factory):
    """The check must not have been disabled — only made outcome-aware."""
    reader = reader_factory([_op("ok"), _op("error")])
    summary = ops.coverage_summary(reader, "soc2")
    change = next(c for c in summary["controls"] if c["controlId"] == "CC8.1")
    assert change["gap"] and "took effect without an approver" in change["gap"]
    assert "1 further high-risk attempt(s)" in change["gap"]
    assert summary["unapprovedWrites"] == {
        "tookEffect": 1, "outcomeUndetermined": 0, "didNotLand": 1,
        "note": summary["unapprovedWrites"]["note"],
    }


def test_an_undetermined_outcome_counts_as_a_gap_and_says_so(reader_factory):
    """A lost response may well have applied the change — the one case that must
    never be filed under 'did not happen'."""
    reader = reader_factory([_op("unknown")])
    summary = ops.coverage_summary(reader, "soc2")
    change = next(c for c in summary["controls"] if c["controlId"] == "CC8.1")
    assert change["gap"]
    assert "undetermined and may have taken effect" in change["gap"]
    assert summary["unapprovedWrites"]["outcomeUndetermined"] == 1


def test_gap_analysis_reports_the_same_summary(reader_factory):
    reader = reader_factory([_op("ok"), _op("unknown"), _op("error")])
    gaps = ops.gap_analysis(reader, "soc2")
    assert gaps["unapprovedWrites"]["tookEffect"] == 1
    assert gaps["unapprovedWrites"]["outcomeUndetermined"] == 1
    assert gaps["unapprovedWrites"]["didNotLand"] == 1
    finding = next(f for f in gaps["findings"] if f["controlId"] == "CC8.1")
    assert "approver" in finding["remediation"]
