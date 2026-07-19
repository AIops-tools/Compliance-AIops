"""Absent evidence fields come back as null, not as an empty string.

For a compliance tool this is not cosmetic. ``"approvedBy": ""`` reads as "an
approver field exists and is blank"; the truth may be "no approver was ever
recorded for this operation". Those are different findings for an auditor, and a
smaller local model asked to summarise a trail will pick whichever reads more
fluently. These tests pin the contract, plus the truncation flags that keep a
partial population from being presented as a complete one.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from compliance_aiops.governance import opt_str
from compliance_aiops.ops import controls as control_ops
from compliance_aiops.ops import events as event_ops
from compliance_aiops.ops import reports as report_ops
from compliance_aiops.ops._util import SCAN_LIMIT, norm_event, opt_s, s

pytestmark = pytest.mark.unit


def _reader(rows: list[dict]):
    """A reader that honours ``limit`` the way the real one does."""
    reader = MagicMock()
    reader.query.side_effect = lambda limit=100, **kw: rows[:limit]
    return reader


def _row(**over) -> dict:
    base = {
        "id": 1, "source": "ceph-aiops", "ts": "2026-07-01T09:00:00+00:00",
        "skill": "ceph-aiops", "tool": "osd_purge", "status": "ok",
        "risk_level": "high",
    }
    base.update(over)
    return base


@pytest.mark.unit
def test_opt_str_distinguishes_absent_from_empty():
    assert opt_str(None) is None, "absent must stay absent"
    assert opt_str("") == "", "a genuinely empty value is not the same as absent"
    assert opt_str("alice@example.com", 64) == "alice@example.com"


@pytest.mark.unit
def test_opt_str_still_sanitizes_and_truncates():
    assert opt_str("a\x00b") == "ab"  # control character stripped
    assert opt_str("abcdef", 3) == "abc"


@pytest.mark.unit
def test_opt_str_accepts_non_string_values():
    assert opt_str(42) == "42"


@pytest.mark.unit
def test_opt_s_and_s_differ_only_on_absence():
    assert s(None) == "" and opt_s(None) is None
    assert s("alice") == opt_s("alice") == "alice"


# ── the evidence shape ───────────────────────────────────────────────────


@pytest.mark.unit
def test_no_approver_recorded_is_null_not_blank():
    """The distinction an auditor actually reads."""
    ev = norm_event(_row())
    assert ev["approvedBy"] is None, "no approver recorded must not read as blank"
    assert ev["rationale"] is None and ev["riskTier"] is None


@pytest.mark.unit
def test_a_recorded_empty_approver_stays_empty():
    """An approver column written as '' is a different fact from an absent one.

    It means the harness wrote the column and the value was empty — worth
    distinguishing from a row where the column was never populated.
    """
    ev = norm_event(_row(approved_by=""))
    assert ev["approvedBy"] == ""


@pytest.mark.unit
def test_recorded_approver_survives_intact():
    ev = norm_event(_row(approved_by="alice@example.com", rationale="CHG-42"))
    assert ev["approvedBy"] == "alice@example.com" and ev["rationale"] == "CHG-42"


@pytest.mark.unit
def test_evidence_never_drops_a_key():
    """Keys are always present; only their value may be null.

    Omitting a key entirely is worse than a null — a reviewer cannot tell the
    field was even considered.
    """
    ev = norm_event({})
    for key in ("id", "source", "environment", "ts", "skill", "tool", "status",
                "riskLevel", "riskTier", "agent", "user", "approvedBy", "rationale"):
        assert key in ev, f"{key} must be present even when the row omitted it"


@pytest.mark.unit
def test_approval_classification_is_unaffected_by_the_null_shape():
    """is_approved reads the RAW row, so nulls cannot flip an approval verdict."""
    from compliance_aiops.ops._util import is_approved

    assert is_approved(_row(approved_by="alice")) is True
    assert is_approved(_row()) is False
    assert is_approved(_row(approved_by="   ")) is False


# ── truncation announces itself ──────────────────────────────────────────


@pytest.mark.unit
def test_query_events_returns_a_truncation_envelope():
    reader = _reader([_row(id=i) for i in range(5)])
    out = event_ops.query_events(reader, limit=2)
    assert out["returned"] == 2 and out["limit"] == 2 and out["truncated"] is True
    assert len(out["events"]) == 2


@pytest.mark.unit
def test_query_events_count_describes_what_you_were_given():
    """``count`` used to describe the pre-slice rows while ``events`` was sliced.

    The two numbers disagreed about the same call, and nothing in the payload
    said which was which.
    """
    reader = _reader([_row(id=i) for i in range(5)])
    out = event_ops.query_events(reader, limit=2)
    assert out["count"] == out["returned"] == len(out["events"]) == 2


@pytest.mark.unit
def test_query_events_is_not_truncated_at_exactly_the_limit():
    """The boundary case a length-comparison heuristic gets wrong."""
    reader = _reader([_row(id=i) for i in range(2)])
    out = event_ops.query_events(reader, limit=2)
    assert out["returned"] == 2 and out["truncated"] is False


@pytest.mark.unit
def test_query_events_fetches_one_extra_row_to_measure():
    reader = _reader([_row(id=i) for i in range(5)])
    event_ops.query_events(reader, limit=2)
    assert reader.query.call_args.kwargs["limit"] == 3


@pytest.mark.unit
def test_coverage_summary_states_whether_its_population_was_capped():
    """A coverage percentage over a silently truncated scan is not evidence."""
    reader = _reader([_row(id=i) for i in range(3)])
    out = control_ops.coverage_summary(reader, "soc2")
    assert out["scanTruncated"] is False and out["scanLimit"] == SCAN_LIMIT


@pytest.mark.unit
def test_a_capped_scan_is_reported_as_truncated():
    reader = MagicMock()
    # One row past the cap: exactly what the extra fetch exists to detect.
    reader.query.return_value = [_row(id=i) for i in range(SCAN_LIMIT + 1)]
    out = control_ops.coverage_summary(reader, "soc2")
    assert out["scanTruncated"] is True
    assert out["eventsScanned"] == SCAN_LIMIT, "the probe row is never counted as evidence"


@pytest.mark.unit
def test_reports_carry_the_scan_flag_and_their_own_row_caps():
    reader = _reader([_row(id=i, approved_by="") for i in range(3)])
    approval = report_ops.approval_report(reader)
    assert approval["scanTruncated"] is False
    assert approval["truncated"] is False and approval["limit"] == 200
    assert approval["unapprovedTruncated"] is False

    exceptions = report_ops.exceptions_report(reader)
    assert exceptions["scanTruncated"] is False and exceptions["truncated"] is False


@pytest.mark.unit
def test_control_evidence_sample_cap_announces_itself():
    reader = _reader([_row(id=i, tool="vm_delete", approved_by="alice") for i in range(5)])
    out = control_ops.control_evidence(reader, "soc2", "CC8.1", sample_size=2)
    assert out["limit"] == 2
    assert out["returned"] == len(out["sample"])
    assert out["truncated"] is (out["populationSize"] > 2)


@pytest.mark.unit
def test_undo_list_envelope_measures_truncation(monkeypatch):
    from mcp_server.tools import undo as undo_tools

    rows = [
        {
            "undo_id": f"u{i}",
            "ts": "2026-07-18T00:00:00Z",
            "tool": "some_tool",
            "undo_tool": "some_inverse_tool",
            "note": "",
        }
        for i in range(4)
    ]
    captured = {}

    class _Store:
        def list(self, *, status=None, limit=50):
            captured["limit"] = limit
            return rows[:limit]

    monkeypatch.setattr(undo_tools, "get_undo_store", lambda: _Store())
    result = undo_tools.undo_list(limit=3)
    assert captured["limit"] == 4, "one extra row is fetched to measure truncation"
    assert result["returned"] == 3
    assert result["limit"] == 3
    assert result["truncated"] is True
    assert len(result["undos"]) == 3
