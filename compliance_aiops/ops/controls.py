"""Control coverage, per-control evidence, and gap analysis (read-only).

Maps the audit-event population to framework controls (see
:mod:`compliance_aiops.frameworks`) and reports coverage honestly: a control is
only "covered" when the trail actually contains its evidence, and change-approval
controls are flagged when high-risk writes lack an approver — the exact gap an
auditor probes. Every finding carries the design-vs-operating caveat.
"""

from __future__ import annotations

from typing import Any

from compliance_aiops import frameworks as fw
from compliance_aiops.ops._util import SCAN_LIMIT, norm_event, s, scan


def _events(reader: Any, since: str | None, until: str | None) -> tuple[list[dict], bool]:
    """The event population for a report, plus whether the scan hit its cap.

    A coverage percentage computed over a silently truncated population is not
    evidence — so the flag travels with the numbers into every report below.
    """
    return scan(reader, since=since, until=until)


def coverage_summary(reader: Any, framework: str, since: str | None = None,
                     until: str | None = None) -> dict:
    """[READ] Per-control coverage for one framework over a period."""
    controls = fw.controls_for(framework)
    events, scan_truncated = _events(reader, since, until)
    unapproved = fw.unapproved_writes(events)
    rows: list[dict] = []
    covered_count = 0
    for c in controls:
        evidence = fw.evidence_for(c, events)
        gap = _gap_reason(c, evidence, unapproved)
        covered = not gap and bool(evidence)
        covered_count += int(covered)
        rows.append({
            "controlId": c.control_id,
            "title": c.title,
            "strength": c.strength,
            "evidenceCount": len(evidence),
            "covered": covered,
            "gap": gap or None,
            "caveat": c.caveat or None,
        })
    return {
        "framework": framework.lower(),
        "frameworkTitle": fw.FRAMEWORK_TITLES.get(framework.lower(), framework),
        "period": {"since": since, "until": until},
        "controlsTotal": len(controls),
        "controlsCovered": covered_count,
        "eventsScanned": len(events),
        "scanLimit": SCAN_LIMIT,
        "scanTruncated": scan_truncated,
        "controls": rows,
    }


def _gap_reason(control: fw.Control, evidence: list[dict], unapproved: list[dict]) -> str:
    """Return a human gap reason for a control, or '' if adequately covered."""
    if not evidence:
        return "No matching evidence in the audit trail for this period."
    if control.selector == "change" and unapproved:
        return (f"{len(unapproved)} high-risk write op(s) recorded without an "
                f"approver (approved_by empty) — change-approval gap.")
    return ""


def control_evidence(reader: Any, framework: str, control_id: str,
                     since: str | None = None, until: str | None = None,
                     sample_size: int = 20) -> dict:
    """[READ] Evidence rows for ONE control + population size + reproducible query."""
    control = fw.get_control(framework, control_id)
    events, scan_truncated = _events(reader, since, until)
    evidence = fw.evidence_for(control, events)
    requested = max(int(sample_size), 1)
    return {
        "framework": framework.lower(),
        "controlId": control.control_id,
        "title": control.title,
        "requirement": control.requirement,
        "strength": control.strength,
        "caveat": control.caveat or None,
        "selector": control.selector,
        "populationSize": len(evidence),
        "sample": [norm_event(e) for e in evidence[:requested]],
        "returned": min(len(evidence), requested),
        "limit": requested,
        "truncated": len(evidence) > requested,
        "scanLimit": SCAN_LIMIT,
        "scanTruncated": scan_truncated,
        "reproduceWith": f"query_audit_events(selector='{control.selector}', "
                         f"since={since!r}, until={until!r})",
    }


def gap_analysis(reader: Any, framework: str, since: str | None = None,
                 until: str | None = None) -> dict:
    """[READ] Controls with no/weak evidence, each with an honest reason + caveat."""
    controls = fw.controls_for(framework)
    events, scan_truncated = _events(reader, since, until)
    unapproved = fw.unapproved_writes(events)
    gaps: list[dict] = []
    for c in controls:
        evidence = fw.evidence_for(c, events)
        reason = _gap_reason(c, evidence, unapproved)
        if reason or c.strength == "partial":
            gaps.append({
                "controlId": c.control_id,
                "title": c.title,
                "strength": c.strength,
                "reason": reason or "Evidence present but strength is PARTIAL.",
                "caveat": c.caveat or None,
                "remediation": _remediation(c, reason),
            })
    _partial = "Evidence present but strength is PARTIAL."
    return {
        "framework": framework.lower(),
        "period": {"since": since, "until": until},
        "gapCount": sum(1 for g in gaps if g["reason"] != _partial),
        "partialCount": sum(1 for g in gaps if "PARTIAL" in g["reason"]),
        "findings": gaps,
        "scanLimit": SCAN_LIMIT,
        "scanTruncated": scan_truncated,
        "note": "Audit trails evidence OPERATING effectiveness strongly and control "
                "DESIGN/configuration only partially — pair partial controls with "
                "config/policy evidence from your GRC system.",
    }


def _remediation(control: fw.Control, reason: str) -> str:
    if "without an approver" in reason:
        return ("Require an approver on high-risk ops: have operators pass "
                "<TOOL>_AUDIT_APPROVED_BY on high/critical writes.")
    if "No matching evidence" in reason:
        return "Run governed ops in this period, or widen the reporting window."
    return "Supplement with control-design evidence (config/policy) from your GRC system."


def list_frameworks() -> list[dict]:
    """[READ] The supported frameworks and their control counts."""
    return [{"framework": f, "title": fw.FRAMEWORK_TITLES[f],
             "controls": len(fw.controls_for(f))} for f in fw.FRAMEWORKS]


def _title(framework: str) -> str:
    return s(fw.FRAMEWORK_TITLES.get(framework.lower(), framework), 128)
