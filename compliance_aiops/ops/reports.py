"""Approval trail and exceptions reports (read-only).

``approval_report`` is the who/what/when/why/approval artifact auditors most
request for change-management (SOC2 CC8.1), least-privilege (PCI 7-8), and access
control (HIPAA §164.312(a)). ``exceptions_report`` surfaces denied / errored /
budget-tripped ops — the enforcement + anomaly evidence auditors *want* to see
(denials prove the control actually blocks, not rubber-stamps).
"""

from __future__ import annotations

from typing import Any

from compliance_aiops.ops._util import (
    EXCEPTION_STATUSES,
    is_approved,
    is_high_risk,
    is_write,
    norm_event,
)


def approval_report(reader: Any, since: str | None = None, until: str | None = None,
                    high_only: bool = True) -> dict:
    """[READ] High-risk write ops with their approver + rationale (approval trail)."""
    events = reader.query(since=since, until=until, limit=100_000)
    ops = [e for e in events if is_write(e) and (is_high_risk(e) if high_only else True)]
    approved = [e for e in ops if is_approved(e)]
    unapproved = [e for e in ops if not is_approved(e)]
    return {
        "period": {"since": since, "until": until},
        "highOnly": high_only,
        "totalWriteOps": len(ops),
        "approved": len(approved),
        "unapproved": len(unapproved),
        "unapprovedOps": [norm_event(e) for e in unapproved[:100]],
        "ops": [norm_event(e) for e in ops[:200]],
    }


def exceptions_report(reader: Any, since: str | None = None,
                      until: str | None = None) -> dict:
    """[READ] Denied / error / budget-exceeded ops (enforcement + anomaly evidence)."""
    events = reader.query(since=since, until=until, limit=100_000)
    hits = [e for e in events if (e.get("status") or "").lower() in EXCEPTION_STATUSES]
    by_status: dict[str, int] = {}
    for e in hits:
        st = (e.get("status") or "").lower()
        by_status[st] = by_status.get(st, 0) + 1
    return {
        "period": {"since": since, "until": until},
        "total": len(hits),
        "byStatus": dict(sorted(by_status.items(), key=lambda kv: kv[1], reverse=True)),
        "events": [norm_event(e) for e in hits[:200]],
    }
