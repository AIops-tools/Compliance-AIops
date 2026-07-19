"""Shared helpers for Compliance ops modules.

Normalises raw ``audit_log`` rows into a stable evidence shape and sanitises all
audit-sourced text (tool names, rationale, approver) before it reaches the agent
or a bundle — the audit trail is data produced by other tools, so treat it as
untrusted and pass it through the output-hygiene sanitizer.
"""

from __future__ import annotations

from typing import Any

from compliance_aiops.governance import opt_str, sanitize

# Statuses where the governance layer BLOCKED an action — evidence that policy /
# approval / budget enforcement is actually operative (not merely logged).
ENFORCEMENT_STATUSES = ("denied", "budget_exceeded")
EXCEPTION_STATUSES = ("denied", "error", "budget_exceeded")
# risk_level values that denote a state-changing (write) operation.
WRITE_RISK_LEVELS = ("medium", "high", "critical")
HIGH_RISK_LEVELS = ("high", "critical")


def s(value: Any, limit: int = 512) -> str:
    """Sanitize an arbitrary value to a bounded, injection-safe string."""
    return sanitize(str(value if value is not None else ""), limit)


def opt_s(value: Any, limit: int = 512) -> str | None:
    """Sanitize a value that may legitimately be absent, preserving that absence.

    Companion to :func:`s`, which folds ``None`` into ``""``. In evidence that
    conflation is not cosmetic: ``"approvedBy": ""`` reads as "an approver field
    exists and is blank", while the truth may be "no approver was ever recorded
    for this operation". Those are different findings for an auditor, and a
    smaller local model asked to summarise the trail will pick whichever reads
    more fluently. Absence stays ``null``; a genuinely empty recorded value
    stays ``""``.

    Use this for any optional audit column; keep :func:`s` for the columns the
    governance harness always writes, and for values fed to ``.lower()``.
    """
    return opt_str(value, limit)


def norm_event(row: dict) -> dict:
    """Fold a raw audit row into the stable evidence shape.

    Columns the harness always writes stay strings; the optional ones — the
    attribution and justification fields an auditor reads most closely — keep
    their absence as ``null`` rather than reporting a blank that was never there.
    """
    return {
        "id": row.get("id"),
        "source": s(row.get("source"), 64),
        "environment": opt_s(row.get("environment"), 64),
        "ts": s(row.get("ts"), 40),
        "skill": s(row.get("skill"), 64),
        "tool": s(row.get("tool"), 96),
        "status": s(row.get("status"), 32),
        "riskLevel": s(row.get("risk_level"), 16),
        "riskTier": opt_s(row.get("risk_tier"), 32),
        "agent": opt_s(row.get("agent"), 32),
        "user": opt_s(row.get("user"), 64),
        "approvedBy": opt_s(row.get("approved_by"), 96),
        "rationale": opt_s(row.get("rationale"), 256),
    }


def is_write(row: dict) -> bool:
    """A state-changing op (risk >= medium)."""
    return s(row.get("risk_level"), 16).lower() in WRITE_RISK_LEVELS


def is_high_risk(row: dict) -> bool:
    return s(row.get("risk_level"), 16).lower() in HIGH_RISK_LEVELS


def is_enforced(row: dict) -> bool:
    """Governance blocked this call (policy / budget) — enforcement evidence."""
    return s(row.get("status"), 32).lower() in ENFORCEMENT_STATUSES


def is_approved(row: dict) -> bool:
    return bool(s(row.get("approved_by"), 96).strip())


#: Cap on rows scanned per report so a huge trail cannot OOM a summary.
SCAN_LIMIT = 100_000


def scan(reader: Any, **filters: Any) -> tuple[list[dict], bool]:
    """Fetch the event population for a report, measuring whether it was capped.

    Returns ``(rows, truncated)``. One row past :data:`SCAN_LIMIT` is requested
    so ``truncated`` is measured rather than inferred from the count happening
    to land exactly on the cap. Every report that calls this surfaces the flag:
    a coverage percentage or gap finding computed over a silently truncated
    population is not evidence, and an agent cannot tell the difference unless
    the payload says so.
    """
    rows = reader.query(limit=SCAN_LIMIT + 1, **filters)
    if len(rows) > SCAN_LIMIT:
        return rows[:SCAN_LIMIT], True
    return rows, False
