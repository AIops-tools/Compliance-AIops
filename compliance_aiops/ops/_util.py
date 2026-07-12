"""Shared helpers for Compliance ops modules.

Normalises raw ``audit_log`` rows into a stable evidence shape and sanitises all
audit-sourced text (tool names, rationale, approver) before it reaches the agent
or a bundle — the audit trail is data produced by other tools, so treat it as
untrusted per the prompt-injection defense.
"""

from __future__ import annotations

from typing import Any

from compliance_aiops.governance import sanitize

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


def norm_event(row: dict) -> dict:
    """Fold a raw audit row into the stable evidence shape."""
    return {
        "id": row.get("id"),
        "source": s(row.get("source"), 64),
        "environment": s(row.get("environment"), 64),
        "ts": s(row.get("ts"), 40),
        "skill": s(row.get("skill"), 64),
        "tool": s(row.get("tool"), 96),
        "status": s(row.get("status"), 32),
        "riskLevel": s(row.get("risk_level"), 16),
        "riskTier": s(row.get("risk_tier"), 32),
        "agent": s(row.get("agent"), 32),
        "user": s(row.get("user"), 64),
        "approvedBy": s(row.get("approved_by"), 96),
        "rationale": s(row.get("rationale"), 256),
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
