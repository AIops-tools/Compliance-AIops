"""Framework → control → evidence mapping (HIPAA / PCI-DSS / SOC 2 / GDPR).

The audit row is the atomic evidence unit. Each :class:`Control` names a
**selector** — which audit events count as evidence for it — and an honest
**strength**: infra-ops audit trails prove *operating effectiveness* ("the
control ran, here are the samples") strongly, but prove *design / configuration*
("MFA is required", "roles are least-privilege") only partially. ``gap_analysis``
surfaces that caveat per control rather than overclaiming.

This module is a frozen data table + pure selector functions — no I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from compliance_aiops.ops._util import (
    is_approved,
    is_enforced,
    is_high_risk,
    is_write,
)

# ── selectors: does an audit event count as evidence for a control class? ──


def _sel_audit_trail(e: dict) -> bool:
    """Any recorded op — evidence the audit mechanism exists and is populated."""
    return True


def _sel_attribution(e: dict) -> bool:
    """Op carries actor attribution (a user or an agent identity)."""
    return bool((e.get("user") or "").strip()) or bool((e.get("agent") or "").strip())


def _sel_change(e: dict) -> bool:
    """A state-changing (write) op — the population for change-management review."""
    return is_write(e)


def _sel_enforcement(e: dict) -> bool:
    """The governance layer blocked an op (policy / budget) — access enforcement."""
    return is_enforced(e)


def _sel_exception(e: dict) -> bool:
    """A denied / errored / budget-tripped op — monitoring / anomaly evidence."""
    st = (e.get("status") or "").lower()
    return st in ("denied", "error", "budget_exceeded")


SELECTORS: dict[str, Callable[[dict], bool]] = {
    "audit_trail": _sel_audit_trail,
    "attribution": _sel_attribution,
    "change": _sel_change,
    "enforcement": _sel_enforcement,
    "exception": _sel_exception,
    "integrity": _sel_audit_trail,  # coverage judged by chain verification, not count
}


@dataclass(frozen=True)
class Control:
    framework: str
    control_id: str
    title: str
    requirement: str
    selector: str
    strength: str  # "strong" | "partial"
    caveat: str = ""


# ── the catalog ────────────────────────────────────────────────────────────

_CONTROLS: tuple[Control, ...] = (
    # HIPAA Security Rule §164.312
    Control("hipaa", "164.312(b)", "Audit controls",
            "Record and examine activity in systems containing ePHI.",
            "audit_trail", "strong"),
    Control("hipaa", "164.312(a)(1)", "Access control",
            "Allow access only to authorized persons/software; unique user ID.",
            "attribution", "strong",
            "Proves per-op actor attribution and access-enforcement events; does "
            "NOT evidence IAM provisioning/least-privilege config."),
    Control("hipaa", "164.312(c)(1)", "Integrity",
            "Protect ePHI from improper alteration or destruction.",
            "change", "strong",
            "Covers ops-integrity (approval on write ops) + log integrity (hash "
            "chain). Does not cover application-level data validation."),
    # PCI-DSS v4.0
    Control("pci_dss", "10.2", "Audit log content",
            "Log user, event type, date/time, success/failure, source, resource.",
            "audit_trail", "strong"),
    Control("pci_dss", "10.3", "Protect audit logs",
            "Protect logs from modification; verify integrity.",
            "integrity", "strong"),
    Control("pci_dss", "7-8", "Least privilege / authentication",
            "Restrict access by need-to-know; individual accounts on privileged ops.",
            "change", "partial",
            "Evidences approval-gating + denials on privileged ops; does NOT "
            "evidence the RBAC/MFA configuration itself."),
    # SOC 2 Trust Services Criteria
    Control("soc2", "CC6.1", "Logical access controls",
            "Restrict logical access to authorized users; least privilege.",
            "enforcement", "strong",
            "Denials/blocks demonstrate operating effectiveness; design of the "
            "access model is out of scope for an audit trail."),
    Control("soc2", "CC7.2", "Monitoring for anomalies",
            "Detect and evaluate anomalies and security events.",
            "exception", "strong"),
    Control("soc2", "CC8.1", "Change management",
            "Authorize, approve, and track changes.",
            "change", "strong",
            "approved_by + risk_tier + rationale on write ops are the change-"
            "approval samples; assumes the approval gate is configured."),
    # GDPR
    Control("gdpr", "Art.30", "Records of processing activities",
            "Maintain a record of processing activities (what/who/when).",
            "attribution", "partial",
            "Supplements the ROPA with a per-op processing log; does not replace "
            "the legal register."),
    Control("gdpr", "Art.32", "Security of processing",
            "Ensure ongoing confidentiality/integrity; test measures regularly.",
            "integrity", "strong",
            "Redacted params (confidentiality) + hash chain (integrity) + "
            "verify_chain (regular testing) cover the technical-measures half."),
)

FRAMEWORKS = ("hipaa", "pci_dss", "soc2", "gdpr")
FRAMEWORK_TITLES = {
    "hipaa": "HIPAA Security Rule (§164.312)",
    "pci_dss": "PCI-DSS v4.0",
    "soc2": "SOC 2 Trust Services Criteria",
    "gdpr": "GDPR (Art. 30 / 32)",
}


def controls_for(framework: str) -> list[Control]:
    fw = framework.lower()
    if fw not in FRAMEWORKS:
        raise ValueError(
            f"Unknown framework '{framework}'. Choose one of: {', '.join(FRAMEWORKS)}."
        )
    return [c for c in _CONTROLS if c.framework == fw]


def get_control(framework: str, control_id: str) -> Control:
    for c in controls_for(framework):
        if c.control_id == control_id:
            return c
    raise KeyError(f"Control '{control_id}' not found in {framework}.")


def evidence_for(control: Control, events: list[dict]) -> list[dict]:
    """Filter events to those that count as evidence for one control."""
    sel = SELECTORS[control.selector]
    return [e for e in events if sel(e)]


def unapproved_writes(events: list[dict]) -> list[dict]:
    """High-risk write ops lacking an approver — the CC8.1 / §312(c) gap signal."""
    return [e for e in events if is_high_risk(e) and is_write(e) and not is_approved(e)]
