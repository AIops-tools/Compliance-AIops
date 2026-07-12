"""One-shot compliance posture overview (read-only).

Folds audit-source availability + per-framework coverage into one summary an
agent can call first. Resilient — a failing sub-call degrades to a partial
summary with an ``errors`` list.
"""

from __future__ import annotations

from typing import Any

from compliance_aiops import frameworks as fw
from compliance_aiops.ops import controls as controls_ops


def posture_overview(reader: Any, since: str | None = None,
                     until: str | None = None) -> dict:
    """[READ] Audit sources + per-framework covered/total control counts."""
    errors: list[str] = []
    sources = reader.sources_status()
    readable = sum(1 for s in sources if s.get("readable"))

    frameworks: list[dict] = []
    for f in fw.FRAMEWORKS:
        try:
            cov = controls_ops.coverage_summary(reader, f, since, until)
            frameworks.append({
                "framework": f, "title": fw.FRAMEWORK_TITLES[f],
                "covered": cov["controlsCovered"], "total": cov["controlsTotal"],
            })
        except Exception as exc:  # noqa: BLE001 — collect, keep going
            errors.append(f"{f}: {str(exc)[:120]}")

    return {
        "auditSources": len(sources),
        "readableSources": readable,
        "period": {"since": since, "until": until},
        "frameworks": frameworks,
        "errors": errors,
    }
