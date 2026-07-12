"""Audit-source listing + cross-tool event query + activity timeline (read-only)."""

from __future__ import annotations

from typing import Any

from compliance_aiops.frameworks import SELECTORS
from compliance_aiops.ops._util import norm_event, s


def list_sources(reader: Any) -> list[dict]:
    """[READ] Configured audit sources with readability + row counts."""
    return reader.sources_status()


def query_events(
    reader: Any, source: str | None = None, skill: str | None = None,
    tool: str | None = None, status: str | None = None, risk_level: str | None = None,
    approved: bool | None = None, selector: str | None = None,
    since: str | None = None, until: str | None = None, limit: int = 100,
) -> dict:
    """[READ] Cross-tool audit event query (the workhorse).

    ``selector`` (audit_trail / attribution / change / enforcement / exception)
    applies a compliance evidence-class filter on top of the field filters.
    """
    rows = reader.query(source=source, skill=skill, tool=tool, status=status,
                        risk_level=risk_level, approved=approved,
                        since=since, until=until, limit=max(limit, 1))
    if selector:
        sel = SELECTORS.get(selector)
        if sel is None:
            raise ValueError(f"Unknown selector '{selector}'. Options: {', '.join(SELECTORS)}.")
        rows = [r for r in rows if sel(r)]
    return {"count": len(rows), "events": [norm_event(r) for r in rows[:limit]]}


def activity_timeline(reader: Any, since: str | None = None, until: str | None = None,
                      bucket: str = "day") -> dict:
    """[READ] Op counts bucketed by hour or day — the monitoring-continuity view."""
    if bucket not in ("hour", "day"):
        raise ValueError("bucket must be 'hour' or 'day'.")
    rows = reader.query(since=since, until=until, limit=100_000)
    width = 13 if bucket == "hour" else 10  # ISO prefix: YYYY-MM-DDTHH / YYYY-MM-DD
    buckets: dict[str, int] = {}
    for r in rows:
        key = s(r.get("ts"), 40)[:width]
        if key:
            buckets[key] = buckets.get(key, 0) + 1
    series = [{"bucket": k, "count": v} for k, v in sorted(buckets.items())]
    return {"bucket": bucket, "total": len(rows), "series": series}
