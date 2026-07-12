"""Read-only reader over sibling AIops audit databases.

This is the compliance-aiops analog of the platform tools' "connection": instead
of an httpx client to a remote API, it opens each configured ``audit.db``
**read-only** (SQLite ``mode=ro``) and unions their ``audit_log`` rows into one
stream, tagging every row with its ``source`` tool. It never writes to a source
DB — evidence is derived, the originals are left untouched.

Resilient: a missing, locked, or corrupt source is skipped with a warning rather
than failing the whole query (an auditor still gets evidence from the readable
sources, plus a clear note that one was unreadable via ``sources_status``).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from compliance_aiops.config import AppConfig, AuditSource, load_config

_log = logging.getLogger("compliance-aiops.reader")

# The vendored governance audit schema (shared across the whole tool line).
AUDIT_COLUMNS = (
    "id", "ts", "skill", "tool", "params", "result", "status", "duration_ms",
    "agent", "workflow_id", "user", "risk_level", "rationale", "approved_by", "risk_tier",
)


class ComplianceError(Exception):
    """A compliance-aiops operation failed; carries a teaching message."""


def _connect_ro(path: str) -> sqlite3.Connection:
    """Open a SQLite DB strictly read-only (never creates or writes)."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


class AuditReader:
    """Unions the ``audit_log`` tables of several read-only audit DBs."""

    def __init__(self, sources: list[AuditSource]) -> None:
        self._sources = list(sources)

    @property
    def sources(self) -> list[AuditSource]:
        return self._sources

    def _query_one(self, source: AuditSource, where: str, values: list[Any],
                   limit: int) -> list[dict]:
        if not source.exists:
            _log.warning("Audit source '%s' missing at %s", source.name, source.path)
            return []
        try:
            conn = _connect_ro(str(source.path))
        except sqlite3.Error as exc:
            _log.warning("Cannot open audit source '%s': %s", source.name, exc)
            return []
        try:
            # `where` is built only from hardcoded "col = ?" fragments below; every
            # user value is a bound parameter. No user text is interpolated.
            sql = f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?"  # nosec B608
            rows = conn.execute(sql, [*values, limit]).fetchall()
        except sqlite3.Error as exc:
            _log.warning("Query failed on source '%s': %s", source.name, exc)
            return []
        finally:
            conn.close()
        out = []
        for r in rows:
            row = dict(r)
            row["source"] = source.name
            row["environment"] = source.environment
            out.append(row)
        return out

    def query(
        self,
        *,
        source: str | None = None,
        skill: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        risk_level: str | None = None,
        approved: bool | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 500,
    ) -> list[dict]:
        """Union audit rows across sources (newest first), applying filters.

        ``approved=True`` keeps only rows with a non-empty ``approved_by``;
        ``approved=False`` keeps only rows without one. ``since``/``until`` are
        ISO timestamps compared against ``ts``.
        """
        clauses: list[str] = []
        values: list[Any] = []
        for col, val in (("skill", skill), ("tool", tool), ("status", status),
                         ("risk_level", risk_level)):
            if val is not None:
                clauses.append(f"{col} = ?")
                values.append(val)
        if since is not None:
            clauses.append("ts >= ?")
            values.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            values.append(until)
        if approved is True:
            clauses.append("approved_by <> ''")
        elif approved is False:
            clauses.append("approved_by = ''")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        selected = [s for s in self._sources if source is None or s.name == source]
        rows: list[dict] = []
        for src_ in selected:
            rows.extend(self._query_one(src_, where, values, limit))
        rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
        return rows[:limit]

    def ordered_ids(self, source: str) -> list[int]:
        """Return a source's audit-row ids in ascending order (for gap detection)."""
        src_ = next((s for s in self._sources if s.name == source), None)
        if src_ is None or not src_.exists:
            return []
        try:
            conn = _connect_ro(str(src_.path))
        except sqlite3.Error:
            return []
        try:
            return [int(r["id"]) for r in conn.execute("SELECT id FROM audit_log ORDER BY id")]
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def sources_status(self) -> list[dict]:
        """Per-source readability + row count (for doctor / list_sources)."""
        out = []
        for s in self._sources:
            readable, count = False, None
            if s.exists:
                try:
                    conn = _connect_ro(str(s.path))
                    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                    conn.close()
                    readable = True
                except sqlite3.Error:
                    readable = False
            out.append({"name": s.name, "path": str(s.path), "exists": s.exists,
                        "readable": readable, "rowCount": count,
                        "environment": s.environment})
        return out


def get_reader(config: AppConfig | None = None) -> AuditReader:
    """Build an AuditReader from config (auto-discovers sources if none configured)."""
    cfg = config or load_config()
    return AuditReader(list(cfg.sources))
