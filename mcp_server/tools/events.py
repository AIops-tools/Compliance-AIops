"""Audit-source + event-query MCP tools (read-only)."""

from typing import Optional

from compliance_aiops.governance import governed_tool
from compliance_aiops.ops import events as ops
from mcp_server._shared import _get_reader, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_audit_sources() -> list:
    """[READ] List sibling audit DBs (~/.<tool>-aiops/audit.db) + readability/row counts.

    Call this first to see which governed AIops tools' trails are available as
    compliance evidence.
    """
    return ops.list_sources(_get_reader())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def query_audit_events(
    source: Optional[str] = None, skill: Optional[str] = None, tool: Optional[str] = None,
    status: Optional[str] = None, risk_level: Optional[str] = None,
    approved: Optional[bool] = None, selector: Optional[str] = None,
    since: Optional[str] = None, until: Optional[str] = None, limit: int = 100,
) -> dict:
    """[READ] Cross-tool audit event query — the workhorse.

    Args:
        source: Restrict to one source tool (e.g. nutanix-aiops).
        skill / tool / status / risk_level: Field filters.
        approved: True = only ops with an approver; False = only ops without one.
        selector: Evidence class filter — audit_trail / attribution / change /
            enforcement / exception.
        since / until: ISO timestamps bounding the period.
        limit: Max rows to return.
    """
    return ops.query_events(_get_reader(), source=source, skill=skill, tool=tool,
                            status=status, risk_level=risk_level, approved=approved,
                            selector=selector, since=since, until=until, limit=limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def activity_timeline(
    since: Optional[str] = None, until: Optional[str] = None, bucket: str = "day"
) -> dict:
    """[READ] Op counts bucketed by hour/day — monitoring-continuity evidence.

    Args:
        since / until: ISO timestamps bounding the period.
        bucket: "hour" or "day".
    """
    return ops.activity_timeline(_get_reader(), since=since, until=until, bucket=bucket)
