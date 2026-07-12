"""Approval-trail + exceptions MCP tools (read-only)."""

from typing import Optional

from compliance_aiops.governance import governed_tool
from compliance_aiops.ops import reports as ops
from mcp_server._shared import _get_reader, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def approval_report(
    since: Optional[str] = None, until: Optional[str] = None, high_only: bool = True
) -> dict:
    """[READ] High-risk write ops with approver + rationale (the change-approval trail).

    The who/what/when/why/approval artifact for SOC 2 CC8.1, PCI 7-8, HIPAA §312(a).

    Args:
        since / until: ISO timestamps bounding the period.
        high_only: True = only high/critical-risk writes (default); False = all writes.
    """
    return ops.approval_report(_get_reader(), since, until, high_only)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def exceptions_report(since: Optional[str] = None, until: Optional[str] = None) -> dict:
    """[READ] Denied / error / budget-exceeded ops — enforcement + anomaly evidence.

    Denials prove the governance controls actually block, not rubber-stamp.

    Args:
        since / until: ISO timestamps bounding the period.
    """
    return ops.exceptions_report(_get_reader(), since, until)
