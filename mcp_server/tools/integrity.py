"""Hash-chain integrity MCP tools (read-only)."""

from typing import Optional

from compliance_aiops.governance import governed_tool
from compliance_aiops.ops import integrity as ops
from mcp_server._shared import _get_reader, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def verify_source_chain(
    source: str, since: Optional[str] = None, until: Optional[str] = None
) -> dict:
    """[READ] Chain head for a source's current events + row-id gap detection.

    Record the returned chainHead out-of-band; re-run later to detect changes.
    Row-id gaps may indicate deleted audit rows.

    Args:
        source: Source tool name (from list_audit_sources).
        since / until: ISO timestamps bounding the range.
    """
    return ops.verify_source_chain(_get_reader(), source, since, until)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def verify_bundle(bundle_path: str) -> dict:
    """[READ] Verify a sealed evidence bundle: chain integrity, seal head, signature.

    Args:
        bundle_path: Path to a bundle .json produced by generate_evidence_bundle.
    """
    return ops.verify_bundle(bundle_path)
