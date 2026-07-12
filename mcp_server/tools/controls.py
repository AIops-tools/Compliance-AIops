"""Framework coverage / evidence / gap-analysis MCP tools (read-only)."""

from typing import Optional

from compliance_aiops.governance import governed_tool
from compliance_aiops.ops import controls as ops
from mcp_server._shared import _get_reader, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_frameworks() -> list:
    """[READ] Supported compliance frameworks (HIPAA / PCI-DSS / SOC 2 / GDPR) + control counts."""
    return ops.list_frameworks()


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def coverage_summary(
    framework: str, since: Optional[str] = None, until: Optional[str] = None
) -> dict:
    """[READ] Per-control coverage for a framework over a period (are we covered?).

    Args:
        framework: hipaa / pci_dss / soc2 / gdpr.
        since / until: ISO timestamps bounding the reporting period.
    """
    return ops.coverage_summary(_get_reader(), framework, since, until)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def control_evidence(
    framework: str, control_id: str, since: Optional[str] = None,
    until: Optional[str] = None, sample_size: int = 20,
) -> dict:
    """[READ] Evidence rows for ONE control + population size + reproducible query.

    Args:
        framework: hipaa / pci_dss / soc2 / gdpr.
        control_id: e.g. "164.312(b)", "10.2", "CC8.1", "Art.30".
        since / until: ISO timestamps bounding the period.
        sample_size: Number of representative evidence rows to include.
    """
    return ops.control_evidence(_get_reader(), framework, control_id, since, until, sample_size)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def gap_analysis(
    framework: str, since: Optional[str] = None, until: Optional[str] = None
) -> dict:
    """[READ] Controls with no/weak evidence, each with an honest reason + remediation.

    States the design-vs-operating caveat: audit trails evidence operating
    effectiveness strongly and control design/configuration only partially.

    Args:
        framework: hipaa / pci_dss / soc2 / gdpr.
        since / until: ISO timestamps bounding the period.
    """
    return ops.gap_analysis(_get_reader(), framework, since, until)
