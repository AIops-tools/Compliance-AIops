"""Evidence-bundle generation / signing / export MCP tools (governed artifacts).

These write a LOCAL bundle file only — they never touch external infrastructure —
so they are low risk (sign_bundle is medium: it reads the encrypted signing key).
"""

from typing import Optional

from compliance_aiops.governance import governed_tool
from compliance_aiops.ops import bundle as ops
from mcp_server._shared import _get_config, _get_reader, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def generate_evidence_bundle(
    framework: str, period_start: Optional[str] = None, period_end: Optional[str] = None,
    out_path: Optional[str] = None, sign: bool = False,
) -> dict:
    """[WRITE][risk=low] Assemble + hash-chain-seal an evidence bundle for a framework.

    One-call happy path: coverage + approval trail + exceptions + sealed evidence
    records → a bundle .json under ~/.compliance-aiops/bundles/. Reads audit DBs
    and writes a local artifact only; touches no external system.

    Args:
        framework: hipaa / pci_dss / soc2 / gdpr.
        period_start / period_end: ISO timestamps bounding the reporting period.
        out_path: Where to write the bundle (default: the bundle dir).
        sign: If True and a signing key is stored, attach an HMAC signature.
    """
    return ops.generate_evidence_bundle(
        _get_reader(), _get_config(), framework,
        period_start=period_start, period_end=period_end, out_path=out_path, sign=sign)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def sign_bundle(bundle_path: str) -> dict:
    """[WRITE][risk=medium] Attach an HMAC signature over a bundle's seal (uses stored key).

    Requires a signing key in the encrypted store ('compliance-aiops secret set
    signing-key'). Medium risk because it reads the encrypted secret store.

    Args:
        bundle_path: Path to a bundle .json.
    """
    return ops.sign_bundle(_get_config(), bundle_path)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def export_bundle(bundle_path: str, fmt: str = "markdown", out_path: Optional[str] = None) -> dict:
    """[WRITE][risk=low] Render a bundle to markdown / csv / json.

    Args:
        bundle_path: Path to a bundle .json.
        fmt: "markdown", "csv", or "json".
        out_path: Output path (default: alongside the bundle).
    """
    return ops.export_bundle(bundle_path, fmt=fmt, out_path=out_path)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_bundles() -> list:
    """[READ] Previously generated bundles + their chain head and metadata."""
    return ops.list_bundles(_get_config())
