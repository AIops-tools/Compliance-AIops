"""CLI package for compliance-aiops.

Re-exports ``app`` so the pyproject entry point
``compliance-aiops = "compliance_aiops.cli:app"`` works unchanged.
"""

from compliance_aiops.cli._root import app

__all__ = ["app"]
