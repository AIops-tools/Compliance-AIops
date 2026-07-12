"""``compliance-aiops overview`` — one-shot compliance posture."""

from __future__ import annotations

import json

from compliance_aiops.cli._common import cli_errors, console, get_reader


@cli_errors
def overview_cmd() -> None:
    """One-shot posture: audit sources + per-framework covered/total control counts."""
    from compliance_aiops.ops import overview as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.posture_overview(reader)))
