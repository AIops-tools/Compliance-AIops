"""``compliance-aiops bundle`` — generate / verify / list / export evidence bundles."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from compliance_aiops.cli._common import cli_errors, console, get_reader

bundle_app = typer.Typer(
    name="bundle",
    help="Evidence bundles: generate, verify, list, export.",
    no_args_is_help=True,
)

FwArg = Annotated[
    str,
    typer.Argument(help="Framework: hipaa / pci_dss / soc2 / gdpr / iso27001 / djcp_l3"),
]
PathArg = Annotated[str, typer.Argument(help="Path to a bundle .json")]
PeriodOpt = Annotated[
    str | None,
    typer.Option("--period", help="Relative window, e.g. 7d / 24h / 2w / last-7-days"),
]


@bundle_app.command("generate")
@cli_errors
def bundle_generate(
    framework: FwArg,
    since: Annotated[str | None, typer.Option("--since", help="ISO start")] = None,
    until: Annotated[str | None, typer.Option("--until", help="ISO end")] = None,
    period: PeriodOpt = None,
    sign: Annotated[bool, typer.Option("--sign", help="Sign with the stored key")] = False,
) -> None:
    """Assemble + hash-chain-seal an evidence bundle for a framework/period.

    Use --since/--until for an explicit window, or --period for a convenience
    relative window (e.g. --period 7d for the last 7 days).
    """
    from compliance_aiops.ops import bundle as ops

    reader, cfg = get_reader()
    console.print_json(json.dumps(
        ops.generate_evidence_bundle(reader, cfg, framework,
                                     period_start=since, period_end=until,
                                     sign=sign, period=period)))


@bundle_app.command("schedule")
@cli_errors
def bundle_schedule(
    framework: FwArg,
    cron: Annotated[
        str, typer.Option("--cron", help="5-field cron expression")
    ] = "0 2 * * 1",
    period: Annotated[
        str, typer.Option("--period", help="Relative window for each run, e.g. 7d")
    ] = "7d",
    sign: Annotated[bool, typer.Option("--sign", help="Include --sign in the command")] = False,
) -> None:
    """Print a ready-to-paste cron line for periodic sealed-bundle generation.

    WRITES NOTHING and starts no daemon — it only composes the crontab line and
    the exact non-interactive command. Paste the printed cronLine into `crontab -e`.
    """
    from compliance_aiops.ops import bundle as ops

    console.print_json(json.dumps(
        ops.bundle_schedule_hint(framework, cron=cron, period=period, sign=sign)))


@bundle_app.command("verify")
@cli_errors
def bundle_verify(bundle_path: PathArg) -> None:
    """Verify a sealed bundle's hash chain + seal head + signature."""
    from compliance_aiops.ops import integrity as ops

    console.print_json(json.dumps(ops.verify_bundle(bundle_path)))


@bundle_app.command("list")
@cli_errors
def bundle_list() -> None:
    """List previously generated bundles + their chain head."""
    from compliance_aiops.ops import bundle as ops

    _, cfg = get_reader()
    console.print_json(json.dumps(ops.list_bundles(cfg)))


@bundle_app.command("export")
@cli_errors
def bundle_export(
    bundle_path: PathArg,
    fmt: Annotated[str, typer.Option("--format", help="markdown / csv / json")] = "markdown",
) -> None:
    """Render a bundle to markdown / csv / json."""
    from compliance_aiops.ops import bundle as ops

    console.print_json(json.dumps(ops.export_bundle(bundle_path, fmt=fmt)))
