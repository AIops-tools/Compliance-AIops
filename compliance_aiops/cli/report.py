"""``compliance-aiops report`` — coverage / gaps / approval / exceptions reads."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from compliance_aiops.cli._common import TargetOption, cli_errors, console, get_reader

report_app = typer.Typer(
    name="report",
    help="Compliance reports: sources, coverage, gaps, approvals, exceptions.",
    no_args_is_help=True,
)

FwArg = Annotated[str, typer.Argument(help="Framework: hipaa / pci_dss / soc2 / gdpr")]
SinceOpt = Annotated[str | None, typer.Option("--since", help="ISO start timestamp")]
UntilOpt = Annotated[str | None, typer.Option("--until", help="ISO end timestamp")]


@report_app.command("sources")
@cli_errors
def report_sources(target: TargetOption = None) -> None:
    """List audit sources and their readability."""
    from compliance_aiops.ops import events as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.list_sources(reader)))


@report_app.command("coverage")
@cli_errors
def report_coverage(framework: FwArg, since: SinceOpt = None, until: UntilOpt = None) -> None:
    """Per-control coverage for a framework."""
    from compliance_aiops.ops import controls as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.coverage_summary(reader, framework, since, until)))


@report_app.command("gaps")
@cli_errors
def report_gaps(framework: FwArg, since: SinceOpt = None, until: UntilOpt = None) -> None:
    """Controls with no/weak evidence + honest caveats."""
    from compliance_aiops.ops import controls as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.gap_analysis(reader, framework, since, until)))


@report_app.command("approvals")
@cli_errors
def report_approvals(since: SinceOpt = None, until: UntilOpt = None) -> None:
    """High-risk write ops + who approved (the change-approval trail)."""
    from compliance_aiops.ops import reports as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.approval_report(reader, since, until)))


@report_app.command("exceptions")
@cli_errors
def report_exceptions(since: SinceOpt = None, until: UntilOpt = None) -> None:
    """Denied / error / budget-exceeded ops (enforcement + anomaly evidence)."""
    from compliance_aiops.ops import reports as ops

    reader, _ = get_reader()
    console.print_json(json.dumps(ops.exceptions_report(reader, since, until)))
