"""Top-level Typer app: assembles sub-apps and top-level commands."""

from __future__ import annotations

import typer

from compliance_aiops.cli._common import cli_errors
from compliance_aiops.cli.bundle import bundle_app
from compliance_aiops.cli.doctor import doctor_cmd
from compliance_aiops.cli.init import init_cmd
from compliance_aiops.cli.overview import overview_cmd
from compliance_aiops.cli.report import report_app
from compliance_aiops.cli.secret import secret_app

app = typer.Typer(
    name="compliance-aiops",
    help="Governed compliance evidence from AIops audit trails — HIPAA / PCI-DSS / "
    "SOC 2 / GDPR mapping + hash-chain-sealed bundles.",
    no_args_is_help=True,
)

app.add_typer(report_app, name="report")
app.add_typer(bundle_app, name="bundle")
app.add_typer(secret_app, name="secret")
app.command("init")(init_cmd)
app.command("overview")(overview_cmd)
app.command("doctor")(doctor_cmd)


@app.command("mcp")
@cli_errors
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients (does not go through uvx/PyPI
    resolution at launch):
        compliance-aiops mcp
    """
    import sys

    if sys.version_info < (3, 11):
        typer.echo(
            f"ERROR: compliance-aiops requires Python >= 3.11 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Fix: uv python install 3.12 && "
            f"uv tool install --python 3.12 --force compliance-aiops",
            err=True,
        )
        raise typer.Exit(2)

    from mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()
