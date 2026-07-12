"""Environment + audit-source diagnostics for Compliance AIops."""

from __future__ import annotations

from rich.console import Console

from compliance_aiops.config import load_config
from compliance_aiops.connection import get_reader
from compliance_aiops.secretstore import SECRETS_FILE, check_permissions, has_store

_console = Console()


def run_doctor(skip_auth: bool = False) -> int:
    """Check config, audit sources, and the optional signing key.

    Returns 0 healthy, 1 if problems. Never raises — a doctor must survive the
    thing it diagnoses being unhealthy.
    """
    problems = 0

    try:
        config = load_config()
    except Exception as exc:  # noqa: BLE001 — report, do not crash
        _console.print(f"[red]✗ Config load failed: {exc}[/]")
        return 1

    if not config.sources:
        _console.print(
            "[red]✗ No audit sources found.[/] No sibling AIops audit DBs under "
            "~/.*-aiops/audit.db, and none configured. Run 'compliance-aiops init'."
        )
        return 1
    _console.print(f"[green]✓ {len(config.sources)} audit source(s) resolved[/]")

    reader = get_reader(config)
    readable = 0
    for st in reader.sources_status():
        if st["readable"]:
            readable += 1
            _console.print(
                f"[green]✓ {st['name']} — {st['rowCount']} audit rows ({st['path']})[/]"
            )
        elif st["exists"]:
            _console.print(f"[red]✗ {st['name']} — present but unreadable/incompatible[/]")
            problems += 1
        else:
            _console.print(f"[yellow]! {st['name']} — path missing ({st['path']})[/]")
            problems += 1
    if readable == 0:
        _console.print("[red]✗ No readable audit sources — nothing to build evidence from.[/]")
        problems += 1

    # Optional signing key (for sealed-bundle signatures).
    if has_store():
        _console.print(f"[green]✓ Encrypted secret store present: {SECRETS_FILE}[/]")
        perm_warning = check_permissions()
        if perm_warning:
            _console.print(f"[yellow]! {perm_warning}[/]")
        _console.print(
            "[dim]  (A signing key is optional — bundles hash-chain-seal without one.)[/]"
        )
    else:
        _console.print(
            "[dim]! No secret store — evidence bundles will be hash-chain-sealed but "
            "unsigned. Add a signing key with 'compliance-aiops secret set signing-key'.[/]"
        )

    return 1 if problems else 0
