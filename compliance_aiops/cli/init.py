"""``compliance-aiops init`` — a friendly, interactive onboarding wizard.

Discovers the sibling AIops tools' audit databases (``~/.<tool>-aiops/audit.db``),
records them plus an organization name into ``config.yaml``, and optionally
stores a **bundle-signing key** in the encrypted secret store. There are no
platform credentials here — the tool reads local audit trails, it doesn't connect
to any external system.
"""

from __future__ import annotations

import getpass

import typer
import yaml

from compliance_aiops.cli._common import cli_errors, console
from compliance_aiops.config import CONFIG_DIR, CONFIG_FILE, discover_sources
from compliance_aiops.governance.paths import ops_path

# Starter policy: keeps the secure-by-default gate (high/critical writes need a
# named approver) explicit and editable, and shows the other rule kinds.
DEFAULT_RULES_YAML = """\
# compliance-aiops policy rules — hot-reloaded on change (no restart needed).
# Kinds: deny rules, maintenance_window, risk_tiers (graduated autonomy).

risk_tiers:
  - name: high-risk-requires-approver
    tier: dual
    min_risk_level: high
    reason: >-
      High/critical writes need a named human approver — set
      COMPLIANCE_AUDIT_APPROVED_BY (and COMPLIANCE_AUDIT_RATIONALE) before the call.

# deny:
#   - name: no-prod-bundle-signing
#     operations: ["sign_*"]
#     environments: ["production"]
#     reason: "Bundle signing in production goes through change management."

# maintenance_window:
#   start: "22:00"
#   end: "06:00"
"""


def _write_default_rules() -> None:
    """Seed a starter rules.yaml (only when none exists) so the policy layer
    is explicit from day one; never overwrites an operator-authored file."""
    rules_path = ops_path("rules.yaml")
    if rules_path.exists():
        return
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(DEFAULT_RULES_YAML, "utf-8")
    console.print(f"[green]✓ Wrote default policy rules:[/] {rules_path}")


def _write_config(sources: list[dict], organization: str) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    doc = {"organization": organization, "sources": sources}
    CONFIG_FILE.write_text(yaml.safe_dump(doc, sort_keys=False), "utf-8")


@cli_errors
def init_cmd() -> None:
    """Interactively register audit sources and (optionally) a signing key."""
    console.print("[bold cyan]Compliance AIops — setup wizard[/]")
    console.print(
        "This discovers your sibling AIops tools' audit databases and records "
        "them (plus your organization name) to config.yaml. No platform "
        "credentials are needed — it reads local audit trails.\n"
    )

    organization = typer.prompt("Organization name (appears on evidence bundles)",
                                default="Unnamed Organization").strip()

    console.print("\n[bold]Discovering audit sources under ~/.*-aiops/audit.db …[/]")
    discovered = discover_sources()
    sources: list[dict] = []
    if discovered:
        for src_ in discovered:
            keep = typer.confirm(f"  Include '{src_.name}' ({src_.path})?", default=True)
            if keep:
                env = typer.prompt(f"    Environment tag for '{src_.name}'",
                                   default="").strip()
                sources.append({"name": src_.name, "path": str(src_.path),
                                "environment": env})
    else:
        console.print(
            "[yellow]  No sibling audit DBs found. Install and run a governed AIops "
            "tool first (e.g. nutanix-aiops), or add sources to config.yaml by hand.[/]"
        )

    _write_config(sources, organization)
    console.print(f"\n[green]✓ Wrote {len(sources)} source(s) to {CONFIG_FILE}[/]")

    console.print("\n[bold]Optional — bundle-signing key[/]")
    console.print(
        "[dim]Evidence bundles are always hash-chain-sealed. A signing key adds a "
        "signature (non-repudiation). You can skip this and add it later with "
        "'compliance-aiops secret set signing-key'.[/]"
    )
    if typer.confirm("Set up a signing key now?", default=False):
        from compliance_aiops.secretstore import SecretStore, resolve_master_password

        password = resolve_master_password(confirm_if_new=True)
        store = SecretStore.unlock(password)
        key = getpass.getpass("Signing key (a secret string; input hidden): ")
        store.set("signing-key", key)
        console.print("[green]✓ Signing key stored encrypted.[/]")
        console.print(
            "[dim]Tip: export COMPLIANCE_AIOPS_MASTER_PASSWORD=... so the MCP server "
            "can unlock it non-interactively.[/]"
        )

    _write_default_rules()
    console.print(f"\n[green]✓ Setup complete.[/] Config: {CONFIG_FILE}")
    if typer.confirm("Run a source check now (compliance-aiops doctor)?", default=True):
        from compliance_aiops.doctor import run_doctor

        raise typer.Exit(run_doctor())
