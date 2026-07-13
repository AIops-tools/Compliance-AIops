"""Configuration management for Compliance AIops.

Unlike the platform tools in this line, compliance-aiops has **no remote API**.
Its data sources are the local **audit databases** written by the sibling AIops
tools' vendored governance harness — each tool keeps `~/.<tool>-aiops/audit.db`
(same ``audit_log`` schema across the whole line). A "source" is one such DB.

If no ``config.yaml`` exists, sources are **auto-discovered** by globbing
``~/.*-aiops/audit.db`` (excluding this tool's own). An explicit config can pin
exact paths, label each source's environment, and set the organization name that
appears on generated evidence bundles.

The encrypted secret store is optional here — it holds only an optional
**bundle-signing key** (for non-repudiation of sealed evidence bundles), never a
platform credential.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from compliance_aiops.governance.paths import ops_home

CONFIG_DIR = ops_home()
CONFIG_FILE = CONFIG_DIR / "config.yaml"
ENV_FILE = CONFIG_DIR / ".env"

# Where sealed evidence bundles are written by default.
BUNDLE_DIR = CONFIG_DIR / "bundles"

# Auto-discovery: sibling audit DBs live at ~/.<tool>-aiops/audit.db.
_DISCOVERY_GLOB = ".*-aiops/audit.db"
_SELF = "compliance-aiops"

# Legacy env-var fragments used by the generic 'secret migrate' command. There
# are no per-target platform secrets here (only an optional signing key), so
# migrate is effectively a no-op — the fragments exist to keep the shared secret
# CLI importable.
SECRET_ENV_PREFIX = "COMPLIANCE_"  # nosec B105 — env-var name, not a secret
SECRET_ENV_SUFFIX = "_SECRET"  # nosec B105 — env-var name, not a secret

_log = logging.getLogger("compliance-aiops.config")


@dataclass(frozen=True)
class AuditSource:
    """One sibling tool's audit database.

    ``name`` labels the source (usually the tool name, e.g. ``nutanix-aiops``);
    ``path`` is its ``audit.db``; ``environment`` is an optional tag (prod / lab)
    used to scope evidence to a compliance boundary.
    """

    name: str
    path: Path
    environment: str = ""

    @property
    def exists(self) -> bool:
        return self.path.exists()


def discover_sources() -> tuple[AuditSource, ...]:
    """Find sibling audit DBs under the home dir (excluding this tool's own)."""
    found: list[AuditSource] = []
    for db in sorted(Path.home().glob(_DISCOVERY_GLOB)):
        tool = db.parent.name.lstrip(".")  # ".nutanix-aiops" -> "nutanix-aiops"
        if tool == _SELF:
            continue
        found.append(AuditSource(name=tool, path=db))
    return tuple(found)


@dataclass(frozen=True)
class AppConfig:
    """Top-level application config."""

    sources: tuple[AuditSource, ...] = ()
    organization: str = "Unnamed Organization"
    bundle_dir: Path = field(default=BUNDLE_DIR)

    def get_source(self, name: str) -> AuditSource:
        for src_ in self.sources:
            if src_.name == name:
                return src_
        available = ", ".join(s.name for s in self.sources) or "(none)"
        raise KeyError(f"Source '{name}' not found. Available: {available}")


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load config from YAML, or auto-discover sibling audit DBs if none exists."""
    path = config_path or CONFIG_FILE
    if not path.exists():
        sources = discover_sources()
        if not sources:
            _log.warning(
                "No config and no sibling audit DBs found under ~/.*-aiops/. "
                "Run 'compliance-aiops init' or point at a source explicitly."
            )
        return AppConfig(sources=sources)

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    if raw.get("sources"):
        sources = tuple(
            AuditSource(
                name=s["name"],
                path=Path(s["path"]).expanduser(),
                environment=s.get("environment", ""),
            )
            for s in raw["sources"]
        )
    else:
        sources = discover_sources()

    bundle_dir = Path(raw["bundle_dir"]).expanduser() if raw.get("bundle_dir") else BUNDLE_DIR
    return AppConfig(
        sources=sources,
        organization=raw.get("organization", "Unnamed Organization"),
        bundle_dir=bundle_dir,
    )
