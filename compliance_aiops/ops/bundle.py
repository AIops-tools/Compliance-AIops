"""Evidence-bundle assembly, sealing, signing, and export (governed artifacts).

``generate_evidence_bundle`` is the one-call happy path: it assembles the
coverage summary, the approval trail (high-risk ops + who approved), exceptions
(denied/error/budget), and the hash-chained evidence records into a **sealed**
bundle written under ``~/.compliance-aiops/bundles/``. It never touches an
external system — it only reads audit DBs and writes a local artifact — so its
risk tier is low.

The chain is built over the ordered evidence records only (not the seal), so the
``chainHead`` for a given (framework, period, sources) is **reproducible** — that
determinism is itself part of the integrity story and is regression-tested.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from compliance_aiops import __version__, frameworks, hashchain
from compliance_aiops.config import AppConfig
from compliance_aiops.ops import controls as controls_ops
from compliance_aiops.ops import reports as reports_ops
from compliance_aiops.ops._util import SCAN_LIMIT, norm_event, s, scan
from compliance_aiops.secretstore import MASTER_PASSWORD_ENV

_SCHEMA_VERSION = 1
_SIGNING_KEY_NAME = "signing-key"

# Convenience relative windows for `--period`: "<n><unit>" with unit d/h/w, or the
# spelled-out "last-7-days" style. Resolves to (since, until) ISO strings ending now.
_PERIOD_RE = re.compile(r"^(?:last-)?(\d+)-?(day|days|d|hour|hours|h|week|weeks|w)s?$")
_UNIT_HOURS = {"d": 24, "day": 24, "h": 1, "hour": 1, "w": 168, "week": 168}


def resolve_period(period: str | None) -> tuple[str | None, str | None]:
    """Turn a relative window like ``7d`` / ``last-7-days`` into (since, until) ISO.

    Returns ``(None, None)`` for a falsy ``period`` (the whole trail). Raises
    ``ValueError`` on an unparseable spec so the caller fails fast.
    """
    if not period:
        return None, None
    m = _PERIOD_RE.match(period.strip().lower())
    if not m:
        raise ValueError(
            f"Unparseable --period '{period}'. Use forms like '7d', '24h', "
            f"'2w', or 'last-7-days'."
        )
    qty, unit = int(m.group(1)), m.group(2).rstrip("s")
    until = datetime.now(tz=UTC)
    since = until - timedelta(hours=qty * _UNIT_HOURS[unit])
    return since.isoformat(), until.isoformat()


def _ordered_events(reader: Any, since: str | None,
                    until: str | None) -> tuple[list[dict], bool]:
    """Bundle records in deterministic (ts, id) order, plus a scan-cap flag.

    A sealed bundle that silently omitted rows beyond the scan cap would present
    a partial trail as a complete one — the failure mode an evidence tool must
    never have. The flag is recorded in the seal so a verifier sees it too.
    """
    rows, truncated = scan(reader, since=since, until=until)
    return sorted(rows, key=lambda r: (r.get("ts", ""), r.get("id", 0))), truncated


def _source_manifest(reader: Any) -> list[dict]:
    out = []
    for st in reader.sources_status():
        digest = None
        if st.get("readable"):
            try:
                digest = hashlib.sha256(Path(st["path"]).read_bytes()).hexdigest()
            except OSError:
                digest = None
        out.append({"name": st["name"], "path": st["path"],
                    "rowCount": st.get("rowCount"), "dbSha256": digest})
    return out


def _signing_key() -> str | None:
    """The optional bundle-signing key from the encrypted store (None if absent)."""
    try:
        from compliance_aiops.secretstore import get_secret, has_store

        if has_store():
            return get_secret(_SIGNING_KEY_NAME)
    except Exception:  # noqa: BLE001 — no key configured is a normal state
        return None
    return None


def generate_evidence_bundle(
    reader: Any, config: AppConfig, framework: str,
    period_start: str | None = None, period_end: str | None = None,
    out_path: str | None = None, sign: bool = False, period: str | None = None,
) -> dict:
    """[WRITE][medium] Assemble + seal an evidence bundle for a framework/period.

    ``period`` is a convenience relative window (e.g. ``7d`` / ``last-7-days``)
    used only when explicit ``period_start`` / ``period_end`` are not supplied.
    """
    if period and not (period_start or period_end):
        period_start, period_end = resolve_period(period)
    coverage = controls_ops.coverage_summary(reader, framework, period_start, period_end)
    approval = reports_ops.approval_report(reader, period_start, period_end)
    exceptions = reports_ops.exceptions_report(reader, period_start, period_end)

    ordered, scan_truncated = _ordered_events(reader, period_start, period_end)
    records = [norm_event(e) for e in ordered]
    chained = hashchain.chain(records)

    generated_at = datetime.now(tz=UTC).isoformat()
    seal = {
        "schemaVersion": _SCHEMA_VERSION,
        "framework": framework.lower(),
        "frameworkTitle": coverage["frameworkTitle"],
        "organization": config.organization,
        "period": {"start": period_start, "end": period_end},
        "sources": _source_manifest(reader),
        "recordCount": chained["count"],
        "scanLimit": SCAN_LIMIT,
        "scanTruncated": scan_truncated,
        "genesisHash": hashchain.GENESIS,
        "chainHead": chained["head"],
        "generatedAt": generated_at,
        "generator": f"compliance-aiops {__version__}",
        "signature": None,
    }
    if sign:
        key = _signing_key()
        if key:
            seal["signature"] = {"alg": "HMAC-SHA256",
                                 "value": hashchain.sign_head(chained["head"], key)}

    bundle = {
        "seal": seal,
        "coverage": coverage,
        "approvalTrail": approval,
        "exceptions": exceptions,
        "records": chained["records"],
    }

    path = _resolve_out(config, framework, generated_at, out_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), "utf-8")

    return {"action": "generate_evidence_bundle", "bundlePath": str(path),
            "framework": framework.lower(), "recordCount": chained["count"],
            "scanLimit": SCAN_LIMIT, "scanTruncated": scan_truncated,
            "chainHead": chained["head"], "signed": bool(seal["signature"]),
            "controlsCovered": coverage["controlsCovered"],
            "controlsTotal": coverage["controlsTotal"]}


def _confine_out(requested: str, base: Path, hint: str) -> Path:
    """Resolve ``requested`` and require it to stay inside ``base``.

    Path confinement for agent-supplied output paths: a bare relative filename
    lands inside ``base``; anything resolving outside it (``../`` escapes,
    absolute paths elsewhere) raises a teaching ``ValueError``.
    """
    base_resolved = base.expanduser().resolve()
    candidate = Path(requested).expanduser()
    if not candidate.is_absolute():
        candidate = base_resolved / candidate
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise ValueError(
            f"out_path '{requested}' resolves outside the allowed output "
            f"directory {base_resolved}. {hint}"
        )
    return resolved


def _resolve_out(config: AppConfig, framework: str, generated_at: str,
                 out_path: str | None) -> Path:
    if out_path:
        return _confine_out(
            out_path,
            config.bundle_dir,
            "Evidence bundles may only be written inside the configured bundle "
            "directory — pass a bare filename (it lands there) or a path under "
            "it, or change bundle_dir in config.yaml to relocate it.",
        )
    stamp = generated_at.replace(":", "").replace("-", "").split(".")[0]
    return config.bundle_dir / f"{framework.lower()}-{stamp}.json"


def sign_bundle(config: AppConfig, bundle_path: str) -> dict:
    """[WRITE][medium] Attach an HMAC signature over the seal using the stored key."""
    path = Path(bundle_path).expanduser()
    bundle = json.loads(path.read_text("utf-8"))
    key = _signing_key()
    if not key:
        raise ValueError(
            "No signing key configured. Store one with "
            "'compliance-aiops secret set signing-key' first."
        )
    head = bundle.get("seal", {}).get("chainHead", "")
    bundle["seal"]["signature"] = {"alg": "HMAC-SHA256",
                                   "value": hashchain.sign_head(head, key)}
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), "utf-8")
    return {"action": "sign_bundle", "bundlePath": str(path), "signed": True}


def export_bundle(bundle_path: str, fmt: str = "markdown", out_path: str | None = None) -> dict:
    """[WRITE][medium] Render a bundle to markdown / csv (json is the native form)."""
    path = Path(bundle_path).expanduser()
    bundle = json.loads(path.read_text("utf-8"))
    fmt = fmt.lower()
    if fmt == "markdown":
        text, ext = _to_markdown(bundle), "md"
    elif fmt == "csv":
        text, ext = _to_csv(bundle), "csv"
    elif fmt == "json":
        text, ext = json.dumps(bundle, ensure_ascii=False, indent=2), "json"
    else:
        raise ValueError(f"Unknown format '{fmt}'. Choose markdown, csv, or json.")
    if out_path:
        out = _confine_out(
            out_path,
            path.parent,
            "Exports may only be written alongside the source bundle — pass a "
            "bare filename or a path inside the bundle's own directory.",
        )
    else:
        out = path.with_suffix(f".{ext}")
    out.write_text(text, "utf-8")
    return {"action": "export_bundle", "format": fmt, "outPath": str(out)}


def _to_markdown(bundle: dict) -> str:
    seal = bundle.get("seal", {})
    cov = bundle.get("coverage", {})
    lines = [
        f"# Compliance evidence bundle — {seal.get('frameworkTitle', '')}",
        "",
        f"- **Organization:** {seal.get('organization', '')}",
        f"- **Period:** {seal.get('period', {}).get('start')} → "
        f"{seal.get('period', {}).get('end')}",
        f"- **Generated:** {seal.get('generatedAt', '')} by {seal.get('generator', '')}",
        f"- **Records:** {seal.get('recordCount', 0)}  ·  "
        f"**Chain head:** `{seal.get('chainHead', '')}`",
        f"- **Signed:** {'yes' if seal.get('signature') else 'no'}",
        "",
        "## Control coverage",
        "",
        "| Control | Title | Strength | Evidence | Covered | Gap |",
        "|---|---|---|--:|:--:|---|",
    ]
    for c in cov.get("controls", []):
        lines.append(
            f"| {c['controlId']} | {c['title']} | {c['strength']} | {c['evidenceCount']} | "
            f"{'✓' if c['covered'] else '✗'} | {c.get('gap') or ''} |"
        )
    covered = f"{cov.get('controlsCovered', 0)}/{cov.get('controlsTotal', 0)}"
    lines += ["", f"_Covered {covered} controls over {cov.get('eventsScanned', 0)} events._", "",
              "> Audit trails evidence operating effectiveness strongly and control "
              "design/configuration only partially."]
    return "\n".join(lines)


def _to_csv(bundle: dict) -> str:
    header = "controlId,title,strength,evidenceCount,covered,gap"
    rows = [header]
    for c in bundle.get("coverage", {}).get("controls", []):
        gap = (c.get("gap") or "").replace(",", ";").replace("\n", " ")
        rows.append(f"{c['controlId']},{c['title']},{c['strength']},"
                    f"{c['evidenceCount']},{c['covered']},{gap}")
    return "\n".join(rows)


_DEFAULT_CRON = "0 2 * * 1"  # 02:00 every Monday


def bundle_schedule_hint(
    framework: str, cron: str = _DEFAULT_CRON, period: str = "7d", sign: bool = False,
) -> dict:
    """[READ] Ready-to-paste cron line + non-interactive command for periodic sealing.

    Writes NOTHING and starts no daemon — it only composes (and validates) the
    crontab line and the exact ``compliance-aiops bundle generate`` invocation an
    operator can schedule themselves. The cron expression must be a standard
    5-field spec; the framework must be a known one.
    """
    frameworks.controls_for(framework)  # fail fast on an unknown framework
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError(
            f"cron '{cron}' must be a standard 5-field expression "
            f"(minute hour day-of-month month day-of-week), got {len(fields)} field(s)."
        )
    resolve_period(period)  # fail fast on an unparseable window
    fw = framework.lower()
    command = (
        f"compliance-aiops bundle generate {fw} --period {period}"
        + (" --sign" if sign else "")
    )
    cron_line = f"{cron} {command}"
    return {
        "action": "bundle_schedule_hint",
        "writesNothing": True,
        "framework": fw,
        "cron": cron,
        "period": period,
        "signed": sign,
        "command": command,
        "cronLine": cron_line,
        "masterPasswordEnv": MASTER_PASSWORD_ENV,
        "note": (
            "This tool writes nothing and runs no daemon. Add cronLine to your "
            "crontab (crontab -e) to seal a bundle on a schedule. Export "
            f"{MASTER_PASSWORD_ENV} in the cron job's environment so a stored "
            "signing key unlocks non-interactively — do NOT inline the real "
            "password in the crontab file."
        ),
    }


def list_bundles(config: AppConfig) -> list[dict]:
    """[READ] Previously generated bundles under the bundle dir + their seal head."""
    out: list[dict] = []
    if not config.bundle_dir.exists():
        return out
    for f in sorted(config.bundle_dir.glob("*.json")):
        try:
            seal = json.loads(f.read_text("utf-8")).get("seal", {})
        except (ValueError, OSError):
            continue
        out.append({"bundlePath": str(f), "framework": s(seal.get("framework"), 32),
                    "generatedAt": s(seal.get("generatedAt"), 40),
                    "recordCount": seal.get("recordCount"),
                    "chainHead": s(seal.get("chainHead"), 64),
                    "signed": bool(seal.get("signature"))})
    return out
