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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from compliance_aiops import __version__, hashchain
from compliance_aiops.config import AppConfig
from compliance_aiops.ops import controls as controls_ops
from compliance_aiops.ops import reports as reports_ops
from compliance_aiops.ops._util import norm_event, s

_SCHEMA_VERSION = 1
_SIGNING_KEY_NAME = "signing-key"


def _ordered_events(reader: Any, since: str | None, until: str | None) -> list[dict]:
    rows = reader.query(since=since, until=until, limit=100_000)
    return sorted(rows, key=lambda r: (r.get("ts", ""), r.get("id", 0)))


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
    out_path: str | None = None, sign: bool = False,
) -> dict:
    """[WRITE][low] Assemble + seal an evidence bundle for a framework/period."""
    coverage = controls_ops.coverage_summary(reader, framework, period_start, period_end)
    approval = reports_ops.approval_report(reader, period_start, period_end)
    exceptions = reports_ops.exceptions_report(reader, period_start, period_end)

    records = [norm_event(e) for e in _ordered_events(reader, period_start, period_end)]
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
            "chainHead": chained["head"], "signed": bool(seal["signature"]),
            "controlsCovered": coverage["controlsCovered"],
            "controlsTotal": coverage["controlsTotal"]}


def _resolve_out(config: AppConfig, framework: str, generated_at: str,
                 out_path: str | None) -> Path:
    if out_path:
        return Path(out_path).expanduser()
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
    """[WRITE][low] Render a bundle to markdown / csv (json is the native form)."""
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
    out = Path(out_path).expanduser() if out_path else path.with_suffix(f".{ext}")
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
