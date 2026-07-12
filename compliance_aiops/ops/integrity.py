"""Chain integrity over a live source range or a sealed bundle (read-only).

Two checks operators run: (1) ``verify_source_chain`` builds a hash chain over a
source's current events and reports its head + any **row-id gaps** (a missing id
is a possible deletion — what an auditor most wants flagged); (2) ``verify_bundle``
re-derives the chain of a previously sealed bundle and reports the first broken
link, seal-head match, and signature validity.

A hash chain is tamper-**evident**, not tamper-**proof**: it detects casual /
single-row edits against a previously recorded head, and proves a held bundle is
unaltered since sealing. The source ``audit.db`` remains the source of truth.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from compliance_aiops import hashchain
from compliance_aiops.ops._util import s


def _ordered(reader: Any, source: str, since: str | None, until: str | None) -> list[dict]:
    """A source's events in deterministic (ts, id) ascending order."""
    rows = reader.query(source=source, since=since, until=until, limit=100_000)
    return sorted(rows, key=lambda r: (r.get("ts", ""), r.get("id", 0)))


def verify_source_chain(reader: Any, source: str, since: str | None = None,
                        until: str | None = None) -> dict:
    """[READ] Chain head for a source's current events + row-id gap detection."""
    events = _ordered(reader, source, since, until)
    result = hashchain.chain(events)
    gaps = _id_gaps(reader.ordered_ids(source))
    return {
        "source": s(source, 64),
        "recordCount": result["count"],
        "chainHead": result["head"],
        "idContiguous": not gaps,
        "gaps": gaps,
        "note": "Record chainHead out-of-band; re-run later to detect changes. "
                "Gaps in row ids may indicate deleted audit rows.",
    }


def _id_gaps(ids: list[int]) -> list[dict]:
    """Missing ids in an ascending sequence (possible deletions)."""
    gaps: list[dict] = []
    for prev, cur in zip(ids, ids[1:]):
        if cur > prev + 1:
            gaps.append({"afterId": prev, "beforeId": cur, "missing": cur - prev - 1})
    return gaps


def verify_bundle(bundle_path: str) -> dict:
    """[READ] Verify a sealed evidence bundle: chain, seal head, signature."""
    path = Path(bundle_path).expanduser()
    if not path.exists():
        return {"error": f"Bundle not found: {s(bundle_path, 256)}"}
    try:
        bundle = json.loads(path.read_text("utf-8"))
    except (ValueError, OSError) as exc:
        return {"error": f"Cannot read bundle: {s(exc, 200)}"}

    records = bundle.get("records", [])
    seal = bundle.get("seal", {})
    chain_verdict = hashchain.verify_chain(records)
    seal_head = seal.get("chainHead")
    head_matches = bool(chain_verdict.get("valid")) and seal_head == chain_verdict.get("head")

    return {
        "bundlePath": str(path),
        "framework": s(seal.get("framework"), 32),
        "recordCount": len(records),
        "chainValid": chain_verdict.get("valid"),
        "brokenAtSeq": chain_verdict.get("brokenAtSeq"),
        "sealHead": seal_head,
        "headMatches": head_matches,
        "signaturePresent": bool(seal.get("signature")),
        "verdict": "intact" if head_matches else "TAMPERED_OR_MODIFIED",
    }
