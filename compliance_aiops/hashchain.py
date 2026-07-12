"""Tamper-evident hash-chaining for evidence bundles.

The sibling audit DBs are append-only but not individually hash-chained, so
compliance-aiops builds a **hash chain over the ordered evidence records at seal
time**: each record's hash = ``SHA-256(prev_hash || canonical_json(record))``.
The final ``head`` hash commits to the entire ordered set — changing, inserting,
or dropping any record after sealing changes the head, which ``verify_chain``
detects and localises to the first broken link.

Standard + dependency-light: SHA-256 over canonical JSON (sorted keys, compact
separators, UTF-8). An optional detached signature over the head (a key from the
encrypted secret store) adds non-repudiation, but the chain alone is already
tamper-evident.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

GENESIS = "0" * 64


def canonical(record: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a record (excludes chain metadata keys)."""
    payload = {k: v for k, v in record.items() if not k.startswith("_chain")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _link(prev_hash: str, record: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(canonical(record))
    return h.hexdigest()


def chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Return ``{"head", "count", "records"}`` where each record gains
    ``_chain_seq`` and ``_chain_hash`` (the running chain hash up to it)."""
    prev = GENESIS
    chained: list[dict[str, Any]] = []
    for i, rec in enumerate(records):
        link = _link(prev, rec)
        chained.append({**rec, "_chain_seq": i, "_chain_hash": link})
        prev = link
    return {"head": prev, "count": len(chained), "records": chained}


def verify_chain(chained: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute the chain and report the first broken link, if any."""
    prev = GENESIS
    for rec in chained:
        expected = _link(prev, rec)
        if rec.get("_chain_hash") != expected:
            return {"valid": False, "brokenAtSeq": rec.get("_chain_seq"),
                    "count": len(chained)}
        prev = expected
    return {"valid": True, "brokenAtSeq": None, "head": prev, "count": len(chained)}


def sign_head(head: str, key: str) -> str:
    """Detached HMAC-SHA256 signature over the chain head (non-repudiation)."""
    return hmac.new(key.encode("utf-8"), head.encode("ascii"), hashlib.sha256).hexdigest()


def verify_signature(head: str, signature: str, key: str) -> bool:
    """Constant-time check of a head signature."""
    return hmac.compare_digest(sign_head(head, key), signature)
