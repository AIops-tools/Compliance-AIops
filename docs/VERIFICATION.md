# Verification — compliance-aiops

`compliance-aiops` is unusual in this product line: it is **not a platform
wrapper**. It has no external API, no network calls, and no platform
credentials. Its only inputs are on-disk `audit.db` files, opened **read-only**.

That means there is no "live cluster" to verify against — and no reason to defer
verification. Everything this tool claims is **offline and deterministic**, and
can therefore be verified completely on a laptop with no infrastructure at all.

This document defines what a full verification run covers and the criteria for
recording it as verified. It is deliberately checklist-shaped so the result is
reproducible and auditable — not a subjective "seems fine".

## What the test suite already guarantees

- Every module imports; the CLI builds; every MCP tool carries the
  `@governed_tool` harness marker (`tests/test_smoke.py`).
- **Synthetic audit DBs are built through the real governance-harness
  `AuditEngine`** — not hand-written SQLite — so the schema under test is the
  schema the sibling tools actually write.
- A **golden reproducible `chainHead`** is asserted: the same (framework,
  period, sources) produces a byte-identical chain head across runs.
- **Tamper tests** confirm detection: mutating a record, reordering records, and
  deleting a row are each caught by `verify_bundle` / `verify_source_chain`.
- Row-id gap detection flags deletions in a source trail.
- Framework mapping produces the documented `strong` / `partial` evidence
  strength per control, and `gap_analysis` emits the caveat rather than
  overclaiming.
- Bundle export paths are **restricted** — a traversal attempt in an export path
  is refused.

What the suite does **not** by itself establish: that the tool behaves correctly
against the **real, accumulated** audit trails of the other AIops tools on a
machine that has actually been used. That is what the run below adds.

## Prerequisites for a full run

No infrastructure. You need:

- A machine with **at least two** sibling AIops tools that have genuinely been
  used, so `~/.*-aiops/audit.db` files contain real accumulated activity —
  including at least one **high-risk** operation with a named approver and at
  least one **failed** operation (`status=error`).
- If you have no such history, generate it: run any sibling tool's `doctor`, a
  read, and one approved governed write, then a deliberately failing write.

```bash
uv tool install compliance-aiops
compliance-aiops init      # org name, optional signing key, encrypted store
```

## Verification checklist

Tick every box. A box that cannot be ticked is a verification gap — record it,
do not silently pass.

### 1. Discovery and connectivity
- [ ] `compliance-aiops doctor` → all green (config, source discovery, and the
      optional signing key).
- [ ] `compliance-aiops report sources` → **every** sibling tool with an
      `audit.db` on the machine is listed, with a plausible event count and date
      range. A silently missing source is the most damaging failure mode this
      tool has — it would produce a confidently incomplete bundle.
- [ ] Set `COMPLIANCE_AIOPS_HOME` to a temp dir and re-run → sources and bundles
      follow the relocated home (no hardcoded real `$HOME`).

### 2. Reads over real accumulated trails
- [ ] `query_audit_events` → returns real rows with populated tool, status,
      risk tier, approver, and timestamp fields.
- [ ] `activity_timeline` → the shape of real activity, with no crash on a
      source whose schema is at a different harness version.
- [ ] `compliance-aiops report approvals` → the high-risk operation you ran shows
      up **with its approver and rationale**.
- [ ] `compliance-aiops report exceptions` → operations lacking an approver or
      rationale are listed, and the deliberately failed operation is present
      with `status=error`.
- [ ] `compliance-aiops report coverage soc2` (and `hipaa`, `pci_dss`, `gdpr`) →
      coverage numbers are non-zero where activity exists and honestly zero
      where it does not.
- [ ] `compliance-aiops report gaps <framework>` → each gap carries its caveat
      and remediation hint; `partial`-strength controls are labelled `partial`,
      never silently promoted to `strong`.
- [ ] `control_evidence` on one control → the returned **reproducible query**,
      run by hand, yields the same population as the coverage number claims.

### 3. Determinism — the core claim
- [ ] `compliance-aiops bundle generate soc2 --since X --until Y` twice over the
      **same** sources and period → **identical `chainHead`** both times.
- [ ] The same generation on a **different machine** with the same source files
      copied in → still the same `chainHead` (proves no host-dependent input
      leaked into the chain).
- [ ] Reordering unrelated activity outside the period does **not** change the
      `chainHead`.

### 4. Tamper detection — the second core claim
- [ ] `compliance-aiops bundle verify <path>` on an untouched bundle → passes and
      reports the matching `chainHead`.
- [ ] Edit one character in a record inside a copied bundle → `bundle verify`
      **fails** and identifies the break.
- [ ] Delete a row from a **copy** of a source `audit.db`, then
      `verify_source_chain` → the **row-id gap is flagged**. (Copy — never mutate
      a real trail.)
- [ ] `sign_bundle` then `bundle verify` → the HMAC signature validates; corrupt
      the signature → verification fails.

### 5. Read-only guarantee
- [ ] After a full run, every source `audit.db` is **byte-identical** to before
      (compare SHA-256 hashes taken before and after). This is the tool's
      strongest safety claim — verify it by hash, not by assumption.
- [ ] The only files written anywhere are under `~/.compliance-aiops/`
      (bundles + this tool's own audit.db). Confirm with a filesystem diff.
- [ ] `export_bundle` with a traversal path (`../../etc/x`) → refused.

### 6. Governance actually gates
- [ ] With no `~/.compliance-aiops/rules.yaml`, a high/critical operation is
      **refused** unless `COMPLIANCE_AUDIT_APPROVED_BY` names an approver
      (secure-by-default).
- [ ] This tool's own operations are audited to
      `~/.compliance-aiops/audit.db` — i.e. the evidence tool is itself
      auditable, and a later bundle can include its own activity.
- [ ] A tight generation loop trips the runaway budget guard.

### 7. Unattended path
- [ ] `compliance-aiops bundle schedule soc2 --cron "0 2 * * 1" --period 7d --sign`
      → emits a `cronLine` and **writes nothing** (confirm with a filesystem
      diff).
- [ ] Run the emitted command by hand in a **clean environment** with only
      `COMPLIANCE_AIOPS_MASTER_PASSWORD` and `COMPLIANCE_AIOPS_HOME` set → a
      signed bundle is produced non-interactively.

### 8. Cleanup
- [ ] Remove the test bundles; confirm `compliance-aiops bundle list` is clean
      and no source trail was touched.

## Criteria to consider this tool verified

Record `compliance-aiops` as verified **only when all of the following hold**:

1. Every box above is ticked, on real accumulated audit trails from at least two
   sibling tools — not on synthetic fixtures alone.
2. Section 3 (determinism) passed **across two machines**, and section 5
   (read-only) passed by **hash comparison**.
3. Any schema-version or field-shape mismatch found against a real sibling trail
   is fixed **and covered by a test**, so the suite cannot regress it.
4. The run is written up in this repo's release notes with the date, the tool
   version, and which sibling tools' trails were used.

Note the scope of the claim even when fully green: this tool is
**tamper-EVIDENT, not tamper-PROOF**, and it produces **evidence, not
certification**. The source `audit.db` files remain the system of record. A
green checklist verifies that the tool reports faithfully — it does not make the
underlying audit trail authoritative.

## Notes for maintainers

- This is the **easiest tool in the line to verify** — no infrastructure, no
  credentials, no network. There is no good reason for it to carry verification
  debt.
- The two claims that actually matter are **determinism** (section 3) and
  **tamper detection** (section 4). If you only have an hour, do those.
- Always operate on **copies** of source trails when testing tamper detection.
- The verification story for the whole product line is tracked centrally; add
  this tool's result there so the verification-debt ledger stays accurate.
