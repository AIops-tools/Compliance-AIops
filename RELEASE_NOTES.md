# Compliance AIops v0.1.0 — preview

Governed **compliance-evidence** tooling for AI-agent infrastructure ops. It
**reads the local audit trails your governed AIops agents already write**
(`~/.<tool>-aiops/audit.db`, one shared `audit_log` schema, discovered via
`~/.*-aiops/audit.db`) **read-only**, and turns that activity into
**framework-mapped, hash-chain-sealed compliance evidence**. It does **not** scan
infrastructure and does **not** replace a GRC platform.

Unlike the other tools in the AIops-tools line it is **not a platform wrapper** —
**no external API, no network, no platform credentials**. Standalone: the
governance harness is bundled in the package.

> **Preview.** Evidence, not certification. Fully offline; the source `audit.db`
> files remain the system of record. The integrity claims are themselves
> test-verified (see below).

## Highlights

- **15 MCP tools** — 12 read/analysis, 3 write/artifact (no external mutation).
  - Read: `list_audit_sources`, `query_audit_events`, `activity_timeline`,
    `list_frameworks`, `coverage_summary`, `control_evidence`, `gap_analysis`,
    `approval_report`, `exceptions_report`, `verify_source_chain`,
    `verify_bundle`, `list_bundles`.
  - Write: `generate_evidence_bundle` (low), `export_bundle` (low),
    `sign_bundle` (medium).
- **Framework mapping with honest evidence-strength** — HIPAA §164.312 /
  PCI-DSS v4.0 / SOC 2 TSC / GDPR. Audit trails prove *operating effectiveness*
  strongly and *design / configuration* only partially; each control is labelled
  `strong` / `partial` and `gap_analysis` surfaces the caveat.
- **Hash-chain-sealed bundles** — SHA-256 over ordered records, reproducible
  `chainHead`, optional HMAC signature. `verify_bundle` catches tampering;
  `verify_source_chain` detects row-id gaps / deletions.
- **Zero-network, read-only** — no credentials, no outbound calls, no mutation of
  the source trails. Bundles written to `~/.compliance-aiops/bundles/`.
- **Deterministic offline tests** — synthetic audit DBs built through the real
  harness `AuditEngine`, a golden reproducible `chainHead`, and tamper tests.
  No live infrastructure dependency.

## Install

```bash
uv tool install compliance-aiops
compliance-aiops init        # discover sibling audit DBs, set org name, optional signing key
compliance-aiops doctor      # which sibling audit DBs are present/readable
```

## Caveats

- **Tamper-EVIDENT, not tamper-PROOF** — the source `audit.db` remains the system
  of record; record the `chainHead` out-of-band for an independent anchor.
- **Evidence, not certification.** OSCAL export is a documented v0.2 roadmap item
  (v0.1 emits JSON + Markdown + CSV).
- **Preview:** interfaces may change before v1.0.
