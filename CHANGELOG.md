# Changelog

## v0.1.1

- Fix: `COMPLIANCE_AIOPS_HOME` now also relocates `config.yaml` (was hardcoded to `~/.compliance-aiops`).
- Fix: **CLI writes are now audited + undo-recorded** via the governance path — previously only the MCP tools recorded audit/undo; CLI `manage`/`remediate`/etc. writes now go through the same `@governed_tool` layer (they keep their dry-run + double-confirm). CLI write output is now the governed JSON result. No API/tool changes.


All notable changes to compliance-aiops are documented here. This project adheres
to [Semantic Versioning](https://semver.org/) and the
[Keep a Changelog](https://keepachangelog.com/) format.

## [0.1.0] — preview

Initial preview release: governed **compliance-evidence** tooling that reads the
local audit trails governed AIops agents already write (`~/.<tool>-aiops/audit.db`,
discovered via `~/.*-aiops/audit.db`) **read-only** and turns them into
**framework-mapped, hash-chain-sealed** evidence. **No external API, no network,
no platform credentials.** Evidence, not certification. Standalone governance
harness bundled in the package.

### Added

- **15 MCP tools** (12 read/analysis, 3 write/artifact — no external mutation):
  - **Audit reads** — `list_audit_sources`, `query_audit_events` (filter by
    tool/skill/status/risk/approved/selector/since/until), `activity_timeline`
    (hour/day buckets).
  - **Framework mapping** — `list_frameworks`, `coverage_summary` (per-control,
    one framework), `control_evidence` (evidence rows + population + reproducible
    query for one control), `gap_analysis` (no/weak-evidence controls + honest
    caveat + remediation).
  - **Assurance reports** — `approval_report` (high-risk write ops + approver +
    rationale), `exceptions_report` (denied / error / budget_exceeded).
  - **Integrity** — `verify_source_chain` (chain head + row-id gap detection),
    `verify_bundle` (chain + seal head + signature), `list_bundles`.
  - **Artifacts** — `generate_evidence_bundle` (low; coverage + approval trail +
    exceptions + sealed records → a bundle `.json`), `export_bundle` (low;
    markdown / csv / json), `sign_bundle` (medium; HMAC over the seal).
- **Framework catalog** (`compliance_aiops/frameworks.py`) — HIPAA §164.312,
  PCI-DSS v4.0, SOC 2 TSC, GDPR, each control carrying an evidence-strength label
  (`strong` / `partial`) and an honest caveat.
- **Hash-chain integrity** (`compliance_aiops/hashchain.py`) — SHA-256 over
  ordered records (`hash = SHA-256(prev_hash ‖ canonical_json(record))`, genesis
  prev = 64 zeros), reproducible `chainHead`, optional HMAC signature.
- **Ops modules** (`compliance_aiops/ops/`) — `events`, `controls`, `reports`,
  `overview`, `bundle`, `integrity`.
- **Encrypted signing-key store** — the bundle-signing key is stored encrypted in
  `~/.compliance-aiops/secrets.enc` (Fernet + scrypt); unlocked via
  `COMPLIANCE_AIOPS_MASTER_PASSWORD`. No platform credentials are used.
- **CLI** (`compliance-aiops`) — `init`, `overview`, `report`
  (sources/coverage/gaps/approvals/exceptions), `bundle`
  (generate/verify/list/export), `secret` (set/list/rm/migrate/rotate-password),
  `doctor`, `mcp`.
- **Deterministic offline tests** — synthetic audit DBs built via the real
  harness `AuditEngine`, a golden reproducible `chainHead`, and tamper tests.

### Known limitations

- **Tamper-EVIDENT, not tamper-PROOF** — the source `audit.db` remains the system
  of record.
- **Evidence, not certification.** OSCAL export is a v0.2 roadmap item (v0.1 emits
  JSON + Markdown + CSV shaped to ease a future OSCAL Assessment-Results adapter).
- **Preview** — interfaces may change before v1.0.
