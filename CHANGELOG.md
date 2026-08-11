# Changelog

## v0.10.0 — 2026-08-11

### Added
- **OSCAL export** — `oscal_assessment_results` (read, returns the document inline) and `export_bundle --format oscal` (writes `<bundle>.oscal.json`). A sealed evidence bundle becomes a **NIST OSCAL 1.2.3 Assessment Results** document: one observation and one finding per control, `reviewed-controls` naming the framework's full control set, and a `back-matter` resource binding the document to the bundle by chain head and per-source SHA-256.
- **Deterministic by construction.** UUIDs are version 5, derived from the bundle's chain head, so re-exporting the same bundle produces a **byte-identical** document (verified end to end, not just unit-tested). Random v4 UUIDs would have thrown away the reproducibility the bundle's chain head exists to provide.

### Honest about what OSCAL cannot say
Three places where the model cannot carry what this tool knows, handled explicitly — an evidence artifact that overstates is worse than none:
- **`import-ap` is required and there is no assessment plan.** This evidence is collected continuously by operations tooling, not produced by a planned assessment. `href` resolves to a back-matter resource that says exactly that, rather than naming a plan nobody wrote.
- **`status.state` has only `satisfied` / `not-satisfied`** — no "partially satisfied". This tool's own model is more careful: an audit trail evidences that a control *operated*, not that it is correctly *designed*. Partial-strength controls are therefore reported `satisfied` **plus** an `evidence-strength=partial` prop, remarks naming what the trail does not prove, a count in the result's own description, and the same count as `satisfiedOnPartialEvidence` in the returned summary — four places, because a bare `satisfied` silently upgrades the claim.
- **A truncated source scan leads the result description in prose** (`POPULATION INCOMPLETE: …`), not just a prop. A partial population presented as a complete assessment is the worst failure this tool could have.

### Verified
- Output validated against the **published NIST schema** (`oscal_assessment-results_schema.json`, OSCAL v1.2.3) for **all six frameworks** — hipaa, pci_dss, soc2, gdpr, iso27001, djcp_l3 — with synthetic bundles exercising both statuses, both evidence strengths, a truncated scan and a signed seal. `scripts/validate_oscal.py` reproduces it (schema file + `jsonschema` required; neither is a runtime dependency of a tool that must work offline).
- Validating for real is what found the defects below; a hand-checked emitter would have shipped them.

### Changed
- **A change-management gap now requires an unapproved *change*, not an unapproved attempt.** `coverage_summary` / `gap_analysis` counted every high-risk write with an empty `approved_by` as a change-approval gap, ignoring the outcome the harness had already recorded. Found on a real cross-tool audit trail: two high-risk writes failed on a dropped connection and were still reported as "2 high-risk write op(s) recorded without an approver — change-approval gap". Asked to produce those two unapproved changes, the trail would have shown neither happened. The gap now rests on ops that **took effect** plus ops whose **outcome is undetermined** (a lost response may well have landed — the case that must never be filed under "did not happen"), and both payloads carry an `unapprovedWrites` summary with `tookEffect` / `outcomeUndetermined` / `didNotLand`. Attempts that did not land are still reported — they evidence a process that does not require approvers — just not as changes.

### Fixed (found by that validation, before release)
- **The zero-controls case emitted an invalid document, and a test called it a "valid shell".** The structural check passed and the test agreed, fossilising a wrong belief; the published schema disagreed on four counts (`control-selections` must name `include-all` or a non-empty `include-controls`, and `observations`/`findings` are `minItems: 1`). There is no way in OSCAL to say "nothing was in scope", and `include-all` would assert the opposite of the truth, so the emitter now **refuses** with a teaching error rather than misstating its own scope.
- **A prop carrying an absent field invalidated the whole document.** OSCAL strings must match `^\S(.*\S)?$`, so a bundle with no genesis hash — or a control with no title — produced an empty `value` and a document no consumer would accept. Empty props are now dropped: an omitted prop says "not stated", an empty one asserts a blank value. A sparse bundle is now part of the schema-validation run.
- **The write path was less strict than the read path.** `export_bundle --format oscal` wrote the file without the structural check that `oscal_assessment_results` runs, so the malformed document was the one that reached an auditor while the inspectable one was fine. It now refuses to write, and the CLI exits non-zero when a document fails its check — printing one with exit 0 means the shell redirect that captured it "succeeded".
- **Framework-native control ids are not legal OSCAL identifiers.** OSCAL's `TokenDatatype` requires a letter/underscore start and allows only letters, digits, `.`, `-`, `_` — so `164.312(b)` and `164.312(a)(1)` (parentheses) and `10.2` / `8.1.5.4` (digit-initial) are all invalid; only the SOC 2 (`CC6.1`) and ISO (`A.5.15`) styles happened to pass. `control-id` and `target-id` are now derived, framework-prefixed tokens (`hipaa_164.312-a-1`), with the native id preserved on `target.title`, a `framework-control-id` prop and the finding description — the join back to the framework must not be lost to a syntax rule.
- **A prop name carried a colon** (`source-sha256:proxmox`), also not a legal token, and a source name is operator-chosen free text so no amount of naming discipline fixes it. The digest is now a `source-sha256` prop with the source name in `remarks`, where free text is allowed. A test asserts **every** prop name and control id in the whole document is a legal token, so a future addition cannot reintroduce the class.

## v0.9.0 — 2026-08-10

### Fixed
- **An undetermined outcome no longer exits as a plain failure.** A write whose response was lost carries *both* `error` and `outcomeUnknown`, and the harness deliberately judges unknown first when writing the audit row — the change may have taken effect, so a blind retry could apply it twice. The CLI guard judged `error` first, so the audit said "may have taken effect" while the exit status told a script it had not happened. The two layers now agree (exit 2, not 1), and a test pins the ordering so it cannot silently flip back.
- **The CLI reported a refused or failed governed write as a success.** 1 write call site (`undo apply`) printed the governed twin's payload and exited **0** whatever it said — and `@tool_errors` flattens every refusal, guard rejection and upstream failure into `{"error": ...}` rather than raising, so nothing downstream of a `&&` chain or a CI step could tell a blocked write from a landed one. The dry-run path already exited non-zero, which made the asymmetry worse: the preview was stricter than the write it previews. Results now route through a `checked()` helper — exit 1 on an error payload, exit 2 on an undetermined outcome, unchanged on success. This defect class had been fixed repo-by-repo several times and kept coming back; an audit across the whole line found it live in **18 of the 24 tools at once (87 call sites)**, so each tool now carries an invariant test that fails if any future CLI command prints a governed result without checking it.

## v0.8.0 — 2026-08-03

### Fixed
- **`undo apply` replays against the target the original write ran on.** It dispatched the inverse against whatever target the *caller* named — in practice the config's first entry — while the write's own target sat unused in the undo record. On a multi-target config the inverse therefore ran against the wrong host; it only looks harmless because the resource usually is not there, but two hosts holding the same name and the inverse **succeeds on the wrong one, silently**. An explicitly named target still wins. Line-wide: all 24 copies had the identical defect. Caught live in container-host-aiops, where a stop recorded against a Podman target replayed against a Portainer one.

## v0.7.0 — 2026-08-02

### Changed (BREAKING)
- **Requires MCP SDK 2.0** (`mcp[cli]>=2.0,<3.0`). `mcp.server.fastmcp` no longer exists in 2.0; the server is now built with `MCPServer` and reports its package version in the stdio handshake.

### Fixed
- **`undo apply` works from the CLI.** Every write tool is imported lazily inside its own CLI command, so a CLI-driven undo ran in a process where the inverse tool was never registered and failed with "inverse tool is not registered" — for every write tool. Only the MCP entry point, which imports the whole server, worked. Found while live-verifying against a real cluster.
- **An undetermined outcome is audited `unknown`, not `ok`.** The harness only classified a result as undetermined when the payload *also* carried an `error` key, so a write that looked successful but had not been confirmed was recorded as a success.


## v0.6.0 — 2026-07-21

### Changed (BREAKING)
- **Removed the authorization layer** — read-only mode, the approver gate, and rules.yaml deny are gone. The skill no longer decides read vs write; that is the agent's judgement or the connecting account's permissions. `<PREFIX>_READ_ONLY` now has no effect (a startup warning is logged); `<PREFIX>_AUDIT_APPROVED_BY`/`_RATIONALE` are optional audit annotations.
- The retained guarantee is **unbypassable audit over MCP and CLI alike** — no unaudited entry point. Harness = audit + runaway safety guard + undo + sanitize; `risk_level` is a descriptive audit label, not a gate.

See RELEASE_NOTES.md for tool-specific changes.


## v0.5.0 — 2026-07-20

### Fixed
- Harness: a write whose response is lost is audited `status=unknown`, not `error` — it may have taken effect. Undo tokens gain `effectVerified` (undo.db migrated in place).
- Harness: a dry-run no longer records an undo token, and no longer requires a named approver. Guards now run on the preview path.
- Truncated strings end in an ellipsis instead of being cut silently; error messages are capped at 800 chars, not 300.

See RELEASE_NOTES.md for the full detail.

## v0.3.0 — 2026-07-17

### Added
- **New:** ISO/IEC 27001:2022 + 等保2.0 (DJCP L3) framework mappings + bundle scheduling hints.
- **Undo executor**: `undo list` / `undo apply <id>` (CLI + MCP) — apply a recorded replayable inverse; the dispatched inverse is re-gated by its own risk tier; single-use, dry-run, double-confirm, both wrapper + inverse audited.

## v0.2.1 — 2026-07-16

### Fixed
- **`secrets.enc` now follows `COMPLIANCE_AIOPS_HOME`** (secretstore hardcoded the real
  home directory; config/audit/undo already relocated — found in live verification).
- **Audit fidelity**: failures sanitized into `{"error": ...}` results by the MCP error
  layer are now audited as `status=error` (they previously read as `ok`, hiding failed
  attempts from exception reports), and no undo is recorded for a call that failed.

### Tests
- `doctor` and the `init` wizard are now fully covered (previously ~10–20%); plus a
  regression test for the sanitized-failure audit status.

## v0.2.0 — 2026-07-13

Security-hardening release from a line-wide code review.

### Changed (behavior)
- **Secure by default**: with no `rules.yaml`, high/critical operations now require a
  named approver (`COMPLIANCE_AUDIT_APPROVED_BY`). A fresh install no longer allows
  destructive writes unattended; `init` seeds a starter `rules.yaml` you can edit,
  and an operator-authored rules file is honoured as-is.
- `__version__` is now single-sourced from package metadata (the previous release
  self-reported a stale version string).
- Sanitize docs no longer overstate scope: it strips control/format characters and
  truncates; semantic prompt-injection resistance must come from the consuming agent.

### Fixed
- Evidence-bundle `out_path` is confined to the configured bundle directory (path-traversal fix; escapes raise a teaching error).

### Tests
- Governance persistence is now tested against REAL `audit.db`/`undo.db` files
  (write → audit row + inverse undo row with captured prior state).
- The CLI confirmed-write path (dry-run / double-confirm / governed execution) is
  covered end-to-end.
- `pytest-cov` added to the dev dependencies.

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
