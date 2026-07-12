---
name: compliance-aiops
description: >
  Use this skill whenever the user needs compliance evidence from the audit trails their governed AIops agents already write — mapping AI-agent infra-ops activity to HIPAA §164.312, PCI-DSS v4.0, SOC 2 TSC, or GDPR controls, producing a change-approval report, a gap analysis, an exceptions/anomaly report, or a hash-chain-sealed, tamper-evident evidence bundle.
  Always use this skill for "compliance evidence", "HIPAA / PCI-DSS / SOC 2 / GDPR evidence", "audit trail report", "coverage for control X", "which controls are we short on / gap analysis", "who approved this change / change-management evidence", "denied or errored ops / anomaly evidence", "seal / sign an evidence bundle", "prove this bundle wasn't altered", or "detect deleted audit rows".
  Do NOT use to scan or operate infrastructure and do NOT treat it as a GRC platform — it reads the local audit databases the OTHER AIops-tools write and converts them to evidence; for platform operations use those other AIops-tools.
  Preview — evidence, not certification. Reads sibling audit trails read-only; no external API, no network, no platform credentials. Fully offline and deterministic.
installer:
  kind: uv
  package: compliance-aiops
argument-hint: "[framework (hipaa|pci_dss|soc2|gdpr) or describe your evidence task]"
allowed-tools:
  - Bash
metadata: {"openclaw":{"requires":{"env":["COMPLIANCE_AIOPS_CONFIG"],"bins":["compliance-aiops"],"config":["~/.compliance-aiops/config.yaml"]},"optional":{"env":["COMPLIANCE_AIOPS_MASTER_PASSWORD"],"config":["~/.compliance-aiops/secrets.enc"]},"primaryEnv":"COMPLIANCE_AIOPS_CONFIG","homepage":"https://github.com/AIops-tools/Compliance-AIops","emoji":"📋","os":["macos","linux"]}}
compatibility: >
  Standalone compliance-evidence tooling (preview). The governance harness (audit, policy, token/runaway budget, undo, risk-tiers) is bundled in the package — no external skill-family dependency.
  Data source: the LOCAL audit databases the other governed AIops tools already write, discovered by glob at ~/.*-aiops/audit.db (one shared audit_log schema). These are read READ-ONLY. There is NO external API, NO network, and NO platform credentials.
  The only optional secret is a bundle-signing key, stored ENCRYPTED in ~/.compliance-aiops/secrets.enc (Fernet/AES-128 + scrypt-derived key) — never plaintext on disk, unlocked by a master password from COMPLIANCE_AIOPS_MASTER_PASSWORD (non-interactive/MCP/CI) or an interactive prompt (CLI on a TTY). If you never sign bundles you need no secret at all.
  Outputs: evidence bundles written to ~/.compliance-aiops/bundles/ (the only files written). All tool calls are themselves audited to a local SQLite DB under ~/.compliance-aiops/ (relocatable via COMPLIANCE_AIOPS_HOME). Write tools (generate_evidence_bundle, export_bundle: low risk; sign_bundle: medium) pass through the @governed_tool decorator but perform NO external mutation.
  Integrity: bundles are hash-chain-sealed (SHA-256 over ordered records; reproducible chainHead) with an optional HMAC signature. Tamper-EVIDENT, not tamper-PROOF — the source audit.db remains the system of record.
  Webhooks: none — no outbound network calls at all.
  Transitive dependencies: the MCP SDK and cryptography (Fernet). No post-install scripts or background services.
  PREVIEW: evidence, not certification. Fully offline and deterministic. OSCAL export is a v0.2 roadmap item (v0.1 emits JSON/Markdown/CSV).
---

# Compliance AIops (preview)

> **Disclaimer**: Community-maintained open-source project, **not affiliated with, endorsed by, or sponsored by any framework body or GRC vendor.** HIPAA, PCI-DSS, SOC 2, GDPR and OSCAL are referenced descriptively; trademarks belong to their owners. Source at [github.com/AIops-tools/Compliance-AIops](https://github.com/AIops-tools/Compliance-AIops) under the MIT license.

Governed **compliance-evidence** tooling — **15 MCP tools**. It **reads the audit
trails your governed AIops agents already write** (`~/.<tool>-aiops/audit.db`, one
shared `audit_log` schema, discovered via `~/.*-aiops/audit.db`) **read-only**,
and turns that activity into **framework-mapped, hash-chain-sealed compliance
evidence**. It does **not** scan infrastructure and does **not** replace a GRC
platform.

> **Standalone**: the governance harness is bundled (`compliance_aiops.governance`).
> **Not a platform wrapper** — no external API, no network, no platform
> credentials. **Preview**: evidence, not certification; fully offline and
> deterministic.

## What This Skill Does

| Group | Tools | Count | Read/Write |
|-------|-------|:-----:|:----------:|
| **Audit reads** | `list_audit_sources`, `query_audit_events`, `activity_timeline` | 3 | read |
| **Framework mapping** | `list_frameworks`, `coverage_summary`, `control_evidence`, `gap_analysis` | 4 | read |
| **Assurance reports** | `approval_report`, `exceptions_report` | 2 | read |
| **Integrity** | `verify_source_chain`, `verify_bundle`, `list_bundles` | 3 | read |
| **Artifacts** | `generate_evidence_bundle` (low), `export_bundle` (low), `sign_bundle` (medium) | 3 | write (no external mutation) |

## Frameworks & sample controls

| Framework | Sample controls (strength) |
|-----------|----------------------------|
| **HIPAA** §164.312 | 164.312(b) Audit controls (strong), 164.312(a)(1) Access control (strong), 164.312(c)(1) Integrity (strong) |
| **PCI-DSS v4.0** | 10.2 Audit log content (strong), 10.3 Protect audit logs (strong), 7-8 Least privilege / authn (partial) |
| **SOC 2 TSC** | CC6.1 Logical access (strong), CC7.2 Monitoring (strong), CC8.1 Change management (strong) |
| **GDPR** | Art.30 Records of processing (partial), Art.32 Security of processing (strong) |

Audit trails prove *operating effectiveness* strongly but *control design /
configuration* only partially — each control is labelled `strong` or `partial`,
and `gap_analysis` surfaces the caveat rather than overclaiming.

## Quick Install

```bash
uv tool install compliance-aiops
compliance-aiops init       # discover sibling ~/.*-aiops/audit.db, set org name, optional signing key
compliance-aiops doctor     # which sibling audit DBs are present/readable
```

## When to Use This Skill

- Map AI-agent infra-ops activity to a framework's controls (`coverage_summary`)
- Pull the evidence rows + population for one control (`control_evidence`)
- Find controls with no or weak evidence, with the honest caveat (`gap_analysis`)
- Produce a change-approval artifact — who approved which high-risk write and why
  (`approval_report`)
- Produce enforcement / anomaly evidence — denied / errored / budget-tripped ops
  (`exceptions_report`)
- Seal a tamper-evident evidence bundle (`generate_evidence_bundle`,
  `sign_bundle`) and later prove it wasn't altered (`verify_bundle`)
- Detect deleted / missing audit rows in a source trail (`verify_source_chain`)

**Do NOT use** to scan or operate infrastructure, or as a GRC platform. It reads
the audit DBs the *other* AIops-tools write; for platform operations use those
other AIops-tools.

## Related Skills — Skill Routing

| If the user wants… | Use |
|--------------------|-----|
| Compliance evidence from existing AIops audit trails | **compliance-aiops** (this skill) |
| To actually operate a platform (VMs, storage, clusters, network, …) | the relevant platform **AIops-tools** skill |
| OT / industrial edge (Modbus, OPC-UA, PLC) | the **industrial-aiops** line |
| A full GRC platform / policy management | out of scope — this is evidence, not GRC |

## Common Workflows

### Produce a SOC 2 CC8.1 change-approval bundle for Q3

1. `compliance-aiops report coverage soc2` → confirm CC8.1 is covered
2. `compliance-aiops report approvals` → high-risk write ops + approver + rationale
3. `compliance-aiops bundle generate soc2 --since 2026-07-01 --until 2026-10-01 [--sign]`
   → a hash-chain-sealed bundle under `~/.compliance-aiops/bundles/`
4. `compliance-aiops bundle export <path> --format markdown` → auditor-facing report

### Which controls are we short on?

1. `compliance-aiops report gaps hipaa` (or `pci_dss` / `soc2` / `gdpr`) →
   controls with no or weak evidence, each with an honest caveat and remediation
2. Drill into one control's population with `control_evidence` (MCP) to see the
   reproducible query behind the coverage number

### Prove this bundle wasn't altered

1. `compliance-aiops bundle verify <path>` → re-derives the chain, compares the
   seal `chainHead`, and checks the optional signature
2. Because the chain is over evidence records only, the same (framework, period,
   sources) reproduces the same `chainHead` — record it out-of-band as an anchor

### Detect deleted audit rows

Use `verify_source_chain` (MCP) on a source: it returns the chain head and flags
**row-id gaps** — a sign that rows were deleted from that `audit.db`.

## Governance & Safety

- Every tool call is audited to `~/.compliance-aiops/audit.db` (relocatable via
  `COMPLIANCE_AIOPS_HOME`).
- The source audit trails are opened **read-only**; the tool never mutates them.
  The only files written are bundles under `~/.compliance-aiops/bundles/`.
- **Tamper-EVIDENT, not tamper-PROOF** — the source `audit.db` remains the system
  of record.

## References

- `references/capabilities.md` — full tool → inputs → returns reference
- `references/cli-reference.md` — CLI command reference
- `references/setup-guide.md` — source discovery, org name, optional signing key, integrity notes
