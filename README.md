<!-- mcp-name: io.github.AIops-tools/compliance-aiops -->

# Compliance AIops (preview)

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by any framework body or GRC vendor.** HIPAA, PCI-DSS, SOC 2, GDPR and OSCAL are referenced descriptively; the frameworks and trademarks belong to their owners. MIT licensed.

Governed **compliance-evidence** tooling for AI-agent infrastructure ops. It
**reads the audit trails your governed AIops agents already write** — the local
`~/.<tool>-aiops/audit.db` SQLite trails, all sharing one `audit_log` schema —
and turns that activity into **framework-mapped, hash-chain-sealed compliance
evidence**. It **never scans your infrastructure and never replaces a GRC
platform**: it converts the trails you already produce into auditor-ready,
tamper-evident evidence bundles.

Unlike the other tools in the AIops-tools line it is **not a platform wrapper**:
**no external API, no network, no platform credentials**. Its only inputs are
those on-disk audit databases, read **read-only**. That also makes it the
easiest-to-self-test tool in the line — fully offline and deterministic.

> **Preview.** Evidence, not certification. Fully offline; the source `audit.db`
> files remain the system of record. OSCAL export is a documented v0.2 roadmap
> item (v0.1 emits JSON + Markdown + CSV shaped to ease a future OSCAL
> Assessment-Results adapter).

## Key features

- **Framework mapping with honest evidence-strength** — audit events map to
  **HIPAA §164.312 / PCI-DSS v4.0 / SOC 2 TSC / GDPR** controls. Audit trails
  prove *operating effectiveness* strongly but *control design / configuration*
  only partially, and each control is labelled `strong` or `partial`.
  `gap_analysis` says so per control, with the caveat and a remediation hint.
- **Hash-chain-sealed evidence bundles** — SHA-256 over ordered records
  (`hash = SHA-256(prev_hash ‖ canonical_json(record))`, genesis prev = 64
  zeros). The `chainHead` is **reproducible** for the same (framework, period,
  sources). `verify_bundle` catches tampering; `verify_source_chain` detects
  row-id gaps / deletions in a source trail. An optional HMAC signature seals a
  bundle under a stored signing key.
- **Zero-network, read-only** — no credentials, no outbound calls, no mutation
  of the source trails. Bundles are the only thing written, under
  `~/.compliance-aiops/bundles/`.
- **Deterministic, test-verified integrity** — the integrity claims are
  themselves covered by tests: synthetic audit DBs are built through the real
  governance-harness `AuditEngine`, a golden reproducible `chainHead` is
  asserted, and tamper tests confirm detection. No live infrastructure needed.

## Tools (15 MCP tools)

### Read / analysis (12)

| Tool | Purpose |
|------|---------|
| `list_audit_sources` | Discovered sibling audit DBs (path, tool, readable, row count) |
| `query_audit_events` | Cross-tool event query — filter by tool/skill/status/risk/approved/selector/since/until |
| `activity_timeline` | Event counts bucketed by hour or day |
| `list_frameworks` | Supported frameworks + control counts |
| `coverage_summary` | Per-control covered/weak/uncovered for ONE framework |
| `control_evidence` | Evidence rows + population + a reproducible query for ONE control |
| `gap_analysis` | Controls with no/weak evidence + honest caveat + remediation |
| `approval_report` | High-risk write ops + who approved + rationale (the CC8.1 / PCI 7-8 / HIPAA §312(a) artifact) |
| `exceptions_report` | Denied / error / budget_exceeded ops — enforcement + anomaly evidence |
| `verify_source_chain` | Chain head + row-id gap detection for one source |
| `verify_bundle` | Verify a sealed bundle: chain + seal head + optional signature |
| `list_bundles` | Bundles under `~/.compliance-aiops/bundles/` |

### Write / artifact (3 — no external mutation)

| Tool | Risk | Purpose |
|------|:---:|---------|
| `generate_evidence_bundle` | low | One call: coverage + approval trail + exceptions + sealed records → a bundle `.json` |
| `export_bundle` | low | Render a bundle to markdown / csv / json |
| `sign_bundle` | medium | HMAC over the seal using the stored signing key |

The CLI exposes a convenience subset; the full 15-tool surface is available over MCP.

## Frameworks & controls

| Framework | Sample controls (strength) |
|-----------|----------------------------|
| **HIPAA** (§164.312) | 164.312(b) Audit controls (strong), 164.312(a)(1) Access control (strong), 164.312(c)(1) Integrity (strong) |
| **PCI-DSS v4.0** | 10.2 Audit log content (strong), 10.3 Protect audit logs (strong), 7-8 Least privilege / authn (partial) |
| **SOC 2 TSC** | CC6.1 Logical access (strong), CC7.2 Monitoring (strong), CC8.1 Change management (strong) |
| **GDPR** | Art.30 Records of processing (partial), Art.32 Security of processing (strong) |

## Install

```bash
uv tool install compliance-aiops      # or: pipx install compliance-aiops
```

## Quick start

```bash
compliance-aiops init                 # discover sibling ~/.*-aiops/audit.db, set org name, optional signing key
compliance-aiops doctor               # which sibling audit DBs are present/readable
compliance-aiops overview             # audit sources + per-framework covered/total
compliance-aiops report coverage soc2 # per-control SOC 2 coverage
compliance-aiops bundle generate soc2 # sealed evidence bundle → ~/.compliance-aiops/bundles/
compliance-aiops bundle verify <path> # re-verify the chain + seal (+ signature)
```

Run as an MCP server (stdio):

```bash
export COMPLIANCE_AIOPS_MASTER_PASSWORD=...   # only needed to unlock a signing key
compliance-aiops mcp                          # or: compliance-aiops-mcp
```

## Integrity & honest limits

- **Tamper-EVIDENT, not tamper-PROOF.** The hash chain and optional signature
  let an auditor *detect* alteration; they do not prevent it. The source
  `audit.db` files remain the system of record — record the `chainHead`
  out-of-band if you need an independent anchor.
- **Operating effectiveness vs. design.** An audit trail strongly evidences that
  a control *ran* (samples, approvals, denials) but only partially evidences that
  a control is *designed / configured* correctly (e.g. MFA required,
  least-privilege roles). Every control carries a `strong` / `partial` label and
  `gap_analysis` surfaces the caveat rather than overclaiming.

## Supported scope & limitations (preview)

- **Evidence, not certification.** This produces auditor-ready evidence bundles;
  it does not issue attestations, opinions, or certifications.
- **In scope:** the four frameworks above, over the `audit_log` trails written by
  governed AIops tools discovered via `~/.*-aiops/audit.db`.
- **Not in scope:** it does **not** scan infrastructure, connect to any platform,
  or replace a GRC platform. For platform operations use the other AIops-tools.
- **OSCAL export is v0.2.** v0.1 emits JSON + Markdown + CSV.
- **Preview:** interfaces may change before v1.0.

## Missing a capability?

Want another framework, control mapping, export format (OSCAL, CSV shape), or a
verification you don't see here? **Open an issue or a PR — contributions
welcome.**
