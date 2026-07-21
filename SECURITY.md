# Security Policy

## Disclaimer

Community-maintained open-source project. Not a substitute for a GRC program or
legal advice — it produces **evidence from audit trails**, it does not certify
compliance. Framework names (HIPAA, PCI-DSS, SOC 2, GDPR) belong to their
respective bodies. Source is publicly auditable under the MIT license.

## Reporting Vulnerabilities

Report privately via a GitHub Security Advisory on
[github.com/AIops-tools/Compliance-AIops](https://github.com/AIops-tools/Compliance-AIops/security/advisories)
or email zhouwei008@gmail.com. Please do not open public issues for security
reports.

## Security Design

### Data Sources — read-only, no credentials
- compliance-aiops has **no external API and no platform credentials**. Its data
  sources are the sibling AIops tools' audit databases (`~/.<tool>-aiops/audit.db`),
  opened strictly **read-only** (SQLite `mode=ro`). It never writes to a source DB
  — evidence is derived, the originals are untouched.
- The **only** secret it can hold is an **optional bundle-signing key**, stored
  **encrypted** in `~/.compliance-aiops/secrets.enc` (Fernet/AES-128 +
  scrypt-derived key; chmod 600). Evidence bundles are always hash-chain-sealed;
  the signing key only adds a signature. With no key configured the tool works
  fully (chain-only integrity).

### Tamper-evident integrity (and its honest limits)
- Evidence bundles are sealed with a **SHA-256 hash chain** over the ordered
  evidence records (`hash_i = SHA-256(prev_hash || canonical_json(record))`); the
  `chainHead` commits to the whole set. `verify_bundle` / `verify_source_chain`
  recompute the chain and localise the first broken link, plus detect **row-id
  gaps** (possible deletions). An optional HMAC signature over the seal adds
  provenance.
- **A hash chain is tamper-*evident*, not tamper-*proof*.** It detects casual /
  single-row edits against a previously recorded `chainHead` and proves a held
  bundle is unaltered since sealing; it cannot stop an attacker with write access
  to the source DB *and* the ability to re-seal. The source `audit.db` remains the
  source of truth — record the `chainHead` out-of-band.

### Governed Operations
Every MCP tool runs through the bundled `@governed_tool` harness
(`compliance_aiops.governance`):
- **Audit** — every call logged to a local SQLite DB under `~/.compliance-aiops/`
  (relocatable via `COMPLIANCE_AIOPS_HOME`), agent-attributed, secret-redacted.
- **Token/runaway budget** — hard ceilings (`COMPLIANCE_MAX_TOOL_CALLS` /
  `COMPLIANCE_MAX_TOOL_SECONDS`) plus an on-by-default guard that trips a tight
  poll/retry loop, preventing unbounded API consumption (e.g. polling a slow
  session).
- **Risk-tier labelling** — each tool's declared `risk_level` is carried into
  the audit row as a descriptive tier. It labels the row; it does not gate the
  call. Whether a write is permitted is the agent's or the account's decision,
  not the skill's.
- **Recursive self-audit** — compliance-aiops runs through the harness like every
  other tool, so its own evidence-generation activity is itself audited (and is
  evidence-eligible).

### State-Changing Operations
There are **none against external systems**. The only "writes" are local
artifacts: `generate_evidence_bundle` / `export_bundle` write a bundle file under
`~/.compliance-aiops/bundles/` (risk=low), and `sign_bundle` reads the encrypted
signing key (risk=medium). No dry-run/double-confirm is needed because nothing
external is mutated.

### Prompt-Injection Protection
The audit trail is data produced by other tools, so it is treated as untrusted:
all audit-sourced text (tool names, rationale, approver, event fields) passes
through a `sanitize()` truncate + control-character strip before reaching the
agent or a bundle.

### Network Scope
**Zero network.** No webhooks, no telemetry, no outbound calls of any kind — the
tool only reads local SQLite files and writes local artifacts. No post-install
scripts or background services.

## Static Analysis

```bash
uvx bandit -r compliance_aiops/ mcp_server/
uv run ruff check .
```

## Supported Versions

The latest released version receives security fixes. This is a preview (0.x);
pin a version in production.
