# AI and agent security — category overview

**Group:** `ai-agent-security` · **17 checks** · **3 sensors** · new in pack v1.2.0

Audits the agentic surface of a ServiceNow instance: what AI agents exist, what
they are allowed to do, whether anyone owns them, and whether the governance
layer the organisation believes covers them actually does.

## What this group is for

The space is not empty — AppOmni ships runtime prompt blocking, ServiceNow's own
AI Control Tower does discovery and observability, Zenity owns cross-platform
agent governance. This group deliberately does **not** compete on any of those.
It covers three things the incumbents do not:

1. **Usage-corroborated least privilege inside ServiceNow's permission model.**
   Not "this agent looks over-privileged" but "this agent holds
   `sys_user_has_role` write and has not exercised it in 90 days of verified log
   coverage — here is the grant to revoke."
2. **EU regulatory evidence.** EUR-Lex-verified NIS2 and DORA mappings, plus a
   conservatively-scoped EU AI Act layer, producing artifacts an auditor accepts.
3. **The inbound agent surface.** Action Fabric and MCP Server let an agent built
   anywhere act inside the instance headlessly. That surface is newer than most
   incumbent check libraries.

**Governance of governance.** Where native tooling provides a control, this group
verifies the control is configured and covering the estate — it never duplicates
what AI Control Tower reports.

## Non-goals

No runtime enforcement of any kind: no inline proxy, no prompt firewall, no
blocking. No LLM model scanning. No rebuilding Control Tower's reporting. No
coverage of non-ServiceNow agent platforms — though external agents *entering*
the instance are in scope regardless of where they were built. The boundary is
the instance, not the agent's birthplace.

## The honesty rules

These are the reason to trust the output, so they are stated plainly.

**An absent plugin produces `N/A`, never PASS.** The absence of Now Assist is not
a security win; it means the control is out of scope. A silent pass would let a
customer believe they were assessed on something never examined.

**An unresolvable field produces `N/A`, not a finding.** Where a release does not
expose the column a check needs, the check says so and names it. Firing anyway
would flag healthy instances on releases we simply cannot read.

**Detection is enumeration-driven.** Table and field names are resolved from
`sys_db_object` and `sys_dictionary` on your instance, never hardcoded. The
`sn_aia` namespace is paid-SKU gated and cannot be verified against a developer
instance, so asserting its identifiers from documentation alone is not something
we are willing to do.

**Nothing claims more than it observed.** Two checks are INVESTIGATE-only by
design: sub-production masking posture (a connected scan cannot see whether a
clone was masked, and this pack will not sample your records to guess) and the
agent kill-switch (a documented procedure is not scannable, so it is attested,
not failed).

## Checks

### Inventory (AIA-001..009)

| Check | Spec | Sev | What it flags |
|---|---|---|---|
| `nowisor-ai-agent-unowned` | AIA-001 | HIGH | Owner field exists and is blank |
| `nowisor-ai-agent-unreviewed-prod` | AIA-002 | HIGH | Active in prod with no review or approval record |
| `nowisor-ai-shadow-llm-endpoint` | AIA-003 | CRITICAL | External model endpoint outside the Gen AI Controller |
| `nowisor-ai-subprod-unmasked-posture` | AIA-004 | INVESTIGATE | Non-prod + agentic surface + no data preservers |
| `nowisor-ai-dormant-skill-grants` | AIA-005 | MEDIUM | Inactive agent whose identity keeps its roles |
| `nowisor-ai-shared-runas-identity` | AIA-006 | HIGH | Multiple agents sharing one execution identity |
| `nowisor-ai-agent-elevated-runas` | AIA-007 | CRITICAL | Execution identity holds admin / security_admin |
| `nowisor-ai-inbound-agent-ungoverned` | AIA-008 | CRITICAL | Inbound MCP / Action Fabric agent absent from the catalog |
| `nowisor-ai-control-tower-coverage-gap` | AIA-009 | HIGH | Agents absent from a deployed Control Tower registry |

### Guardrail and governance posture (AIG-001..008)

| Check | Spec | Sev | What it flags |
|---|---|---|---|
| `nowisor-ai-guardrail-hitl` | AIG-001 | HIGH | Write-capable agent with no human gate |
| `nowisor-ai-llm-payload-masking` | AIG-002 | HIGH | No data-protection control over agent-readable data |
| `nowisor-ai-agent-audit-retention` | AIG-003 | HIGH | Agent logging off, or retention below the 90-day floor |
| `nowisor-ai-prompt-injection-exposure` | AIG-004 | CRITICAL | Untrusted free-text bound into prompt context **and** write reach |
| `nowisor-ai-kill-switch-absent` | AIG-005 | INVESTIGATE | No machine-checkable deactivation path |
| `nowisor-ai-llm-data-residency` | AIG-006 | HIGH | Non-EU model endpoint on an EU-flagged instance |
| `nowisor-ai-mcp-exposure-scope` | AIG-007 | HIGH | Over-broad tool packages / non-expiring OAuth clients |
| `nowisor-ai-governance-unconfigured` | AIG-008 | HIGH | Governance layer deployed but empty |

AIG-004 fires only when **both** conditions hold — a user-editable free-text
field bound into the entity's instruction context **and** write ACL reach on that
entity. Either alone is not reported.

## Sensors

| Sensor | Emits | Purpose |
|---|---|---|
| `tools/ai-discovery-export.js` | `---NOWISOR_AIDISCOVERY---` | Plugins, namespace scan, per-table field resolution, Control Tower + MCP state, log-source retention floors |
| `tools/ai-bom-export.js` | `---NOWISOR_AIBOM---` | One record per agentic entity with NHI lifecycle attributes |
| `tools/ai-usage-export.js` | `---NOWISOR_AIUSAGE---` | Permission envelope + invocation evidence for least-privilege correlation |

All three are pure sensors: read-only, no verdicts, no correlation logic. Each
respects a query budget and reports a truncated run rather than passing it off as
complete.

## Deliverables

**AI Agent Bill of Materials** — `ai_bom.json` plus a CycloneDX 1.6 export built
on the official model classes, validated by an independent checker. See
[`docs/aibom-field-mapping.md`](../../../docs/aibom-field-mapping.md). Carries a
completeness score (resolved/6 per entity, unweighted) and a confidentiality
cover note, because the file necessarily contains internal record identifiers and
the full outbound endpoint inventory.

**Agent Least-Privilege Report** — per agent-permission pair: EXERCISED,
DORMANT, INVESTIGATE, or UNKNOWN-USAGE.

A `DORMANT` verdict is the only one that licenses a revocation, and it is
reachable **only** when telemetry provably spans the whole lookback window.
Partial retention degrades to `UNKNOWN-USAGE` with the shortfall stated.
Recommending a revocation on an artifact of log retention is how a read-only
scanner talks somebody into breaking production, so the gate is not optional.

Where no usage telemetry is supplied at all, the report still runs in
**permission-envelope-only** mode: every pair UNKNOWN-USAGE, zero DORMANT, and a
banner naming the sensor to run.

## Framework mappings

NIS2 Art.21(2) and DORA are EUR-Lex-verified. OWASP LLM Top 10 (2025) and MITRE
ATLAS technique ids are taken from the published lists. EU AI Act is mapped
conservatively — Art.4 and Art.50 by default; Art.26 always carries a
"if high-risk under Annex III" qualifier, because most ITSM workflow agents are
not high-risk under Annex III and claiming otherwise would not survive review.

OWASP Agentic threat ids are deliberately **omitted** until they can be cited
version-pinned against the OWASP source.

## Tier gating

| Tier | Access |
|---|---|
| Recon (free) | Two counts + aggregate AI-BOM completeness, paste-driven |
| Practitioner+ | Full findings, AI-BOM, CycloneDX export |
| Practice+ | Agent Least-Privilege correlation |
