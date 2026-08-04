import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiAgentAuditRetentionCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-agent-audit-retention'],
    name: 'Agent Action Logging Disabled Or Below Retention Floor',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags auditing disabled on agent tables, a missing execution-log table, or retention shorter than the 90-day correlation lookback',
    description:
        "Two failure modes, reported distinctly. Auditing switched off is the obvious one. Retention shorter than the review window is the silent one: the dashboard shows logs, the control looks satisfied, and evidence older than the window is simply gone. Retention is also the precondition for the entire permission-vs-usage correlation - a DORMANT verdict is only legitimate when retention spans the lookback - so an instance failing this check cannot get evidence-grade privilege reduction at all. The finding states that consequence explicitly, because it is the part customers do not expect.",
    resolutionDetails: `1. Enable auditing on the flagged tables: System Definition > Dictionary, filter Table = <table> with an empty Column name, set Audit = true. Auditing applies to subsequent changes only; history before the toggle cannot be recovered
2. Confirm an agent execution-log source exists and is being written for your agent classes
3. Raise retention on the execution log and on sys_audit to at least 90 days, matching the correlation lookback
4. Re-run the Agent Least-Privilege Report afterwards - permissions that reported UNKNOWN-USAGE can become actionable DORMANT verdicts once coverage spans the window

Framework mapping:
- NIS2 Article 21(2)(b): incident handling - requires logging sufficient to reconstruct an incident
- ISO 27001 A.8.15: logging
- ISO 27001 A.8.16: monitoring activities
- DORA Article 10(1): detection of anomalous activities
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-agent-audit-retention.js'),
})
