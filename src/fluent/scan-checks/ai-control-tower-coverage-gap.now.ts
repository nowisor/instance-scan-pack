import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiControlTowerCoverageGapCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-control-tower-coverage-gap'],
    name: 'AI Control Tower Registry Coverage Gap',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags agentic entities running in the instance but absent from the AI Control Tower registry, when Control Tower is deployed',
    description:
        "Native tooling gives customers the control; this check verifies the control actually covers the estate. It deliberately reproduces nothing AI Control Tower reports - no risk scores, no observability, no policy content - and answers the single question Control Tower cannot answer about itself: what is running here that was never registered. This is the unregistered-agent evaluation scenario, so the evidence names where each entity was found and where it was expected, making the answer auditable in one read. Control Tower being deployed is a hard precondition: on an instance without it the check reports not_applicable, because 'you have no governance layer' is the governance-configuration check's finding and reporting every agent as an uncovered gap here would double-count the same defect.",
    resolutionDetails: `For each uncovered entity:
1. Confirm the entity is legitimate and has a named owner
2. Register it in AI Control Tower so the governance layer's inventory matches the instance
3. Where the entity is not recognised, treat it as an unsanctioned deployment: deactivate it and review who created it (the evidence carries sys_created_by and sys_created_on)
4. Re-run this check after registration to confirm full coverage

Matching is by normalised name, so an asset registered under a different label will still appear here. Confirm each entity before acting.

Framework mapping:
- NIS2 Article 21(2)(f): policies and procedures to assess the effectiveness of cybersecurity risk-management measures
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.5.16: identity management
- ISO 27001 A.8.16: monitoring activities
- DORA Article 9(4)(a): develop and document an information security policy
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0103 Deploy AI Agent
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-control-tower-coverage-gap.js'),
})
