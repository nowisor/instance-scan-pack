import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiGovernanceUnconfiguredCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-governance-unconfigured'],
    name: 'AI Governance Layer Deployed But Unconfigured',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags AI Control Tower or an equivalent governance layer present with an empty registry, no active policy records, or coverage short of the active agent estate',
    description:
        "Native tooling gives customers controls; this check verifies the controls are actually configured. It reports on the governance layer rather than through it, and reproduces nothing the layer itself reports. A deployed-but-empty governance layer is worse than none, because a populated-looking dashboard manufactures the confidence that stops anyone looking for what it does not cover. The precondition mirrors the registry-coverage check: a governance layer must be PRESENT for this to fire, and on an instance without one the check reports not_applicable. Between the two checks, an absent layer produces one honest N/A pair rather than two findings about the same gap - deployed-and-empty is this check's finding, deployed-and-incomplete is the other's.",
    resolutionDetails: `1. Populate the registry so every agentic entity in the instance has an entry with a named owner - the registry-coverage check enumerates what is missing
2. Activate the policy set. An empty policy table means the layer is observing without governing
3. Confirm observability covers every active agent class the finding lists, including the inbound external-agent surface if present
4. Set a review cadence; coverage decays every time somebody builds an agent without registering it

Framework mapping:
- NIS2 Article 21(2)(a): policies on risk analysis and information system security
- NIS2 Article 21(2)(f): policies and procedures to assess the effectiveness of cybersecurity risk-management measures
- ISO 27001 A.5.15: access control
- ISO 27001 A.8.16: monitoring activities
- DORA Article 9(4)(a): develop and document an information security policy
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0103 Deploy AI Agent
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-governance-unconfigured.js'),
})
