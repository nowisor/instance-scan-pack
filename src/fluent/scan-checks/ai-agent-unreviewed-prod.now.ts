import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiAgentUnreviewedProdCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-agent-unreviewed-prod'],
    name: 'Active AI Agent With No Review Or Approval Trail',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags agents active on a production-looking instance with no review field value and no approval record - nothing accepted their permissions, prompt or autonomy level',
    description:
        "An agent running in production without an approval trail has no point at which anyone accepted its permissions, its prompt, or its autonomy level - and nothing to re-check when any of those change. The check reads review state from the resolved review/approval field plus approval records, and deliberately does NOT treat a recent sys_updated_on as evidence of review: an agent edited yesterday by the person who built it is not a reviewed agent, and inferring approval from activity would make the check pass exactly where governance is weakest. Production detection is an instance_name token heuristic and is labelled as one; where the instance does not report a name, the finding drops to INVESTIGATE rather than asserting a production control failure. Where the release exposes no review field at all, the result is not_applicable - the platform is not recording review state, so its absence is not evidence of a gap.",
    resolutionDetails: `For each unreviewed agent:
1. Review the agent's permissions, prompt/instructions, tool access and autonomy level
2. Record the outcome where the platform can see it - the resolved review field, or an approval record against the agent
3. Set a recurring review interval; agents drift as their tools and data reach change
4. Where the agent is not recognised, treat it as an unsanctioned deployment (the evidence carries sys_created_by and sys_created_on)

Framework mapping:
- NIS2 Article 21(2)(e): security in network and information systems acquisition, development, and maintenance
- NIS2 Article 21(2)(f): policies and procedures to assess the effectiveness of cybersecurity risk-management measures
- ISO 27001 A.5.16: identity management
- ISO 27001 A.8.25: secure development life cycle
- DORA Article 9(4)(a): develop and document an information security policy
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0081 Modify AI Agent Configuration, AML.T0103 Deploy AI Agent
- EU AI Act Article 26 (deployer obligations) applies only if the deployment qualifies as high-risk under Annex III

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-agent-unreviewed-prod.js'),
})
