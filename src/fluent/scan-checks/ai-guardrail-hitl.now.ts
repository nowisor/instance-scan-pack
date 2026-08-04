import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiGuardrailHitlCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-guardrail-hitl'],
    name: 'AI Agent Can Write Without A Human Gate',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags active agents holding a write-capable role that are neither in supervised execution mode nor covered by an approval record',
    description:
        "An agent that can change state with nobody in the loop turns a model decision directly into a platform write. This check recognises two gates: supervised execution mode (the platform's own control) and an approval record against the entity. It deliberately does NOT accept after-the-fact log review as a gate, because reviewing a write after it lands is not being in the loop. Write capability is evaluated from the run-as identity's roles rather than from the agent's instructions, because roles are what actually bound the agent - an identity holding no roles cannot write whatever its prompt says, and is not reported.",
    resolutionDetails: `For each ungated agent:
1. Switch the agent to supervised execution mode if the platform offers it for that class
2. Otherwise insert an approval activity into the flow the agent triggers, so a human accepts the action before it commits
3. Where neither is practical, reduce the agent's write reach until the unattended action is acceptable - an agent that can only read needs no gate

Framework mapping:
- NIS2 Article 21(2)(a): policies on risk analysis and information system security
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- ISO 27001 A.5.15: access control
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 26 (deployer obligations) applies only if the deployment qualifies as high-risk under Annex III

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-guardrail-hitl.js'),
})
