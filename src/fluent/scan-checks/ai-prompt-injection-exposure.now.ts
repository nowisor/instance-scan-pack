import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiPromptInjectionExposureCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-prompt-injection-exposure'],
    name: 'Prompt-Injection Exposure Via Input Binding',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Fires only when BOTH a user-editable free-text field is bound into an agent prompt context AND that agent holds write ACL reach',
    description:
        "The heuristic is fixed by specification and both conditions are required. (a) an input binding or flow variable maps a user-editable free-text field - work_notes, comments, description, short_description, or an inbound email body - into the entity's instruction context. (b) that same entity's permission envelope includes write ACL reach on any table. Either alone is not reported: free text reaching a read-only agent is a disclosure question, and write reach without an untrusted input source is ordinary configuration. The exposure is the conjunction - untrusted text steering an actor that can change state. Bindings are read from resolved binding tables only; where they cannot be resolved on the release the check emits N/A and never infers what an agent reads from its name or description.",
    resolutionDetails: `The finding names the binding, the source field, and the writable target for every hit.

1. Remove the untrusted field from the agent's prompt context where the use case does not require it
2. Where it is required, sanitise or delimit it so injected text cannot be read as instruction, and constrain what the agent may do with the result
3. Reduce the agent's write reach - an agent that cannot write cannot be steered into writing
4. Add a human gate on the write path (see the human-in-the-loop check)

Framework mapping:
- NIS2 Article 21(2)(a): policies on risk analysis and information system security
- NIS2 Article 21(2)(e): security in acquisition, development, and maintenance
- ISO 27001 A.8.28: secure coding
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM01:2025 Prompt Injection, LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0051 LLM Prompt Injection, AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-prompt-injection-exposure.js'),
})
