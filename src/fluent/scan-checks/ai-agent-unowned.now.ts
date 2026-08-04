import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiAgentUnownedCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-agent-unowned'],
    name: 'AI Agent Without Assigned Owner',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags agentic entities whose owner field exists on this release but is blank - no accountable owner for the agent\'s permissions, prompt, or decommissioning',
    description:
        "An agentic entity with no assigned owner has nobody accountable for the permissions it holds, the prompt that steers it, or the decision to retire it - and it is operationally indistinguishable from an agent an attacker deployed. This is the non-human-identity ownership gap applied to ServiceNow agents. The check resolves the owner column from sys_dictionary rather than assuming a name, because the sn_aia namespace is paid-SKU gated and cannot be verified against a PDI. It fires ONLY where the owner column exists and is empty: where the release has no owner column at all it reports not_applicable, since absence of the field is not evidence of an ownership gap.",
    resolutionDetails: `For each flagged entity:
1. Open the agent record in AI Agent Studio (or the source table named in the finding evidence)
2. Set the owner / owned-by field to a named person or group with authority over the agent's permissions
3. Record the owner in your AI asset catalog (AI Control Tower, if deployed) so registration and ownership agree

The finding evidence names the exact column that supplied each verdict (owner_fields_resolved), so every value is auditable back to a real field.

Framework mapping:
- NIS2 Article 21(2)(i): human resources security, access control policies, and asset management
- ISO 27001 A.5.16: identity management - the full lifecycle of identities is managed
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0103 Deploy AI Agent
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-agent-unowned.js'),
})
