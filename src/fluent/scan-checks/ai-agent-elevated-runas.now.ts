import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiAgentElevatedRunasCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-agent-elevated-runas'],
    name: 'AI Agent Runs As Elevated Identity',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Flags agentic entities whose execution identity holds admin, security_admin or equivalent - the agent\'s blast radius is its run-as role set, not its prompt',
    description:
        "An agent's blast radius is defined by its run-as identity's roles, not by its instructions. An agent executing as an admin-role holder can be steered - by prompt injection, a poisoned tool description, or a misrouted flow - into any write the admin role permits, and the audit trail will attribute the result to the service account rather than to whoever supplied the input. The check resolves the run-as column from sys_dictionary and reads role grants with their lineage. It is delegation-aware: where every elevated role reached the identity through derived or out-of-box inheritance rather than an explicit grant, the finding is capped at CONDITIONAL, because the pack cannot read the customer's intent for a role it did not observe being granted. Rating an OOB-derived grant as CRITICAL is the false positive the delegation-aware severity model exists to prevent.",
    resolutionDetails: `For each flagged agent:
1. Determine the minimum table and field reach the agent actually needs
2. Create a dedicated service identity per agent (see the shared-run-as-identity check) and grant only that reach
3. Remove admin / security_admin from the agent's execution identity
4. Where the finding is CONDITIONAL, first establish whether the role inheritance is intentional - confirm the lineage before revoking anything

Do not revoke on the strength of this finding alone where lineage is derived: check the role-contains chain named in the evidence.

Framework mapping:
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- ISO 27001 A.5.15: access control
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0012 Valid Accounts, AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 26 (deployer obligations) applies only if the deployment qualifies as high-risk under Annex III

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-agent-elevated-runas.js'),
})
