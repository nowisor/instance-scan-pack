import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiSharedRunasIdentityCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-shared-runas-identity'],
    name: 'Multiple AI Agents Share One Execution Identity',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags multiple agentic entities executing under one service account - agent actions cannot be individually attributed and per-agent least privilege becomes impossible',
    description:
        "When several agents share one service account, every record they write carries the same actor. Post-incident you can establish that an agent acted but never which agent, under whose prompt, from which trigger - which defeats the forensic reconstruction NIS2 Article 21(2)(b) expects. It also makes per-agent least privilege unachievable: the shared account's role set is necessarily the union of what every agent needs, so each agent inherits the reach of all the others. Severity does not scale with the number of agents; it scales with whether the shared identity holds roles. A shared read-only identity is untidy, a shared role-holder is an attribution hole with real blast radius, and the check separates the two in its evidence.",
    resolutionDetails: `For each shared identity:
1. Create one dedicated service identity per agent
2. Grant each identity only the table and field reach that agent needs - do not copy the shared account's role set
3. Repoint each agent's run-as field to its own identity
4. Deactivate the shared account once no agent references it, and confirm no integration outside the agent estate depended on it

The evidence lists each shared identity, how many agents use it, and how many roles it holds.

Framework mapping:
- NIS2 Article 21(2)(b): incident handling - requires logging sufficient to reconstruct an incident
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.5.16: identity management
- ISO 27001 A.8.15: logging
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0012 Valid Accounts
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-shared-runas-identity.js'),
})
