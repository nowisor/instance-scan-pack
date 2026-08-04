import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiInboundAgentUngovernedCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-inbound-agent-ungoverned'],
    name: 'Ungoverned Inbound External Agent (MCP / Action Fabric)',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Flags inbound external agents reaching the instance over MCP / Action Fabric that are absent from AI Control Tower or any sanctioned catalog',
    description:
        "Action Fabric and MCP Server let an agent built anywhere - Claude, Copilot, or something homegrown - act inside the instance headlessly, under an OAuth client, against role-scoped tool packages. That is the system of action reachable by a caller no ITSM control was designed around. An inbound agent absent from the sanctioned catalog is unowned privileged access with no lifecycle: nothing reviews its tool scope and nothing owns its revocation. The check keeps three states distinct and refuses to collapse them: no inbound surface at all is not_applicable; an inbound surface with no catalog to compare against is INVESTIGATE (the missing catalog is the governance-configuration check's finding, not N ungoverned agents); an inbound surface plus a populated catalog plus misses is a CRITICAL finding naming each miss and where it was expected.",
    resolutionDetails: `For each ungoverned inbound entry:
1. Identify the OAuth client and the tool package the entry can reach (named in the finding evidence)
2. Register the agent in AI Control Tower (or your sanctioned catalog) with a named owner and a review date
3. Reduce the granted tool package to the minimum the integration needs - prefer read-only tools where they serve
4. Where the entry is unrecognised, deactivate it and revoke the OAuth client

Registration is matched by normalised name, so an agent catalogued under a different label will appear here. Confirm before revoking.

Framework mapping:
- NIS2 Article 21(2)(d): supply chain security, including supplier relationships
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.5.15: access control
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM03:2025 Supply Chain, LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0103 Deploy AI Agent, AML.T0108 AI Agent
- EU AI Act Article 4: AI literacy

Re-run after any Now Assist SKU change: Action Fabric and MCP Server ship inside Now Assist entitlements, so the inbound surface can appear without a deliberate project.

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-inbound-agent-ungoverned.js'),
})
