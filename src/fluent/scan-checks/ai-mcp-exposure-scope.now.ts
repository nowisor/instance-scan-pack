import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiMcpExposureScopeCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-mcp-exposure-scope'],
    name: 'MCP / Action Fabric Exposure Scope Too Broad',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags write-capable tool packages on the inbound agent surface, and OAuth clients with no bounded token lifetime',
    description:
        "This is the complement of the ungoverned-inbound-agent check, not a duplicate of it. That check asks who is connected and whether they are catalogued; this one asks how much the connection can do. An inbound agent can be perfectly registered, owned and reviewed and still hold a write-everything tool package on a non-expiring OAuth client - which is the more common real-world failure, because registration is a governance task somebody owns and scope minimisation is not. The two questions are evaluated independently: one can be answerable while the other is not, and the check reports N/A per question rather than guessing at a tool-package schema that differs across releases.",
    resolutionDetails: `For broad tool grants:
1. Reduce each granted package to the narrowest set that satisfies the use case - prefer read-only tools wherever they serve. A summarisation agent does not need write tools
2. Where a write tool is genuinely required, scope it to specific tables rather than granting a blanket operation

For OAuth clients without expiry:
3. Set a bounded token lifetime and a rotation schedule
4. Revoke clients whose project has ended - access that outlives its justification is standing privileged access

Framework mapping:
- NIS2 Article 21(2)(i): access control policies and asset management
- NIS2 Article 21(2)(d): supply chain security, including supplier relationships
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- ISO 27001 A.5.15: access control
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency, LLM03:2025 Supply Chain
- MITRE ATLAS AML.T0012 Valid Accounts, AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 4: AI literacy

Detection reports configured scope, not observed use. Read-only.`,
    script: Now.include('../../../scripts/check-ai-mcp-exposure-scope.js'),
})
