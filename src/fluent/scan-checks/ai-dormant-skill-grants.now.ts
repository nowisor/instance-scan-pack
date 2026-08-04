import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiDormantSkillGrantsCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-dormant-skill-grants'],
    name: 'Inactive AI Agent Retains Capability Grants',
    active: true,
    category: 'security',
    priority: '3',
    shortDescription:
        'Flags agents switched off whose execution identity still holds platform roles - deactivation is not revocation',
    description:
        "Turning an agent off stops it being invoked; it does not remove anything from its run-as identity. The roles survive, the credentials keep working, and the OAuth tokens keep authenticating. A decommissioned agent therefore leaves behind a fully privileged identity that nobody monitors, precisely because the agent it belonged to is 'not in use' - the standing-credential problem that non-human-identity tooling exists to catch. The check requires BOTH an active flag and a run-as field on the release; missing either, it reports not_applicable rather than guessing. It reports held-but-inactive grants from configuration alone and says so: whether those grants were ever exercised is answered by the Agent Least-Privilege correlation, which needs log coverage this check does not have. Severity is deliberately MEDIUM - this is a cleanup obligation, not an active exploit.",
    resolutionDetails: `For each dormant grant:
1. Confirm the agent is genuinely decommissioned rather than temporarily paused
2. Revoke the roles listed in the finding evidence from the execution identity
3. Deactivate the service account itself where no other agent or integration uses it - the evidence flags which identities are still active user records
4. Where the agent may be re-enabled later, document the grants so they can be restored deliberately rather than left standing

Framework mapping:
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.5.16: identity management
- ISO 27001 A.8.2: privileged access rights are restricted and managed
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0012 Valid Accounts
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-dormant-skill-grants.js'),
})
