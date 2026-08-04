import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiLlmPayloadMaskingCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-llm-payload-masking'],
    name: 'No Data-Protection Control Over Agent-Readable Data',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags an active agentic surface on an instance with no data policies, classification records, field encryption or encrypted dictionary attributes configured',
    description:
        "A read-only scan sees configuration, never payloads. So this check does not and cannot claim that any prompt carried personal data - it reports that the platform is applying no data-protection control to the data these agents can read, which is a verifiable configuration gap rather than an observed disclosure. Any one configured mechanism (an active data policy, a classification record, field encryption, or an encrypted dictionary attribute) satisfies the check. It fires only where an agentic surface is active with entities present, because the control is meaningless on an instance whose agents are all switched off.",
    resolutionDetails: `1. Identify which sensitive tables and fields your active agents can actually read - the Agent Least-Privilege Report resolves this per agent where log coverage permits
2. Apply at least one platform data-protection control over them: a data policy, a data classification record, or field-level encryption
3. Confirm your Now Assist data-handling settings in the Now Assist Admin console; those are UI-configured and expose no property this check can read
4. Re-run to confirm the mechanism is visible to the scan

Framework mapping:
- NIS2 Article 21(2)(h): policies and procedures on the use of cryptography and encryption
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.8.24: use of cryptography
- ISO 27001 A.5.15: access control
- DORA Article 9(3)(b): minimise the risk of corruption or loss of data and unauthorised access
- OWASP LLM02:2025 Sensitive Information Disclosure
- MITRE ATLAS AML.T0024 Exfiltration via AI Inference API
- EU AI Act Article 50 (transparency) applies where the agent is user-facing

Detection is configuration-based and read-only. No record contents are inspected.`,
    script: Now.include('../../../scripts/check-ai-llm-payload-masking.js'),
})
