import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiSubprodUnmaskedPostureCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-subprod-unmasked-posture'],
    name: 'Agentic Features Active On Unmasked Sub-Production Instance',
    active: true,
    category: 'security',
    priority: '3',
    shortDescription:
        'INVESTIGATE-only: non-production instance identity plus an active agentic surface plus no data preservers - a risk posture, never a claim about actual data',
    description:
        "Sub-production clones routinely carry production data, and agentic features on a clone will send whatever they can read to whatever model endpoint is configured for testing - under looser controls, with fewer people watching. This check detects that RISK POSTURE from three coinciding signals: the instance identifies as non-production, an agentic surface is active with entities present, and no data preservers are configured. The claim boundary is the point of the check: a connected scan CANNOT observe whether a clone was masked, and this check deliberately does not sample record contents to find out, because that would be both unreliable and an unacceptable thing for a security scanner to do to customer data. It therefore emits INVESTIGATE and never escalates to CRITICAL without positive evidence of unmasked sensitive data, which it does not gather. Where the preserver table cannot be read at all, the third signal is missing and the check stays silent rather than guessing.",
    resolutionDetails: `This finding asks a question; it does not assert a breach.

1. Confirm whether your clone process masks or excludes the sensitive tables named in the evidence
2. Where masking is handled outside data preservers (a clone-exclude list, a post-clone script), record that and close this as accepted risk
3. Where it is not handled, configure data preservers or a masking step before the next clone
4. Independently, confirm which model endpoint the agentic features on this instance are configured to reach - a test endpoint is still an external data path

Framework mapping:
- NIS2 Article 21(2)(e): security in network and information systems acquisition, development, and maintenance
- NIS2 Article 21(2)(i): access control policies and asset management
- ISO 27001 A.8.33: test information is appropriately selected, protected, and managed
- ISO 27001 A.5.15: access control
- DORA Article 9(3)(d): protect data from risks arising from data management, including poor administration and human error
- OWASP LLM02:2025 Sensitive Information Disclosure
- MITRE ATLAS AML.T0025 Exfiltration via Cyber Means
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only. No record contents are inspected.`,
    script: Now.include('../../../scripts/check-ai-subprod-unmasked-posture.js'),
})
