import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiLlmDataResidencyCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-llm-data-residency'],
    name: 'LLM Connection Terminating Outside The EU',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Flags model endpoints pinned to a non-EU region on instances showing an EU-regulated signal; unpinned global endpoints report INVESTIGATE',
    description:
        "The check speaks only where residency is actually a requirement: it fires only when the instance shows an EU-regulated signal in its name. On an instance with no such signal it is silent, because a non-EU customer using a non-EU endpoint has no finding here and inventing one would train people to ignore the category. Region is inferred from the endpoint URL alone, and that limit is stated in the finding: an explicit non-EU region token fails, an EU-pinned endpoint passes, and a global endpoint with no region pin is INVESTIGATE rather than assumed non-compliant - a hostname is not a data-flow proof, and a provider may route differently than its URL suggests.",
    resolutionDetails: `For non-EU pinned endpoints:
1. Repoint to the provider's EU region where one is offered - the model id or host usually carries the region pin
2. Where no EU region exists, establish a lawful transfer basis and record the supplier assessment; the endpoint configuration does not carry either
3. Consider routing through an EU gateway that terminates in-region

For unpinned endpoints: confirm the processing region with the provider in writing, then pin the endpoint if the provider supports it.

Framework mapping:
- NIS2 Article 21(2)(d): supply chain security, including supplier relationships
- NIS2 Article 21(2)(h): policies and procedures on the use of cryptography and encryption
- ISO 27001 A.5.15: access control
- ISO 27001 A.8.24: use of cryptography
- DORA Article 9(3)(a): ensure the security of the means of transferring data
- OWASP LLM02:2025 Sensitive Information Disclosure, LLM03:2025 Supply Chain
- MITRE ATLAS AML.T0025 Exfiltration via Cyber Means
- EU AI Act Article 50 (transparency) applies where the integration is user-facing

Detection is configuration-based and read-only. Region is inferred from the URL, not observed from traffic.`,
    script: Now.include('../../../scripts/check-ai-llm-data-residency.js'),
})
