import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiShadowLlmEndpointCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-shadow-llm-endpoint'],
    name: 'Shadow AI - Unsanctioned External LLM Endpoint',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Flags outbound integrations configured to reach external model providers outside the Generative AI Controller - undeclared model-data export paths',
    description:
        "A REST message or connection alias pointing at an external model provider is an undeclared data-export path: it sits outside the Generative AI Controller's logging and data-handling configuration, and outside whatever data-processing agreement covers the sanctioned route. The check resolves the endpoint column from sys_dictionary (endpoint field names differ across sys_rest_message, sys_connection and alias tables) and matches configured URLs against known model-provider hosts. Severity is conditional on evidence: where a Gen AI Controller surface exists the integration is a controller bypass (CRITICAL); where no controller exists at all the finding cannot claim a bypass and reports INVESTIGATE instead. Detection is configuration-based - it reports what is configured to be reachable, never what was transmitted, because a read-only scan cannot observe traffic.",
    resolutionDetails: `For each flagged integration:
1. Identify the owner and business purpose of the endpoint named in the finding evidence
2. Route it through the Generative AI Controller (or your sanctioned connection alias) so prompts, responses and data-handling settings are logged centrally
3. Confirm a data-processing agreement covers the provider, and that the payload contents are permitted to leave the instance
4. Where the integration is not needed, deactivate it and revoke its credentials

The finding lists each endpoint, the column it came from, and which provider host matched.

Framework mapping:
- NIS2 Article 21(2)(a): policies on risk analysis and information system security
- NIS2 Article 21(2)(d): supply chain security, including supplier relationships
- ISO 27001 A.5.15: access control
- ISO 27001 A.8.16: monitoring activities
- DORA Article 9(3)(a): ensure the security of the means of transferring data
- DORA Article 9(4)(c): limit logical access to approved functions only
- OWASP LLM02:2025 Sensitive Information Disclosure, LLM03:2025 Supply Chain
- MITRE ATLAS AML.T0025 Exfiltration via Cyber Means, AML.T0096 AI Service API
- EU AI Act Article 50 (transparency) applies where the integration is user-facing

Detection is configuration-based and read-only.`,
    script: Now.include('../../../scripts/check-ai-shadow-llm-endpoint.js'),
})
