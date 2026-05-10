import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const csrfTokenEnforcementCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-csrf-token-enforcement'],
    name: 'CSRF Token Enforcement',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.security.use_csrf_token enforces CSRF protection on platform requests',
    description:
        "When glide.security.use_csrf_token is not 'true', the platform does not validate CSRF tokens on state-changing requests, exposing authenticated sessions to cross-site request forgery. Verified-real property; default value is 'true' on Zurich Patch 6.",
    resolutionDetails: `Set glide.security.use_csrf_token = true via System Properties.

Framework mapping:
- NIS2 Article 21§2(a): risk analysis and information system security policies
- ISO 27001 A.5.15: access control policy
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties; default value 'true'.`,
    script: Now.include('../../../scripts/check-csrf-token-enforcement.js'),
})
