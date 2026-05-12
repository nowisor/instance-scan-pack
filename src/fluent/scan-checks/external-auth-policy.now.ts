import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const externalAuthPolicyCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-external-auth-policy'],
    name: 'External Auth — Disable Local Login',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'When SSO is active, verifies glide.authentication.external.disable_local_login is true so local login does not coexist with the IdP as a bypass path',
    description:
        "When SSO is active and glide.authentication.external.disable_local_login is not 'true', the platform retains a local-credential login path alongside the configured IdP. An attacker who phishes or guesses a local password bypasses the IdP's MFA, conditional access, and audit trail entirely. Check is informational-only when no SSO provider is detected. Verified-real property on Zurich Patch 6.",
    resolutionDetails: `If SSO is configured and is the intended primary auth path: set glide.authentication.external.disable_local_login = true via System Properties. Retain a documented break-glass local admin account that is monitored and rotated.

SSO detection heuristic (read-only): the check looks for active records in the sso_properties table; documented in the script comments. If no SSO is active, no finding is emitted.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management
- ISO 27001 A.5.16: identity management

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties.`,
    script: Now.include('../../../scripts/check-external-auth-policy.js'),
})
