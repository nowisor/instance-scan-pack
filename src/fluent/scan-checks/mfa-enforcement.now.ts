import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const mfaEnforcementCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-mfa-enforcement'],
    name: 'MFA Enforcement',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.authenticate.multifactor enforces multi-factor authentication on platform logins',
    description:
        "When glide.authenticate.multifactor is not 'true', single-factor credentials are sufficient to authenticate to the instance, removing the most effective control against credential-stuffing, phishing, and password-reuse compromise of administrative accounts. Verified-real property on Zurich Patch 6.",
    resolutionDetails: `Set glide.authenticate.multifactor = true via System Properties. Configure an MFA provider (built-in TOTP, ServiceNow Authenticator, or external IdP MFA) before enabling so users are not locked out.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management
- ISO 27001 A.5.17: authentication information
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties.`,
    script: Now.include('../../../scripts/check-mfa-enforcement.js'),
})
