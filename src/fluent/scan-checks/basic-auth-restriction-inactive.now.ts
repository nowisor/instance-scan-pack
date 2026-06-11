import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const basicAuthRestrictionInactiveCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-basic-auth-restriction-inactive'],
    name: 'Basic Auth Restriction Tracking Active',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.authenticate.basic_auth.restriction.active = true so the platform inventories interactive accounts using Basic Auth APIs',
    description:
        "Basic Auth API restriction tracking is the prerequisite for inventorying which interactive accounts authenticate via Basic Auth before enforcement begins. When glide.authenticate.basic_auth.restriction.active is false, the customer is blind to the hybrid-account exposure. If the property is unregistered the instance likely predates the feature - the check reports not_applicable / feature_not_present rather than a fabricated failure. Property verified REAL on Zurich Patch 6 (dev265147), 2026-06-11.",
    resolutionDetails: `Set glide.authenticate.basic_auth.restriction.active = true (tracking mode) to begin recording which accounts use inbound Basic Auth APIs. Tracking is non-blocking; it populates sys_user_basic_auth_exception so you can triage before enabling enforcement.

Framework mapping:
- NIS2 Article 21(2)(j): authentication, including multi-factor authentication
- ISO 27001 A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (dev265147), 2026-06-11.`,
    script: Now.include('../../../scripts/check-basic-auth-restriction-inactive.js'),
})
