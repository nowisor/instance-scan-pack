import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const basicAuthEnforcementPostureCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-basic-auth-enforcement-posture'],
    name: 'Basic Auth Enforcement Posture',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Reports Basic Auth restriction enforcement state and surfaces the days remaining until the enforcement date',
    description:
        "Reads glide.authenticate.basic_auth.restriction.enforce, .enforcement_date and .default_decision. In tracking mode (enforce=false) with a future enforcement date, the check surfaces the days-remaining countdown - the window to validate integrations before interactive Basic Auth accounts are blocked. If the date is already in the past while enforce is still false, enforcement was deferred or overridden and the MFA-bypass surface persists with no scheduled closure. Properties verified REAL on Zurich Patch 6 (dev265147), 2026-06-11.",
    resolutionDetails: `Before the enforcement date, validate every inbound integration that may rely on Basic Auth so it does not 401 at cutover: Discovery, Service Graph Connectors, Intune / JAMF / SCCM, IntegrationHub REST steps, and any custom scripted REST / SOAP integrations. Migrate integration accounts to OAuth or mark them web-service-access-only and allow-list them; then set glide.authenticate.basic_auth.restriction.enforce = true. Do not let the enforcement date pass with enforce still false - that leaves the bypass open indefinitely.

Framework mapping:
- NIS2 Article 21(2)(j): authentication, including multi-factor authentication
- ISO 27001 A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (dev265147), 2026-06-11.`,
    script: Now.include('../../../scripts/check-basic-auth-enforcement-posture.js'),
})
