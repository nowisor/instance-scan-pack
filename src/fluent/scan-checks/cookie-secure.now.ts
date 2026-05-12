import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const cookieSecureCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-cookie-secure'],
    name: 'Cookie Secure Flag Enforcement',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.cookies.secure forces the Secure flag on platform session cookies',
    description:
        "When glide.cookies.secure is not 'true', session cookies may be transmitted over plain HTTP, allowing a network attacker on the same path to intercept the authenticated session identifier and replay it against the instance. Verified-real property on Zurich Patch 6; default value 'true'.",
    resolutionDetails: `Set glide.cookies.secure = true via System Properties.

Framework mapping:
- NIS2 Article 21§2(e): security in network and information systems acquisition, development and maintenance
- ISO 27001 A.8.23: web filtering
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties; default value 'true'.`,
    script: Now.include('../../../scripts/check-cookie-secure.js'),
})
