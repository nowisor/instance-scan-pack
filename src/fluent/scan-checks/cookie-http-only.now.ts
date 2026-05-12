import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const cookieHttpOnlyCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-cookie-http-only'],
    name: 'Cookie HttpOnly Enforcement',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.cookies.http_only forces the HttpOnly flag on platform session cookies',
    description:
        "When glide.cookies.http_only is not 'true', session cookies are accessible to JavaScript via document.cookie, enabling cross-site-scripting payloads to exfiltrate authenticated session identifiers directly to attacker-controlled endpoints. Verified-real property on Zurich Patch 6; default value 'true'.",
    resolutionDetails: `Set glide.cookies.http_only = true via System Properties.

Framework mapping:
- NIS2 Article 21§2(e): security in network and information systems acquisition, development and maintenance
- ISO 27001 A.8.23: web filtering
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties; default value 'true'.`,
    script: Now.include('../../../scripts/check-cookie-http-only.js'),
})
