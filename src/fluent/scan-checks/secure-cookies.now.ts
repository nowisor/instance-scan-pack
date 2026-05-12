import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const secureCookiesCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-secure-cookies'],
    name: 'Secure Cookies UI Property',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Verifies glide.ui.secure_cookies enforces secure-cookie behaviour at the UI layer',
    description:
        "When glide.ui.secure_cookies is not 'true', the UI layer does not enforce the secure-cookie contract that complements the transport-level glide.cookies.* settings, leaving an asymmetry that some session paths may exploit to ship cookies over insecure channels. Verified-real property on Zurich Patch 6; default value 'true'.",
    resolutionDetails: `Set glide.ui.secure_cookies = true via System Properties.

Framework mapping:
- NIS2 Article 21§2(e): security in network and information systems acquisition, development and maintenance
- ISO 27001 A.8.23: web filtering

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties; default value 'true'.`,
    script: Now.include('../../../scripts/check-secure-cookies.js'),
})
