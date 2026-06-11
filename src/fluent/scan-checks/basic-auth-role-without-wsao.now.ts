import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const basicAuthRoleWithoutWsaoCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-basic-auth-role-without-wsao'],
    name: 'Basic Auth Role Without WSAO',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Flags active accounts holding the Basic Auth API allow-list role that are not web-service-access-only (UI-loginable - institutionalized MFA bypass)',
    description:
        "An account holding the Basic Auth API access role (from glide.authenticate.basic_auth.allowed_roles, default snc_basic_auth_api_access) that is NOT web-service-access-only can log into the UI and authenticate to APIs with single-factor Basic Auth - the documented temporary path turned into a standing MFA bypass on a human-loginable account. Escalated to Critical when the account also holds admin or security_admin. mid_server accounts are excluded (legitimate Basic Auth path). Role, allow-list property and sys_user fields verified on Zurich Patch 6 (dev265147), 2026-06-11.",
    resolutionDetails: `For each flagged account: if it is an integration identity, set web-service-access-only = true (WSAO) so it cannot log into the UI; if it is a human, migrate API use to OAuth and remove the role. Treat snc_basic_auth_api_access as a time-boxed exception, not a permanent grant. Privileged accounts (admin / security_admin) holding this role must be remediated first.

Framework mapping:
- NIS2 Article 21(2)(i): access control policies; (j): authentication
- ISO 27001 A.5.16: identity management; A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (dev265147), 2026-06-11.`,
    script: Now.include('../../../scripts/check-basic-auth-role-without-wsao.js'),
})
