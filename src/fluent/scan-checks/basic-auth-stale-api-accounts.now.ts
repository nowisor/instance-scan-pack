import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const basicAuthStaleApiAccountsCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-basic-auth-stale-api-accounts'],
    name: 'Dormant Basic Auth API Accounts',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Flags dormant accounts with a Basic Auth API path by two valid signals: stale exception last_seen, or a non-WSAO role-holder with stale UI login',
    description:
        "Dormant accounts with static Basic Auth credentials are standing attack surface. A plain sys_user.last_login_time test is invalid because web-service-access-only accounts cannot log into the UI by definition (verified on dev265147, 2026-06-11: all active WSAO accounts had empty/ancient last_login_time), so this check uses two valid signals instead: (1) sys_user_basic_auth_exception.last_seen older than the threshold (real Basic Auth usage recency), and (2) an active, non-WSAO holder of the allow-list role whose last UI login is stale (a likely-departed human with a residual API path). Threshold default 90 days (configurable in the check).",
    resolutionDetails: `Revoke the Basic Auth API path or deactivate the account. For tracked-but-unused accounts (exception last_seen stale), confirm no integration still depends on them, then deactivate or convert. For dormant hybrid accounts (departed human retaining the role), remove the role and disable the account. Reducing dormant static credentials shrinks the pre-enforcement attack surface.

Framework mapping:
- NIS2 Article 21(2)(i): access control policies
- ISO 27001 A.5.16: identity management; A.5.17: authentication information
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (dev265147), 2026-06-11.`,
    script: Now.include('../../../scripts/check-basic-auth-stale-api-accounts.js'),
})
