import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const basicAuthHybridUndecidedCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-basic-auth-hybrid-undecided'],
    name: 'Basic Auth Hybrid Accounts Undecided',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Counts interactive accounts detected using Basic Auth APIs (sys_user_basic_auth_exception) that have not been triaged (action_taken=false)',
    description:
        "Each untriaged record in sys_user_basic_auth_exception (action_taken=false) is an interactive account that authenticates with single-factor Basic Auth - an MFA-bypass surface today and an unmanaged outcome at enforcement (the bypass either persists or the account is blocked with a 401). The check counts them and samples the top accounts by usage_count, with each account's decision and last_seen. Table, fields and the action_taken=false predicate verified on Zurich Patch 6 (dev265147), 2026-06-11. If the table is absent it reports feature_table_not_found; if unreadable, insufficient_access - never a fabricated pass.",
    resolutionDetails: `Triage every untriaged exception. For each account choose a decision and apply it: convert integration accounts to web-service-access-only (decision: converted), revoke Basic Auth API login for accounts that should not use it (decision: no_grant), or - only as a time-boxed exception - explicitly maintain access. Migrate human / interactive API use to OAuth. Treat the snc_basic_auth_api_access role as a temporary exception, not a standing grant.

Framework mapping:
- NIS2 Article 21(2)(i): access control policies; (j): authentication
- ISO 27001 A.5.16: identity management; A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (dev265147), 2026-06-11.`,
    script: Now.include('../../../scripts/check-basic-auth-hybrid-undecided.js'),
})
