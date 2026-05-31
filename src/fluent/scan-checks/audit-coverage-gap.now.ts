import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const auditCoverageGapCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-audit-coverage-gap'],
    name: 'Audit Coverage Gap',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Detects whether sys_dictionary.audit is enabled on security-critical tables (sys_user_has_role, sys_security_acl, sys_properties); without audit, post-incident review of role/ACL/property changes is impossible',
    description:
        "ServiceNow's auditing model is opt-in per table: the collection row in sys_dictionary (name=<table>, element='') carries an `audit` flag that, when false, prevents any changes to that table from emitting sys_audit rows. Three tables underpin platform security: sys_user_has_role (who has which role), sys_security_acl (what each role permits), and sys_properties (what hardening is configured). If auditing isn't enabled on these, every other security control becomes unverifiable post-incident — you can detect that an ACL was weakened, but not when, by whom, or from what value. This is the upstream gap that makes the rest of the security telemetry incomplete.",
    resolutionDetails: `For each flagged table:
1. Navigate to System Definition → Dictionary
2. Filter: Table = <flagged table name>, Column name = <empty>
3. Open the collection row, set Audit = true, Update

Audit takes effect immediately for subsequent changes. Historical changes that occurred before the toggle cannot be recovered — only forward-going changes will emit sys_audit rows.

Framework mapping:
- NIS2 Article 21§2(b): incident handling capability — requires logging sufficient to reconstruct an incident
- ISO 27001 A.8.15: Logging — security events must be logged
- ISO 27001 A.8.16: Monitoring activities — logs must be reviewable
- DORA Article 10: Detection — ICT-related incidents must be detectable from telemetry

Cross-scope dependency: the check reads sys_dictionary from x_nowisor_isp, which requires the CrossScopePrivilege shipped with the pack (read on sys_dictionary). If the privilege is missing or revoked, the check reports the table as "unverifiable" rather than silent-passing.

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).`,
    script: Now.include('../../../scripts/check-audit-coverage-gap.js'),
})
