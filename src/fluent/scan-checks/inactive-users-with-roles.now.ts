import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const inactiveUsersWithRolesCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-inactive-users-with-roles'],
    name: 'Inactive Users Retaining Roles',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Inactive sys_user records that retain role grants in sys_user_has_role m2m — privilege residue from incomplete deprovisioning',
    description:
        "Identifies user accounts marked inactive (sys_user.active=false) that still carry one or more role assignments in the sys_user_has_role m2m table. Residual roles on inactive accounts create reactivation-attack surface: an adversary who can flip active=true (via compromised user_admin, integration mis-grant, or update-set replay) inherits the prior privilege without a fresh role-grant audit event. Tier 2 verification (2026-05-12) revealed Zurich Patch 6 does not reliably populate the legacy denormalized sys_user.roles field; this check queries the m2m source-of-truth and groups results by user, emitting one finding per inactive user.",
    resolutionDetails: `Triage findings via sys_user_has_role list filtered by user.active=false. For each row, decide whether to (a) revoke role grants for the user (preferred), or (b) document a business reason to retain the role (e.g., regulated retention period requiring reactivation pathway). Add a deprovisioning workflow that revokes sys_user_has_role rows when sys_user.active flips to false.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management — covers deprovisioning hygiene
- ISO 27001 A.5.18: access rights — revocation upon role change or termination

This check is a ScriptOnlyCheck (not TableCheck) because the cross-scope read pattern + per-user finding aggregation requires explicit iteration. CrossScopePrivilege grants for sys_user and sys_user_has_role are shipped with the pack.`,
    script: Now.include('../../../scripts/check-inactive-users-with-roles.js'),
})
