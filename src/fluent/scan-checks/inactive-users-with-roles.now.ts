import { TableCheck } from '@servicenow/sdk/core'

export const inactiveUsersWithRolesCheck = TableCheck({
    $id: Now.ID['nowisor-inactive-users-with-roles'],
    name: 'Inactive Users Retaining Roles',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Inactive sys_user records that retain role assignments — privilege residue from incomplete deprovisioning',
    description:
        'Identifies user accounts marked inactive that still carry one or more role assignments via the denormalized sys_user.roles field. Residual roles on inactive accounts create reactivation-attack surface: an adversary who can flip active=true (via compromised user_admin, integration mis-grant, or update-set replay) inherits the prior privilege without a fresh role-grant audit event. Verified against Zurich Patch 6 on dev265484.',
    resolutionDetails: `Triage findings via /sys_user_list.do?sysparm_query=active=false^rolesISNOTEMPTY. For each row, decide whether to (a) revoke roles by clearing sys_user_has_role grants for the user (preferred), or (b) document a business reason to retain the role (e.g., regulated retention period requiring reactivation pathway). Add a deprovisioning workflow that revokes sys_user_has_role rows when sys_user.active flips to false.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management — covers deprovisioning hygiene
- ISO 27001 A.5.18: access rights — revocation upon role change or termination

Advanced (script) mode required to emit one finding per inactive-with-roles row carrying v1 metadata. Conditions-only mode emits findings but lacks the metadata block consumed by the advisor.`,
    table: 'sys_user',
    advanced: true,
    conditions: 'active=false^rolesISNOTEMPTY',
    script: Now.include('../../../scripts/check-inactive-users-with-roles.js'),
})
