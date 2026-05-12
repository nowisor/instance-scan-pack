import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserRoleContainsReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-role-contains-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_role_contains',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
