import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserHasRoleReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-has-role-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_has_role',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
