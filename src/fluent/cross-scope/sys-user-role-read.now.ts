import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserRoleReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-role-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_role',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
