import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserGroupReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-group-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_group',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
