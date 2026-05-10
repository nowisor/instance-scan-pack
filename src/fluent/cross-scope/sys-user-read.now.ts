import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
