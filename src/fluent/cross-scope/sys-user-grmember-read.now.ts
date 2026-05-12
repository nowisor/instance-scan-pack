import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserGrmemberReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-grmember-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_grmember',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
