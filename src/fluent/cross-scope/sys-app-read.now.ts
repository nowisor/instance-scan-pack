import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysAppReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-app-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_app',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
