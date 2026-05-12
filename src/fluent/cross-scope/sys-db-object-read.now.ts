import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysDbObjectReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-db-object-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_db_object',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
