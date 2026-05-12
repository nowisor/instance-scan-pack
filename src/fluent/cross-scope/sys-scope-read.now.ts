import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysScopeReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-scope-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_scope',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
