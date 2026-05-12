import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysScopePrivilegeReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-scope-privilege-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_scope_privilege',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
