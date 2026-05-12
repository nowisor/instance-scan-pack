import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysScriptReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-script-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_script',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
