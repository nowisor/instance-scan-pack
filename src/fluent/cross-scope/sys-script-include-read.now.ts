import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysScriptIncludeReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-script-include-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_script_include',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
