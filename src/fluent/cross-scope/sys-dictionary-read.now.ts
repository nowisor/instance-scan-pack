import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysDictionaryReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-dictionary-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_dictionary',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
