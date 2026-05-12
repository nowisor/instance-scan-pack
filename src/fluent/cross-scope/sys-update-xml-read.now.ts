import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUpdateXmlReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-update-xml-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_update_xml',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
