import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUiActionReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-ui-action-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_ui_action',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
