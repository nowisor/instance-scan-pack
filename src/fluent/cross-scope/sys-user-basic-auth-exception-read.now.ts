import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysUserBasicAuthExceptionReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-user-basic-auth-exception-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_user_basic_auth_exception',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
