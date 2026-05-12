import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysSecurityAclReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-security-acl-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_security_acl',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
