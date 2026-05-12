import { CrossScopePrivilege } from '@servicenow/sdk/core'

export const sysSecurityAclRoleReadPrivilege = CrossScopePrivilege({
    $id: Now.ID['nowisor-priv-sys-security-acl-role-read'],
    operation: 'read',
    status: 'allowed',
    targetName: 'sys_security_acl_role',
    targetScope: 'global',
    targetType: 'sys_db_object',
})
