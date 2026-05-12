import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const crossScopePrivilegeGrantsCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-cross-scope-privilege-grants'],
    name: 'Cross-Scope Privilege Grants',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Counts high-impact sys_scope_privilege grants from non-global scopes to Global with write/create/delete operations',
    description:
        'sys_scope_privilege records permit a non-global application to perform restricted operations against records owned by another scope. Grants whose source.scope != global and target.scope = global, with operation in (write, create, delete), let a scoped application mutate Global-scope data — a classic scope-escalation path. The check counts such grants and lists samples for review.',
    resolutionDetails: `Open /sys_scope_privilege_list.do and filter by source.scope!=global^target.scope=global^operationINwrite,create,delete. For each grant, verify the requesting application's business need and review the called API surface. Remove unnecessary grants; for retained grants, document the audit trail (who approved, what business case, expected lifetime).

Framework mapping:
- NIS2 Article 21§2(a): risk analysis and information system security policies — scope-isolation integrity
- ISO 27001 A.8.3: information access restriction — least-privilege across application boundaries

Verified table: sys_scope_privilege with reference fields source (sys_scope) and target (sys_scope), and operation field carrying read/write/create/delete/execute. Cross-scope read of sys_scope_privilege from x_nowisor_isp requires the CrossScopePrivilege records shipped with the pack.`,
    script: Now.include('../../../scripts/check-cross-scope-privilege-grants.js'),
})
