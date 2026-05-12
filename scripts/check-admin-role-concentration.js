// nowisor v1.0.0 — Admin role concentration check
// Flags if admin role assignments > 5% of active users.
//
// Provenance — admin role on dev265484 (Zurich Patch 6, verified 2026-05-10):
//   sys_id: 2831a114c611228501d4ea6c309d626d  scope: Global
//   Verification: GET /api/now/table/sys_user_role?sysparm_query=name=admin
//   The check queries by role.name='admin' and does not depend on sys_id at runtime;
//   sys_id captured here only for cross-instance v1 portability assessment.
//
// Cross-scope read of sys_user_has_role and sys_user from x_nowisor_isp scope
// verified working on 2026-05-10: in-scope query returned identical counts
// to Global-scope REST baseline (18 admin grants / 633 active users = 2.84%).
// CrossScopePrivilege records ship with the pack as belt-and-suspenders for
// production scope-strictness configurations.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function adminRoleConcentration(finding) {
    var THRESHOLD = 0.05

    var rolesGr = new GlideAggregate('sys_user_has_role')
    rolesGr.addQuery('role.name', 'admin')
    rolesGr.addQuery('user.active', true)
    rolesGr.addAggregate('COUNT')
    rolesGr.query()
    var adminCount = 0
    if (rolesGr.next()) {
        adminCount = parseInt(rolesGr.getAggregate('COUNT'), 10)
    }

    var usersGr = new GlideAggregate('sys_user')
    usersGr.addQuery('active', true)
    usersGr.addAggregate('COUNT')
    usersGr.query()
    var activeUsers = 0
    if (usersGr.next()) {
        activeUsers = parseInt(usersGr.getAggregate('COUNT'), 10)
    }

    if (activeUsers === 0) return

    var ratio = adminCount / activeUsers
    if (ratio <= THRESHOLD) return

    var pct = (ratio * 100).toFixed(2)

    var metadata = {
        nowisor_check_id: 'nowisor-admin-role-concentration',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.18', 'A.8.2'],
        },
        evidence: {
            admin_count: adminCount,
            active_users: activeUsers,
            concentration_percent: pct,
            threshold_percent: '5.00',
        },
        severity: 1,
        remediation_id: 'role-001',
        attack_path_refs: [],
    }

    var details =
        'Admin role concentration: ' +
        adminCount +
        ' admins / ' +
        activeUsers +
        ' active users (' +
        pct +
        '%) exceeds 5% threshold.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
