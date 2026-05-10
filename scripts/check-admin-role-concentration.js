// nowisor pilot v0.1 — Admin role concentration check
// Flags if admin role assignments > 5% of active users.
//
// Provenance — admin role on dev265484 (Zurich Patch 6, verified 2026-05-10):
//   sys_id: 2831a114c611228501d4ea6c309d626d  scope: Global
//   Verification: GET /api/now/table/sys_user_role?sysparm_query=name=admin
//   The check queries by role.name='admin' and does not depend on sys_id at runtime;
//   sys_id captured here only for cross-instance v1 portability assessment.
//
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
    if (ratio > THRESHOLD) {
        var pct = (ratio * 100).toFixed(2)
        finding.setValue(
            'finding_details',
            'Admin role concentration: ' +
                adminCount +
                ' admins / ' +
                activeUsers +
                ' active users (' +
                pct +
                '%) exceeds 5% threshold'
        )
        finding.increment()
    }
})(finding)
