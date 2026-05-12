// nowisor v1.0.0 — Elevated role co-assignments check
// Counts active users that hold BOTH 'admin' AND 'itil_admin' roles.
// Intersection computed in-script by collecting user sys_ids from each
// role-grant query and counting overlap.
//
// Role provenance — both names queried by name (role.name='admin' /
// role.name='itil_admin') on Zurich Patch 6 baseline (dev265484, 2026-05-10).
// No sys_id is hardcoded at runtime.
//
// Cross-scope read of sys_user_has_role / sys_user from x_nowisor_isp requires
// the CrossScopePrivilege records shipped with the pack.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function elevatedRoleAssignments(finding) {
    var MAX_LIST = 20

    function collectActiveUserIds(roleName) {
        var ids = {}
        var gr = new GlideRecord('sys_user_has_role')
        gr.addQuery('role.name', roleName)
        gr.addQuery('user.active', true)
        gr.query()
        while (gr.next()) {
            var uid = gr.getValue('user')
            if (uid) ids[uid] = true
        }
        return ids
    }

    var adminIds = collectActiveUserIds('admin')
    var itilAdminIds = collectActiveUserIds('itil_admin')

    var overlapIds = []
    for (var uid in itilAdminIds) {
        if (adminIds.hasOwnProperty(uid)) overlapIds.push(uid)
    }

    var overlapCount = overlapIds.length
    if (overlapCount === 0) return

    var sampleNames = []
    var sampleCap = Math.min(overlapCount, MAX_LIST)
    for (var i = 0; i < sampleCap; i++) {
        var userGr = new GlideRecord('sys_user')
        if (userGr.get(overlapIds[i])) {
            var uname = userGr.getValue('user_name') || userGr.getValue('sys_id')
            sampleNames.push(uname)
        } else {
            sampleNames.push(overlapIds[i])
        }
    }

    var sampleStr = sampleNames.join(', ')
    var overflow = overlapCount > MAX_LIST ? ' (+' + (overlapCount - MAX_LIST) + ' more)' : ''

    var metadata = {
        nowisor_check_id: 'nowisor-elevated-role-assignments',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.18'],
        },
        evidence: {
            co_assignment_count: overlapCount,
            roles: ['admin', 'itil_admin'],
            sample_count: sampleNames.length,
            sample_users: sampleNames,
        },
        severity: 2,
        remediation_id: 'role-003',
        attack_path_refs: [],
    }

    var details =
        'Elevated role co-assignments: ' +
        overlapCount +
        ' active users hold BOTH admin and itil_admin. Sample: ' +
        sampleStr +
        overflow +
        '. Split the duties so platform administration and ITIL process administration are held by disjoint identity sets.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
