// nowisor v1.0.0 — Inactive users retaining roles check
//
// DESIGN (Tier 2 verification rewrite, 2026-05-12):
// Original v1.0.0-build used a TableCheck against sys_user with conditions
// `active=false^rolesISNOTEMPTY`. That predicate relied on the legacy
// denormalized `sys_user.roles` comma-list field, which is unreliably
// populated on Zurich Patch 6 — on dev265484, 0 inactive users had legacy
// roles populated while 1+ had m2m grants in sys_user_has_role. The
// TableCheck silently missed any inactive user whose roles existed only in
// the m2m table.
//
// This rewrite queries sys_user_has_role m2m (the source-of-truth on Zurich)
// and groups by user. One finding is emitted per inactive user retaining any
// role grant; each finding lists the role names in metadata.evidence.
//
// Cross-scope read of sys_user_has_role from x_nowisor_isp requires the
// CrossScopePrivilege records shipped with the pack (read on sys_user and
// sys_user_has_role).
//
// Schema: v1 (---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function inactiveUsersWithRoles(finding) {
    var MAX_FINDINGS = 200
    var MAX_ROLES_PER_USER = 50

    // Single pass: collect role names per inactive user
    var bucket = {}
    var gr = new GlideRecord('sys_user_has_role')
    gr.addQuery('user.active', false)
    gr.query()
    while (gr.next()) {
        var userSysId = gr.getValue('user')
        if (!userSysId) continue
        if (!bucket[userSysId]) {
            bucket[userSysId] = {
                user_name: gr.getDisplayValue('user') || userSysId,
                user_sys_id: userSysId,
                role_names: [],
            }
        }
        if (bucket[userSysId].role_names.length < MAX_ROLES_PER_USER) {
            var roleName = gr.getDisplayValue('role') || gr.getValue('role')
            bucket[userSysId].role_names.push(roleName)
        }
    }

    var userIds = []
    for (var k in bucket) {
        if (bucket.hasOwnProperty(k)) userIds.push(k)
    }
    if (userIds.length === 0) return

    // Stable sort for repeatability
    userIds.sort(function (a, b) {
        return bucket[a].user_name.localeCompare(bucket[b].user_name)
    })

    var emitted = 0
    for (var i = 0; i < userIds.length && emitted < MAX_FINDINGS; i++) {
        var u = bucket[userIds[i]]
        var metadata = {
            nowisor_check_id: 'nowisor-inactive-users-with-roles',
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: {
                nis2: ['21.2.j'],
                iso27001: ['A.5.18'],
            },
            evidence: {
                user_name: u.user_name,
                user_sys_id: u.user_sys_id,
                role_count: u.role_names.length,
                role_names: u.role_names,
            },
            severity: 2,
            remediation_id: 'role-002',
            attack_path_refs: [],
        }

        var details =
            'Inactive user "' +
            u.user_name +
            '" retains ' +
            u.role_names.length +
            ' role grant(s) via sys_user_has_role m2m. Privilege residue from incomplete deprovisioning — reactivation of this account would restore the listed roles without a fresh grant audit event. Roles: ' +
            u.role_names.join(', ') +
            '. User sys_id: ' +
            u.user_sys_id +
            '.' +
            '\n\n---NOWISOR_METADATA---\n' +
            JSON.stringify(metadata)

        finding.setValue('finding_details', details)
        finding.increment()
        emitted++
    }
})(finding)
