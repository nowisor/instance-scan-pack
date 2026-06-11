// nowisor v1.1.0 - Basic Auth role granted without WSAO check (BASICAUTH-04)
// Users holding the Basic Auth API allow-list role (verified property
//   glide.authenticate.basic_auth.allowed_roles = snc_basic_auth_api_access on
//   Zurich Patch 6, dev265484, 2026-06-11) whose account is NOT web-service-
//   access-only. On a UI-loginable account this institutionalizes the MFA bypass.
//   Critical if the account also holds admin/security_admin. mid_server excluded
//   (legitimate Basic Auth path).
// Reads sys_user_has_role + dot-walked sys_user fields (both verified; cross-scope
//   privilege records shipped with the pack).
// Schema: v1   ES5-only (Instance Scan runtime constraint)
;(function basicAuthRoleWithoutWsao(finding) {
    var SENTINEL = '__NOT_SET__'
    var MAX = 200
    var CHECK_ID = 'nowisor-basic-auth-role-without-wsao'
    var PRIV = ['admin', 'security_admin']

    function truthy(v) {
        return v === '1' || v === 1 || v === 'true' || v === true
    }
    function trim(s) {
        return String(s).replace(/^\s+|\s+$/g, '')
    }

    // Allow-list role(s) from the verified property (may be a comma list);
    // default to the documented role if the property is absent.
    var rolesProp = gs.getProperty('glide.authenticate.basic_auth.allowed_roles', SENTINEL)
    var roleNames = []
    if (rolesProp !== SENTINEL && rolesProp) {
        var parts = rolesProp.split(',')
        for (var a = 0; a < parts.length; a++) {
            var rn = trim(parts[a])
            if (rn) roleNames.push(rn)
        }
    }
    if (roleNames.length === 0) roleNames.push('snc_basic_auth_api_access')

    var ghr = new GlideRecord('sys_user_has_role')
    if (!ghr.canRead()) {
        emitAccess('sys_user_has_role')
        return
    }
    ghr.addQuery('role.name', 'IN', roleNames.join(','))
    ghr.addQuery('user.active', true)
    ghr.query()

    var emitted = 0
    var seen = {}
    while (ghr.next() && emitted < MAX) {
        var userId = ghr.getValue('user')
        if (!userId || seen[userId]) continue
        seen[userId] = true

        // WSAO accounts are the legitimate Basic Auth path - skip.
        if (truthy(ghr.getValue('user.web_service_access_only'))) continue

        // One query for this user's privileged + mid_server grants.
        var priv = []
        var isMid = false
        var sub = new GlideRecord('sys_user_has_role')
        sub.addQuery('user', userId)
        sub.query()
        while (sub.next()) {
            var nm = sub.getValue('role.name') || sub.getDisplayValue('role')
            if (nm === 'mid_server') isMid = true
            for (var p = 0; p < PRIV.length; p++) {
                if (nm === PRIV[p]) priv.push(nm)
            }
        }
        if (isMid) continue

        var isPriv = priv.length > 0
        var userName = ghr.getDisplayValue('user') || userId
        var grantedRole = ghr.getValue('role.name') || ghr.getDisplayValue('role')

        var metadata = {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: {
                nis2: ['21.2.i', '21.2.j'],
                iso27001: ['A.5.16', 'A.8.5'],
                dora: ['9'],
            },
            evidence: {
                user_name: userName,
                user_sys_id: userId,
                granted_role: grantedRole,
                web_service_access_only: false,
                privileged_roles: priv,
            },
            severity: isPriv ? 1 : 2,
            remediation_id: 'basicauth-004',
            attack_path_refs: [],
        }

        var description =
            'Interactive account "' + userName + '" holds the Basic Auth API access role (' +
            grantedRole + ') but is NOT web-service-access-only, so it can log into the UI AND authenticate to APIs with single-factor Basic Auth - an institutionalized MFA bypass on a human-loginable account.'
        if (isPriv) {
            description = description +
                ' This account also holds privileged role(s): ' + priv.join(', ') +
                ' - a single-factor Basic Auth path to administrative capability. Treat as critical.'
        }
        description = description + ' User sys_id: ' + userId + '.'

        finding.setValue('finding_details',
            description + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(metadata))
        finding.increment()
        emitted++
    }

    function emitAccess(res) {
        var m = {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: { nis2: ['21.2.i'], iso27001: ['A.5.16'], dora: ['9'] },
            evidence: { status: 'insufficient_access', blocked_resource: res },
            severity: 4,
            remediation_id: 'basicauth-004-access',
            attack_path_refs: [],
        }
        finding.setValue('finding_details',
            'The scan account cannot read ' + res + ' (insufficient access), so Basic Auth role exposure could not be assessed. This is NOT a pass - grant the scan role read access to ' + res + ' and re-run.' +
            '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(m))
        finding.increment()
    }
})(finding)
