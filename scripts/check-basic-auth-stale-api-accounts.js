// nowisor v1.1.0 - Dormant accounts with a Basic Auth API path (BASICAUTH-05)
//
// A single sys_user.last_login_time test is WRONG: web_service_access_only=true
// accounts CANNOT log into the UI by definition, so their last_login_time is
// structurally empty (verified dev265147 2026-06-11 - all 8 active WSAO accounts
// had empty/ancient last_login_time). Using it would false-flag every legitimate
// OOB service account. Two VALID dormancy signals instead:
//   (1) unused_tracked: sys_user_basic_auth_exception.last_seen older than
//       STALE_DAYS - the correct basic-auth-usage recency signal for any account.
//   (2) dormant_hybrid: active, NON-WSAO holder of the allow-list role whose
//       last_login_time is older than STALE_DAYS or never (valid because a
//       non-WSAO account CAN UI-login - a likely-departed human with a residual
//       API path).
// Pure WSAO service-account dormancy needs API-usage telemetry (the log-export
//   sensor / exception last_seen), not UI login - out of scope for a static check.
// Identifiers verified on Zurich Patch 6 (dev265484 / dev265147), 2026-06-11.
// Schema: v1   ES5-only (Instance Scan runtime constraint)
;(function basicAuthStaleApiAccounts(finding) {
    var STALE_DAYS = 90 // configurable threshold
    var MAX = 200
    var CHECK_ID = 'nowisor-basic-auth-stale-api-accounts'
    var EXC = 'sys_user_basic_auth_exception'

    function trim(s) { return String(s).replace(/^\s+|\s+$/g, '') }
    function truthy(v) { return v === '1' || v === 1 || v === 'true' || v === true }

    var cutoff = new GlideDateTime()
    cutoff.addDaysUTC(-STALE_DAYS)
    var cutoffVal = cutoff.getValue()

    function daysAgo(v) {
        if (!v) return null
        var d = new GlideDateTime(v)
        var now = new GlideDateTime()
        return Math.floor((now.getNumericValue() - d.getNumericValue()) / 86400000)
    }

    var emitted = 0
    var seen = {}

    function baseMeta(signal) {
        return {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: {
                nis2: ['21.2.i'],
                iso27001: ['A.5.16', 'A.5.17'],
                dora: ['9'],
            },
            evidence: { signal: signal },
            severity: 3,
            remediation_id: 'basicauth-005',
            attack_path_refs: [],
        }
    }
    function emit(meta, desc) {
        finding.setValue('finding_details', desc + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(meta))
        finding.increment()
        emitted++
    }
    function emitAccess(res) {
        var m = baseMeta('insufficient_access')
        m.severity = 4
        m.remediation_id = 'basicauth-005-access'
        m.evidence = { status: 'insufficient_access', blocked_resource: res }
        emit(m, 'The scan account cannot read ' + res + ' (insufficient access), so dormant Basic Auth accounts could not be fully assessed. This is NOT a pass - grant the scan role read access to ' + res + ' and re-run.')
    }

    // ---- Signal 1: tracked-but-unused (exception last_seen) ----
    var excProbe = new GlideRecord(EXC)
    if (excProbe.isValid() && excProbe.canRead()) {
        var e = new GlideRecord(EXC)
        e.addQuery('user.active', true)
        e.query()
        while (e.next() && emitted < MAX) {
            var ls = e.getValue('last_seen')
            if (ls && ls >= cutoffVal) continue // used recently
            var uid = e.getValue('user')
            if (!uid) continue
            seen[uid] = true
            var nm = e.getDisplayValue('user') || uid
            var di = daysAgo(ls)
            var m = baseMeta('unused_tracked')
            m.evidence.user_name = nm
            m.evidence.user_sys_id = uid
            m.evidence.last_seen = ls || null
            m.evidence.days_since_basic_auth = di
            m.evidence.usage_count = parseInt(e.getValue('usage_count'), 10) || 0
            m.evidence.stale_threshold_days = STALE_DAYS
            var lt = ls ? (ls + ' (' + di + ' days ago)') : 'no recorded Basic Auth activity'
            emit(m, 'Tracked Basic Auth account "' + nm + '" has not used Basic Auth recently - last seen: ' + lt + ', threshold ' + STALE_DAYS + ' days. A dormant Basic Auth path is standing attack surface with no offsetting use; revoke the path or deactivate the account before enforcement. User sys_id: ' + uid + '.')
        }
    }

    // ---- Signal 2: departed-human hybrid (non-WSAO role-holder, stale UI login) ----
    var rolesProp = gs.getProperty('glide.authenticate.basic_auth.allowed_roles', '')
    var roleNames = []
    if (rolesProp) {
        var parts = rolesProp.split(',')
        for (var a = 0; a < parts.length; a++) { var rn = trim(parts[a]); if (rn) roleNames.push(rn) }
    }
    if (roleNames.length === 0) roleNames.push('snc_basic_auth_api_access')

    var rg = new GlideRecord('sys_user_has_role')
    if (!rg.canRead()) {
        emitAccess('sys_user_has_role')
        return
    }
    rg.addQuery('role.name', 'IN', roleNames.join(','))
    rg.addQuery('user.active', true)
    rg.query()
    while (rg.next() && emitted < MAX) {
        var ruid = rg.getValue('user')
        if (!ruid || seen[ruid]) continue
        // Only UI-capable (non-WSAO) accounts: last_login_time is meaningful here.
        if (truthy(rg.getValue('user.web_service_access_only'))) continue
        var ll = rg.getValue('user.last_login_time')
        if (ll && ll >= cutoffVal) continue // logged in recently
        seen[ruid] = true
        var rnm = rg.getDisplayValue('user') || ruid
        var rdi = daysAgo(ll)
        var rm = baseMeta('dormant_hybrid')
        rm.evidence.user_name = rnm
        rm.evidence.user_sys_id = ruid
        rm.evidence.granted_role = rg.getValue('role.name') || rg.getDisplayValue('role')
        rm.evidence.web_service_access_only = false
        rm.evidence.last_login_time = ll || null
        rm.evidence.days_inactive = rdi
        rm.evidence.stale_threshold_days = STALE_DAYS
        var rlt = ll ? (ll + ' (' + rdi + ' days ago)') : 'never logged in'
        emit(rm, 'Account "' + rnm + '" holds the Basic Auth API role and can log into the UI, but its last UI login is stale - ' + rlt + ', threshold ' + STALE_DAYS + ' days. A likely-departed human retaining a single-factor Basic Auth API path; revoke the role or deactivate. User sys_id: ' + ruid + '.')
    }
})(finding)
