// nowisor v1.1.0 - Basic Auth hybrid accounts undecided check (BASICAUTH-03)
// Table sys_user_basic_auth_exception (verified Zurich Patch 6, dev265484,
//   2026-06-11). Fields: user (ref sys_user), decision (choice), action_taken
//   (boolean), last_seen (glide_date_time), usage_count (integer), source.
//   Decision choices (sys_choice): grant | no_grant | converted | global.
// "Undecided" = action_taken=false (auto-detected, admin has not acted).
// Cross-scope read of sys_user_basic_auth_exception requires the shipped
//   CrossScopePrivilege record.
// Schema: v1   ES5-only (Instance Scan runtime constraint)
;(function basicAuthHybridUndecided(finding) {
    var TABLE = 'sys_user_basic_auth_exception'
    var SAMPLE = 20
    var CHECK_ID = 'nowisor-basic-auth-hybrid-undecided'

    var probe = new GlideRecord(TABLE)
    if (!probe.isValid()) {
        emitInfo('feature_table_not_found',
            'The Basic Auth exception table (' + TABLE + ') is not present on this instance, so hybrid-account exposure cannot be inventoried. If the restriction feature is not yet on this release, this is expected - upgrade awareness only.')
        return
    }
    if (!probe.canRead()) {
        emitAccess(TABLE)
        return
    }

    var encoded = 'action_taken=false'
    var agg = new GlideAggregate(TABLE)
    agg.addEncodedQuery(encoded)
    agg.addAggregate('COUNT')
    agg.query()
    var total = 0
    if (agg.next()) total = parseInt(agg.getAggregate('COUNT'), 10) || 0
    if (total === 0) return

    var sample = []
    var gr = new GlideRecord(TABLE)
    gr.addEncodedQuery(encoded)
    gr.orderByDesc('usage_count')
    gr.setLimit(SAMPLE)
    gr.query()
    while (gr.next()) {
        sample.push({
            user_name: gr.getDisplayValue('user') || gr.getValue('user'),
            user_sys_id: gr.getValue('user'),
            decision: gr.getValue('decision'),
            last_seen: gr.getValue('last_seen') || null,
            usage_count: parseInt(gr.getValue('usage_count'), 10) || 0,
        })
    }

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
            table: TABLE,
            encoded_query: encoded,
            undecided_count: total,
            sample_users: sample,
        },
        severity: 2,
        remediation_id: 'basicauth-003',
        attack_path_refs: [],
    }

    var description =
        total +
        ' interactive account(s) detected using Basic Auth APIs have NOT been triaged (action_taken=false) in ' +
        TABLE +
        '. Each is an MFA-bypass surface today (single-factor Basic Auth on a UI-loginable account) and an unmanaged outcome at enforcement: depending on the decision applied, the bypass persists (grant) or the account is blocked with a 401 (no_grant). Triage each to convert to web-service-access-only, revoke API Basic Auth, or explicitly allow-list. Top ' +
        sample.length +
        ' by usage are listed in the evidence.'

    var details =
        description + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(metadata)
    finding.setValue('finding_details', details)
    finding.increment()

    function emitInfo(reason, desc) {
        var m = {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: { nis2: ['21.2.i'], iso27001: ['A.5.16'], dora: ['9'] },
            evidence: { table: TABLE, status: 'not_applicable', reason: reason },
            severity: 4,
            remediation_id: 'basicauth-003-na',
            attack_path_refs: [],
        }
        finding.setValue('finding_details',
            desc + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(m))
        finding.increment()
    }

    function emitAccess(res) {
        var m = {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: '1.0.0',
            nowisor_finding_schema: 'v1',
            framework_mappings: { nis2: ['21.2.i'], iso27001: ['A.5.16'], dora: ['9'] },
            evidence: { status: 'insufficient_access', blocked_resource: res },
            severity: 4,
            remediation_id: 'basicauth-003-access',
            attack_path_refs: [],
        }
        finding.setValue('finding_details',
            'The scan account cannot read ' + res + ' (insufficient access), so hybrid-account exposure could not be assessed. This is NOT a pass - grant the scan role read access to ' + res + ' and re-run.' +
            '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(m))
        finding.increment()
    }
})(finding)
