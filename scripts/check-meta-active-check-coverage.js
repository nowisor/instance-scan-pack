// nowisor - Meta active check coverage (ScriptOnlyCheck)
// Confirms the full pack inventory of active checks is live in x_nowisor_isp.
//
// Inventory source: manifest.json - the count of entries with active != false.
// EXPECTED_COUNT was left at the v1.0.0 value of 26 while the pack grew to 49
// checks (47 active). Since the test below is "totalActive >= EXPECTED_COUNT",
// a stale low value does not merely under-report: it makes this check pass on
// an instance missing up to 21 checks. A coverage check that cannot detect a
// partial install is worse than no coverage check, because it reports clean.
// lib/__tests__/check-status-parity.test.js now pins this literal to the
// manifest, so it cannot silently fall behind the pack again.
// Category: operational (not security) — this is install-health telemetry.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function metaActiveCheckCoverage(finding) {
    var EXPECTED_COUNT = 47
    var SCOPE_NAME = 'x_nowisor_isp'
    var tables = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check',
    ]
    var foundChecks = []
    var totalActive = 0

    for (var t = 0; t < tables.length; t++) {
        var gr = new GlideRecord(tables[t])
        gr.addQuery('sys_scope.scope', SCOPE_NAME)
        gr.addQuery('active', true)
        gr.query()
        while (gr.next()) {
            foundChecks.push({
                name: gr.getValue('name'),
                table: tables[t],
            })
            totalActive++
        }
    }

    if (totalActive >= EXPECTED_COUNT) return

    var metadata = {
        nowisor_check_id: 'nowisor-meta-active-check-coverage',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {},
        evidence: {
            expected_count: EXPECTED_COUNT,
            active_count: totalActive,
            missing_count: EXPECTED_COUNT - totalActive,
            found_checks: foundChecks,
            scope: SCOPE_NAME,
        },
        severity: 3,
        remediation_id: 'meta-coverage-001',
        attack_path_refs: [],
    }

    var details =
        'nowisor active check coverage incomplete: ' +
        totalActive +
        ' active of ' +
        EXPECTED_COUNT +
        ' expected. Re-run the pack installer or reactivate checks under the x_nowisor_isp scope.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
