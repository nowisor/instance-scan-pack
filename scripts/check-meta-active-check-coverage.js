// nowisor v1.0.0 — Meta active check coverage (ScriptOnlyCheck)
// Confirms the full v1.0.0 inventory of 26 checks is active in x_nowisor_isp.
//
// Inventory source: manifest.json (26 entries as of release 2026-05-11).
// Category: operational (not security) — this is install-health telemetry.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function metaActiveCheckCoverage(finding) {
    var EXPECTED_COUNT = 26
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
        ' expected (v1.0.0 inventory). Re-run the pack installer or reactivate checks under the x_nowisor_isp scope.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
