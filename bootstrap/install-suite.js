// nowisor Instance Scan Pack — Suite Bootstrap (v1.0.0)
//
// HOW TO USE
//   1. Install the nowisor pack update set first (System Update Sets → Retrieved Update Sets)
//   2. Open System Definition → Scripts - Background
//   3. Paste this entire script and click "Run script"
//   4. Read the gs.print() output to confirm the suite is provisioned
//
// WHAT IT DOES
//   Provisions the "nowisor Instance Scan Pack" suite and links all nowisor scan checks
//   (across all 4 check types) as members. The Fluent SDK 4.6.0 does not expose a
//   ScanCheckSuite API, so the suite and its m2m membership rows must be created via
//   GlideRecord after the update-set install.
//
// IDEMPOTENT
//   Safe to re-run. Finds existing suite by name and only inserts missing m2m rows.
//
// RE-RUN AFTER UPGRADE
//   The m2m rows (scan_check_suite_check) cascade-delete when the application is
//   uninstalled or `--reinstall`-ed. After every pack upgrade, re-run this script.
//   scan_finding rows persist across reinstalls because they're keyed against the
//   deterministic check sys_ids the SDK regenerates.
//
// CONTRACT (advisor integration)
//   This bootstrap does not touch finding emission. Each check emits its own v1
//   finding schema with the ---NOWISOR_METADATA--- separator. The advisor product
//   parses by suite membership + scope filter.
;(function installNowisorSuite() {
    var SUITE_NAME = 'nowisor Instance Scan Pack'
    var SUITE_DESC =
        'nowisor security checks — open-source agent for the nowisor advisor product. See nowisor.com.'
    var SCOPE_NAME = 'x_nowisor_isp'
    var CHECK_TABLES = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check',
    ]

    gs.print('=== nowisor suite bootstrap (v1.0.0) ===')

    // 1. Find or create suite
    var suiteSysId
    try {
        var suite = new GlideRecord('scan_check_suite')
        suite.addQuery('name', SUITE_NAME)
        suite.setLimit(1)
        suite.query()
        if (suite.next()) {
            suiteSysId = suite.getValue('sys_id')
            gs.print('Found existing suite: ' + suiteSysId)
        } else {
            suite.initialize()
            suite.setValue('name', SUITE_NAME)
            suite.setValue('description', SUITE_DESC)
            suite.setValue('active', true)
            suiteSysId = suite.insert()
            if (!suiteSysId) {
                gs.print(
                    'ERROR: suite insert returned no sys_id. Check that the executing user has create access to scan_check_suite.'
                )
                return
            }
            gs.print('Created suite: ' + suiteSysId)
        }
    } catch (e) {
        gs.print('ERROR creating/finding suite: ' + e)
        return
    }

    // 2. Inventory active nowisor checks across all 4 check tables
    var checks = []
    for (var ti = 0; ti < CHECK_TABLES.length; ti++) {
        var table = CHECK_TABLES[ti]
        try {
            var gr = new GlideRecord(table)
            gr.addQuery('sys_scope.name', SCOPE_NAME)
            gr.addQuery('active', true)
            gr.query()
            while (gr.next()) {
                checks.push({
                    sys_id: gr.getValue('sys_id'),
                    name: gr.getValue('name'),
                    table: table,
                })
            }
        } catch (e) {
            gs.print('  WARNING: could not query ' + table + ': ' + e)
        }
    }
    gs.print(
        'Found ' + checks.length + ' active nowisor checks across all check tables'
    )

    if (checks.length === 0) {
        gs.print(
            'ERROR: no active nowisor checks found. Confirm the update set was installed and committed, and that the scope "' +
                SCOPE_NAME +
                '" exists.'
        )
        return
    }

    // 3. Link each check to the suite (skip if already linked)
    var added = 0
    var skipped = 0
    var errors = 0
    for (var ci = 0; ci < checks.length; ci++) {
        var c = checks[ci]
        try {
            var existing = new GlideRecord('scan_check_suite_check')
            existing.addQuery('suite', suiteSysId)
            existing.addQuery('check', c.sys_id)
            existing.setLimit(1)
            existing.query()
            if (existing.next()) {
                skipped++
                continue
            }
            var m2m = new GlideRecord('scan_check_suite_check')
            m2m.initialize()
            m2m.setValue('suite', suiteSysId)
            m2m.setValue('check', c.sys_id)
            m2m.setValue('score_weight', 1)
            var m2mSysId = m2m.insert()
            if (m2mSysId) {
                added++
            } else {
                errors++
                gs.print('  ERROR linking ' + c.name + ' (' + c.sys_id + ')')
            }
        } catch (e) {
            errors++
            gs.print('  ERROR linking ' + c.name + ': ' + e)
        }
    }
    gs.print(
        'Membership: added ' + added + ', already-linked ' + skipped + ', errors ' + errors
    )

    // 4. Final report
    gs.print('')
    if (errors > 0) {
        gs.print(
            'Bootstrap completed with ' +
                errors +
                ' error(s). Review the error lines above; the suite may be partially provisioned.'
        )
    } else {
        gs.print('Bootstrap complete. Suite "' + SUITE_NAME + '" is ready.')
    }
    gs.print('')
    gs.print('To trigger a scan via REST:')
    gs.print(
        "  curl -u admin:PASSWORD -X POST 'https://<instance>.service-now.com/api/sn_cicd/instance_scan/full_scan'"
    )
    gs.print('')
    gs.print('Or via UI:')
    gs.print(
        "  Navigate to scan_check_suite list view, open '" +
            SUITE_NAME +
            "', click 'Execute Suite Scan'"
    )
})()
