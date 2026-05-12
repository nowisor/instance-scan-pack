# Tier 2 — Phase 1: Pre-flight + fresh suite scan

Run these in order on dev265484. Report back the outputs.

---

## Step 1.0 — Confirm v1.0.0-build state on dev265484

**Where:** Background Scripts

```javascript
;(function preflight() {
    gs.print('=== Phase 1 pre-flight ===')
    var s = new GlideRecord('scan_check_suite')
    s.addQuery('name', 'nowisor Instance Scan Pack')
    s.query()
    if (!s.next()) {
        gs.print('FAIL: suite missing — re-run bootstrap/install-suite.js first')
        return
    }
    var suiteId = s.getValue('sys_id')
    gs.print('Suite present: ' + suiteId)
    gs.print('  Created: ' + s.getValue('sys_created_on'))

    var m = new GlideRecord('scan_check_suite_check')
    m.addQuery('suite', suiteId)
    m.query()
    gs.print('  m2m rows: ' + m.getRowCount())

    // Per-type active counts
    var tables = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check',
    ]
    var total = 0
    for (var i = 0; i < tables.length; i++) {
        var gr = new GlideRecord(tables[i])
        gr.addQuery('sys_scope.scope', 'x_nowisor_isp')
        gr.addQuery('active', true)
        gr.query()
        var n = gr.getRowCount()
        total += n
        gs.print('  ' + tables[i] + ': ' + n)
    }
    gs.print('  TOTAL ACTIVE: ' + total)
})()
```

**Expected:**
- Suite present (sys_id)
- m2m rows: 26
- Per-table: 16 / 1 / 8 / 1
- TOTAL ACTIVE: 26

If any number is off, STOP — re-run `bootstrap/install-suite.js` before continuing.

---

## Step 1.1 — Trigger a fresh suite scan (UI is simplest)

**Easier path (UI):**

1. Navigate to `scan_check_suite.list` (search "Suites" in the nav)
2. Open the **nowisor Instance Scan Pack** record
3. Right-click the header → **Execute Suite Scan** (or use the related link)
4. Note the scan started; you'll get a notification when complete

**Programmatic path (Background Script, alternative):**

```javascript
;(function triggerScan() {
    var s = new GlideRecord('scan_check_suite')
    s.addQuery('name', 'nowisor Instance Scan Pack')
    s.query()
    if (!s.next()) {
        gs.print('ERROR: suite missing')
        return
    }
    var scanner = new sn_instance_scan.ScanInstance()
    var progressId = scanner.triggerSuiteScan(s.getValue('sys_id'))
    gs.print('Scan triggered. Progress ID: ' + progressId)
    gs.print('Monitor at: scan_result_list.do (orderByDesc sys_created_on)')
})()
```

Either way: wait ~3-10 minutes for the scan to finish. LinterChecks are the slowest because they scan every Script Include / Business Rule / UI Action body.

---

## Step 1.2 — Confirm scan completed; capture scan_result sys_id

```javascript
;(function captureResult() {
    gs.print('=== Phase 1.2: capture scan_result ===')
    var r = new GlideRecord('scan_result')
    r.addQuery('scan_check_suite.name', 'nowisor Instance Scan Pack')
    r.orderByDesc('sys_created_on')
    r.setLimit(1)
    r.query()
    if (!r.next()) {
        gs.print('No scan_result found — scan may not have completed yet, retry in 2 min')
        return
    }
    gs.print('scan_result sys_id: ' + r.getValue('sys_id'))
    gs.print('  number: ' + r.getValue('number'))
    gs.print('  state: ' + r.getValue('state'))
    gs.print('  started: ' + r.getValue('started'))
    gs.print('  completed: ' + r.getValue('completed'))

    // Count findings linked to this result
    var f = new GlideRecord('scan_finding')
    f.addQuery('result', r.getValue('sys_id'))
    f.query()
    gs.print('  findings: ' + f.getRowCount())

    // Count check executions
    // (table is scan_check_execution if present; otherwise the result row itself
    //  has summary fields. If the next query 404s, ignore — we'll use the result
    //  sys_id alone for Phase 2.)
    try {
        var e = new GlideRecord('scan_check_execution')
        e.addQuery('result', r.getValue('sys_id'))
        e.query()
        gs.print('  executions: ' + e.getRowCount())
    } catch (err) {
        gs.print('  executions: (scan_check_execution not present or error: ' + err + ')')
    }
})()
```

**Pass criteria:**
- `state` is something terminal (likely `successful` or `complete` — depends on platform)
- `findings` ≥ 0
- `executions` should be 26 (if the table exists on this platform version)

**Report back:**
1. Pre-flight output (Step 1.0)
2. Whether you used UI or programmatic trigger (Step 1.1)
3. Step 1.2 output verbatim — especially the `scan_result sys_id` (Phase 2 needs it)
