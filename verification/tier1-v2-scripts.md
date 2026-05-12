# Tier 1 — Verification 2: Bootstrap idempotency on dev265484

Paste-and-run scripts for the user's interactive ServiceNow session.

Run in order. Capture each output verbatim and report back so the addendum can document outcomes.

---

## Step 2.1 — Capture pre-state (and clean if needed)

**Where:** dev265484 → System Definition → Scripts - Background

```javascript
;(function preState() {
    gs.print('=== Step 2.1: pre-state capture ===')
    var s = new GlideRecord('scan_check_suite')
    s.addQuery('name', 'nowisor Instance Scan Pack')
    s.query()
    if (s.next()) {
        var sysId = s.getValue('sys_id')
        gs.print('Existing suite found: ' + sysId)
        gs.print('  Created: ' + s.getValue('sys_created_on'))

        var m = new GlideRecord('scan_check_suite_check')
        m.addQuery('suite', sysId)
        m.query()
        gs.print('  m2m rows: ' + m.getRowCount())

        // CLEAN: delete m2m rows and the suite for a clean idempotency test
        var deleteM = new GlideRecord('scan_check_suite_check')
        deleteM.addQuery('suite', sysId)
        deleteM.deleteMultiple()
        gs.print('  m2m rows deleted')

        s.deleteRecord()
        gs.print('  suite deleted — clean state for verification')
    } else {
        gs.print('No existing nowisor suite — clean state already')
    }
})()
```

**Expected output:** either "No existing nowisor suite — clean state already" or details of the deleted suite.

---

## Step 2.2 — Install v1.0.0 build to dev265484

**Where:** developer terminal (NOT inside dev265484)

```bash
cd "/Users/TheBrain/My Drive/vsme/vsme-kb/nowisor/instance-scan-pack"
npx now-sdk install --reinstall --auth <dev265484-auth-token>
```

Then in dev265484 Background Scripts, verify 26 active checks:

```javascript
;(function postInstall() {
    gs.print('=== Step 2.2: post-install check counts ===')
    var tables = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check',
    ]
    var total = 0
    for (var i = 0; i < tables.length; i++) {
        var gr = new GlideRecord(tables[i])
        gr.addQuery('sys_scope.name', 'x_nowisor_isp')
        gr.addQuery('active', true)
        gr.query()
        var n = gr.getRowCount()
        total += n
        gs.print('  ' + tables[i] + ': ' + n)
    }
    gs.print('TOTAL: ' + total)
})()
```

**Expected output:**
```
scan_script_only_check: 16
scan_table_check: 1
scan_linter_check: 8
scan_column_type_check: 1
TOTAL: 26
```

If TOTAL is not 26, STOP and report — the install is incomplete.

---

## Step 2.3 — Bootstrap first run

**Where:** dev265484 → System Definition → Scripts - Background

Paste the entire contents of `bootstrap/install-suite.js` and run.

**Expected output shape:**
```
=== nowisor suite bootstrap (v1.0.0) ===
Created suite: <sys_id>
Found 26 active nowisor checks across all check tables
Membership: added 26, already-linked 0, errors 0
Bootstrap complete. Suite "nowisor Instance Scan Pack" is ready.
```

Capture the exact output. Then verify post-state:

```javascript
;(function postBootstrap1() {
    gs.print('=== Step 2.3: post-bootstrap-1 state ===')
    var s = new GlideRecord('scan_check_suite')
    s.addQuery('name', 'nowisor Instance Scan Pack')
    s.query()
    if (s.next()) {
        var sysId = s.getValue('sys_id')
        gs.print('Suite sys_id: ' + sysId)
        var m = new GlideRecord('scan_check_suite_check')
        m.addQuery('suite', sysId)
        m.query()
        gs.print('m2m rows: ' + m.getRowCount())
    } else {
        gs.print('ERROR: no suite found post-bootstrap')
    }
})()
```

**Expected:** m2m rows: 26.

---

## Step 2.4 — Bootstrap second run (idempotency test)

**Where:** dev265484 → System Definition → Scripts - Background

Paste `bootstrap/install-suite.js` again. Run.

**Expected output shape:**
```
=== nowisor suite bootstrap (v1.0.0) ===
Found existing suite: <same sys_id as Step 2.3>
Found 26 active nowisor checks across all check tables
Membership: added 0, already-linked 26, errors 0
Bootstrap complete. Suite "nowisor Instance Scan Pack" is ready.
```

Re-run the state-check from Step 2.3. m2m rows must still be 26. Suite sys_id must be identical.

**Idempotency criteria (ALL must pass):**
1. `added 0`
2. `already-linked 26`
3. `errors 0`
4. m2m row count unchanged at 26
5. Suite sys_id unchanged

---

## Step 2.5 — Smoke test (suite triggers check execution)

**Where:** dev265484 UI

1. Navigate to **System Definition → Scan → Suites** (or open `scan_check_suite.list`)
2. Open the "nowisor Instance Scan Pack" suite record
3. Click "Execute Suite Scan" related link (or whatever the Zurich UI equivalent is)
4. Wait ~3-5 minutes for completion (LinterChecks take ~110s each per v0.2 retrospective)

Then check execution outcomes:

```javascript
;(function smokeTest() {
    gs.print('=== Step 2.5: smoke test execution counts ===')
    var e = new GlideRecord('scan_check_execution')
    e.addQuery('check.sys_scope.name', 'x_nowisor_isp')
    e.orderByDesc('sys_created_on')
    e.setLimit(50)
    e.query()
    gs.print('Recent nowisor executions: ' + e.getRowCount())

    var executed = 0
    var errored = 0
    while (e.next()) {
        var msg = e.getValue('message') || ''
        if (msg.length > 0) {
            errored++
            gs.print(
                '  ERROR: ' +
                    e.getDisplayValue('check') +
                    ' :: ' +
                    msg.substring(0, 200)
            )
        } else {
            executed++
        }
    }
    gs.print('Executed cleanly: ' + executed + ' | Errors: ' + errored)
})()
```

**Pass criteria (smoke level — not Tier 2 content validation):**
- 26 execution records present
- Zero or near-zero errors (≤2 acceptable; document each for Tier 2 follow-up)

If many errors (>3) or cross-scope permission denied, STOP and report — that signals deeper issues than this sprint targets.

---

## Reporting back

Paste back to Claude:
1. Step 2.1 output (one-liner)
2. Step 2.2 totals (4 counts + total)
3. Step 2.3 verbatim bootstrap output + m2m count
4. Step 2.4 verbatim bootstrap output + m2m count
5. Step 2.5 execution counts (`Executed cleanly: N | Errors: M`) and any error lines

Claude will record outcomes in `V1_RETROSPECTIVE_ADDENDUM.md`.
