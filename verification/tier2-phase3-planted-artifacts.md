# Tier 2 — Phase 3: LinterCheck planted-artifact validation

Goal: confirm each of the 7 zero-firing LinterChecks actually detects its target pattern.

The 8th LinterCheck (`nowisor-glide-record-vs-secure`) already produced 523 findings on OOB code in Phase 2 + had valid v1 metadata in 2.B — already validated, no planted artifact needed.

Predicates (extracted from each check script):

| Check | Predicate | Planted artifact strategy |
|---|---|---|
| eval-usage-detector | NAME 'eval' under CALL | `eval('1+1')` |
| set-workflow-false-detector | NAME 'setWorkflow' under CALL | `gr.setWorkflow(false)` |
| glide-evaluator-detector | NAME 'GlideEvaluator' anywhere | `new GlideEvaluator()` |
| set-roles-detector | NAME 'setRoles' under CALL | `gs.getUser().setRoles('admin')` |
| hardcoded-credentials | LITERAL string matching `password\s*[:=]\s*['"]…['"]` etc | `var password = "Pa$$w0rd123!"` |
| direct-property-write | LITERAL `'sys_properties'` under NEW/CALL ancestor | `new GlideRecord('sys_properties')` |
| domain-separation-script-include | setRoles/setSession present AND no 'sys_overrides' anywhere | setRoles without sys_overrides reference (the setRoles-test artifact double-fires this) |

---

## Step 3.1 — Plant the artifacts

```javascript
;(function plant() {
    gs.print('=== Phase 3.1: plant test Script Includes ===')

    var artifacts = [
        {
            name: 'nowisor_tier2_eval_test',
            api_name: 'global.nowisor_tier2_eval_test',
            description: 'Tier 2 test artifact — eval() detector — DELETE after validation',
            script: "var nowisor_tier2_eval_test = Class.create();\nnowisor_tier2_eval_test.prototype = {\n  initialize: function() {},\n  test: function() { return eval('1+1'); },\n  type: 'nowisor_tier2_eval_test'\n};"
        },
        {
            name: 'nowisor_tier2_setworkflow_test',
            api_name: 'global.nowisor_tier2_setworkflow_test',
            description: 'Tier 2 test artifact — setWorkflow(false) detector — DELETE after validation',
            script: "var nowisor_tier2_setworkflow_test = Class.create();\nnowisor_tier2_setworkflow_test.prototype = {\n  initialize: function() {},\n  test: function() { var gr = new GlideRecord('incident'); gr.setWorkflow(false); gr.update(); },\n  type: 'nowisor_tier2_setworkflow_test'\n};"
        },
        {
            name: 'nowisor_tier2_glideevaluator_test',
            api_name: 'global.nowisor_tier2_glideevaluator_test',
            description: 'Tier 2 test artifact — GlideEvaluator detector — DELETE after validation',
            script: "var nowisor_tier2_glideevaluator_test = Class.create();\nnowisor_tier2_glideevaluator_test.prototype = {\n  initialize: function() {},\n  test: function() { var ev = new GlideEvaluator(); return ev.evaluateString('1+1'); },\n  type: 'nowisor_tier2_glideevaluator_test'\n};"
        },
        {
            name: 'nowisor_tier2_setroles_test',
            api_name: 'global.nowisor_tier2_setroles_test',
            description: 'Tier 2 test artifact — setRoles + domain-separation detectors — DELETE after validation',
            // NO sys_overrides reference — this artifact intentionally double-fires
            // both setRoles-detector AND domain-separation-script-include.
            script: "var nowisor_tier2_setroles_test = Class.create();\nnowisor_tier2_setroles_test.prototype = {\n  initialize: function() {},\n  test: function() { gs.getUser().setRoles('admin'); },\n  type: 'nowisor_tier2_setroles_test'\n};"
        },
        {
            name: 'nowisor_tier2_hardcoded_credentials_test',
            api_name: 'global.nowisor_tier2_hardcoded_credentials_test',
            description: 'Tier 2 test artifact — hardcoded credentials detector — DELETE after validation',
            script: "var nowisor_tier2_hardcoded_credentials_test = Class.create();\nnowisor_tier2_hardcoded_credentials_test.prototype = {\n  initialize: function() {},\n  test: function() { var password = 'Pa$$w0rd123!'; var apiKey = 'sk_test_abc123def456'; return password + apiKey; },\n  type: 'nowisor_tier2_hardcoded_credentials_test'\n};"
        },
        {
            name: 'nowisor_tier2_direct_property_write_test',
            api_name: 'global.nowisor_tier2_direct_property_write_test',
            description: 'Tier 2 test artifact — direct sys_properties write detector — DELETE after validation',
            script: "var nowisor_tier2_direct_property_write_test = Class.create();\nnowisor_tier2_direct_property_write_test.prototype = {\n  initialize: function() {},\n  test: function() { var gr = new GlideRecord('sys_properties'); gr.addQuery('name', 'tier2_test'); gr.query(); },\n  type: 'nowisor_tier2_direct_property_write_test'\n};"
        }
    ]

    var planted = []
    for (var i = 0; i < artifacts.length; i++) {
        var a = artifacts[i]
        // Skip if already exists
        var existing = new GlideRecord('sys_script_include')
        existing.addQuery('name', a.name)
        existing.setLimit(1)
        existing.query()
        if (existing.next()) {
            planted.push({ name: a.name, sys_id: existing.getValue('sys_id'), pre_existed: true })
            gs.print('  Already exists: ' + a.name)
            continue
        }
        var gr = new GlideRecord('sys_script_include')
        gr.initialize()
        gr.setValue('name', a.name)
        gr.setValue('api_name', a.api_name)
        gr.setValue('description', a.description)
        gr.setValue('script', a.script)
        gr.setValue('active', true)
        gr.setValue('access', 'package_private')
        var sysId = gr.insert()
        if (sysId) {
            planted.push({ name: a.name, sys_id: sysId, pre_existed: false })
            gs.print('  Planted: ' + a.name + ' (sys_id: ' + sysId + ')')
        } else {
            gs.print('  ERROR planting: ' + a.name)
        }
    }
    gs.print('')
    gs.print('Planted: ' + planted.filter(function(x){return !x.pre_existed}).length + ' new, ' + planted.filter(function(x){return x.pre_existed}).length + ' pre-existing')
    gs.print('---PLANTED ARTIFACTS---')
    gs.print(JSON.stringify(planted, null, 2))
})()
```

Save the printed JSON list — needed for cleanup in Step 3.4.

---

## Step 3.2 — Trigger fresh scan

UI: `scan_check_suite.list` → "nowisor Instance Scan Pack" → Execute Suite Scan.

Or programmatic:

```javascript
;(function trigger() {
    var s = new GlideRecord('scan_check_suite')
    s.addQuery('name', 'nowisor Instance Scan Pack')
    s.query()
    if (s.next()) {
        var pid = new sn_instance_scan.ScanInstance().triggerSuiteScan(s.getValue('sys_id'))
        gs.print('Scan triggered: ' + pid)
    }
})()
```

Wait ~5-10 min.

---

## Step 3.3 — Verify each LinterCheck detected its planted artifact

```javascript
;(function verifyLinters() {
    var r = new GlideRecord('scan_result')
    r.orderByDesc('sys_created_on')
    r.setLimit(1)
    r.query()
    if (!r.next()) {
        gs.print('No scan_result')
        return
    }
    var RID = r.getValue('sys_id')
    gs.print('=== Phase 3.3: planted-artifact detection ===')
    gs.print('scan_result: ' + r.getValue('number') + ' (' + RID + ')')
    gs.print('')

    var expectations = [
        { check_id: 'nowisor-eval-usage-detector', planted_name: 'nowisor_tier2_eval_test' },
        { check_id: 'nowisor-set-workflow-false-detector', planted_name: 'nowisor_tier2_setworkflow_test' },
        { check_id: 'nowisor-glide-evaluator-detector', planted_name: 'nowisor_tier2_glideevaluator_test' },
        { check_id: 'nowisor-set-roles-detector', planted_name: 'nowisor_tier2_setroles_test' },
        { check_id: 'nowisor-hardcoded-credentials', planted_name: 'nowisor_tier2_hardcoded_credentials_test' },
        { check_id: 'nowisor-direct-property-write', planted_name: 'nowisor_tier2_direct_property_write_test' },
        { check_id: 'nowisor-domain-separation-script-include', planted_name: 'nowisor_tier2_setroles_test' }
    ]

    var passCount = 0
    var failCount = 0

    for (var i = 0; i < expectations.length; i++) {
        var exp = expectations[i]
        var f = new GlideRecord('scan_finding')
        f.addQuery('result', RID)
        f.addQuery('check.sys_scope.scope', 'x_nowisor_isp')
        f.query()

        var matchedPlanted = false
        var totalMatched = 0
        var sourceSampleNames = []
        while (f.next()) {
            var details = f.getValue('finding_details') || ''
            var sep = '---NOWISOR_METADATA---'
            var idx = details.indexOf(sep)
            if (idx < 0) continue
            try {
                var meta = JSON.parse(details.substring(idx + sep.length).trim())
                if (meta.nowisor_check_id !== exp.check_id) continue
                totalMatched++
                var sourceName = f.getDisplayValue('source') || ''
                if (sourceSampleNames.length < 5) sourceSampleNames.push(sourceName)
                if (sourceName.indexOf(exp.planted_name) > -1 || sourceName === exp.planted_name) {
                    matchedPlanted = true
                }
            } catch (e) {}
        }

        var verdict = matchedPlanted ? 'PASS' : (totalMatched > 0 ? 'PARTIAL' : 'FAIL')
        if (verdict === 'PASS') passCount++
        else failCount++

        gs.print(verdict + ' | ' + exp.check_id + ' | total findings: ' + totalMatched + ' | planted detected: ' + matchedPlanted)
        if (sourceSampleNames.length > 0) gs.print('  sample sources: ' + sourceSampleNames.join(', '))
    }
    gs.print('')
    gs.print('Phase 3.3 summary: ' + passCount + ' PASS, ' + failCount + ' FAIL')
})()
```

**Pass criteria:** each of the 7 checks shows at least one finding whose `source` matches the planted Script Include name.

**Note on domain-separation:** the setRoles planted artifact intentionally double-fires both `set-roles-detector` and `domain-separation-script-include` (auth-mutation present, no sys_overrides reference). Both should PASS against the same planted artifact.

---

## Step 3.4 — Cleanup (NON-NEGOTIABLE)

```javascript
;(function cleanup() {
    var plantedNames = [
        'nowisor_tier2_eval_test',
        'nowisor_tier2_setworkflow_test',
        'nowisor_tier2_glideevaluator_test',
        'nowisor_tier2_setroles_test',
        'nowisor_tier2_hardcoded_credentials_test',
        'nowisor_tier2_direct_property_write_test'
    ]
    var deleted = 0
    for (var i = 0; i < plantedNames.length; i++) {
        var gr = new GlideRecord('sys_script_include')
        gr.addQuery('name', plantedNames[i])
        gr.query()
        if (gr.next()) {
            gr.deleteRecord()
            deleted++
            gs.print('Deleted: ' + plantedNames[i])
        } else {
            gs.print('Not present: ' + plantedNames[i])
        }
    }

    // Verify nothing remains
    var check = new GlideRecord('sys_script_include')
    check.addQuery('name', 'STARTSWITH', 'nowisor_tier2_')
    check.query()
    gs.print('')
    gs.print('Cleanup complete: ' + deleted + ' deleted | remaining tier2 artifacts: ' + check.getRowCount())
    if (check.getRowCount() > 0) {
        gs.print('ERROR: residual artifacts present — delete manually:')
        while (check.next()) {
            gs.print('  ' + check.getValue('name') + ' (' + check.getValue('sys_id') + ')')
        }
    }
})()
```

Pass criteria: `Cleanup complete: 6 deleted | remaining tier2 artifacts: 0`

(6 deletions because the setRoles planted artifact serves both set-roles-detector and domain-separation tests.)

---

## Reporting back

For each step, paste output:
1. Step 3.1 — number planted vs pre-existed
2. Step 3.2 — scan triggered
3. Step 3.3 — full PASS/FAIL per check + summary
4. Step 3.4 — cleanup count + residual check
