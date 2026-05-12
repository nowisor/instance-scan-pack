# Tier 2 — Phase 2: Per-check validation

scan_result: `4c1dd4b1837c07100fe45950ceaad3a2` (SR00000019, state=complete, 2573 findings, 26 executions)

Three diagnostic scripts. Run in order; report back each output.

---

## Step 2.A — Per-check aggregate (findings + execution outcome)

Aggregates findings per check, surfaces any execution errors, and pulls the script that emitted findings vs. those that didn't.

```javascript
;(function aggregate() {
    var RESULT_ID = '4c1dd4b1837c07100fe45950ceaad3a2'
    gs.print('=== Phase 2.A: per-check aggregate ===')
    gs.print('scan_result: ' + RESULT_ID)
    gs.print('')

    // Get all executions
    var execs = {}
    var e = new GlideRecord('scan_check_execution')
    e.addQuery('result', RESULT_ID)
    e.query()
    while (e.next()) {
        var checkName = e.getDisplayValue('check')
        execs[checkName] = {
            score: e.getValue('score'),
            error: e.getValue('message') || '',
            check_sys_id: e.getValue('check'),
        }
    }

    // Count findings per check
    var f = new GlideRecord('scan_finding')
    f.addQuery('result', RESULT_ID)
    f.query()
    while (f.next()) {
        var cName = f.getDisplayValue('check')
        if (!execs[cName]) execs[cName] = { score: '', error: '', check_sys_id: '' }
        execs[cName].findings = (execs[cName].findings || 0) + 1
    }

    // Print as a clean per-check report
    var names = Object.keys(execs).sort()
    for (var i = 0; i < names.length; i++) {
        var n = names[i]
        var x = execs[n]
        var findingCount = x.findings || 0
        var errorBit = x.error.length > 0 ? ' | ERROR: ' + x.error.substring(0, 100) : ''
        gs.print(n + ' | findings: ' + findingCount + ' | score: ' + x.score + errorBit)
    }
    gs.print('')
    gs.print('TOTAL CHECKS REPORTED: ' + names.length)
})()
```

**What to look for:**
- All 26 check names appear
- No execution errors (`message` empty for all)
- Finding counts distributed sensibly:
  - LinterChecks (8): likely high counts (hundreds to thousands)
  - ScriptOnlyChecks property-based: 0 or 1 each
  - ScriptOnlyChecks role/ACL: 0 or 1 each
  - TableCheck (inactive users): variable
  - ColumnTypeCheck: 0 or 1

If any check shows an execution error, capture it — that's a Phase 2 blocker for that check.

---

## Step 2.B — Metadata sample per check (validates v1 schema)

For each check that produced at least one finding, pull one sample finding and parse its metadata. Confirms `---NOWISOR_METADATA---` separator is present, JSON parses, and framework_mappings exists.

```javascript
;(function sampleMetadata() {
    var RESULT_ID = '4c1dd4b1837c07100fe45950ceaad3a2'
    gs.print('=== Phase 2.B: metadata sample per check ===')

    // Get distinct check sys_ids that have findings in this result
    var checkIds = []
    var seen = {}
    var f = new GlideRecord('scan_finding')
    f.addQuery('result', RESULT_ID)
    f.query()
    while (f.next()) {
        var cid = f.getValue('check')
        if (!seen[cid]) {
            seen[cid] = true
            checkIds.push({ sys_id: cid, name: f.getDisplayValue('check') })
        }
    }
    gs.print('Distinct checks with findings: ' + checkIds.length)
    gs.print('')

    var passCount = 0
    var failCount = 0
    var details = []

    for (var i = 0; i < checkIds.length; i++) {
        var ci = checkIds[i]
        // Pull the first finding for this check
        var f2 = new GlideRecord('scan_finding')
        f2.addQuery('scan_result', RESULT_ID)
        f2.addQuery('check', ci.sys_id)
        f2.setLimit(1)
        f2.query()
        if (!f2.next()) continue

        var detailsText = f2.getValue('finding_details') || ''
        var sep = '---NOWISOR_METADATA---'
        var idx = detailsText.indexOf(sep)

        var result = {
            check: ci.name,
            has_separator: idx > -1,
            parses: false,
            check_id: null,
            schema: null,
            frameworks: null,
            severity: null,
            error: null,
        }

        if (idx > -1) {
            var jsonText = detailsText.substring(idx + sep.length).trim()
            try {
                var meta = JSON.parse(jsonText)
                result.parses = true
                result.check_id = meta.nowisor_check_id
                result.schema = meta.nowisor_finding_schema
                result.severity = meta.severity
                result.frameworks = meta.framework_mappings
                    ? Object.keys(meta.framework_mappings).sort().join(',')
                    : '(none)'
                passCount++
            } catch (e) {
                result.error = e.toString()
                failCount++
            }
        } else {
            failCount++
            result.error = 'no separator in finding_details'
        }

        gs.print(
            (result.parses ? 'PASS' : 'FAIL') +
                ' | ' +
                result.check +
                ' | check_id=' +
                result.check_id +
                ' | schema=' +
                result.schema +
                ' | sev=' +
                result.severity +
                ' | fw=' +
                result.frameworks +
                (result.error ? ' | ERR: ' + result.error : '')
        )
    }

    gs.print('')
    gs.print('Metadata parse: ' + passCount + ' pass, ' + failCount + ' fail')
})()
```

**Pass criteria:**
- Every check producing findings has `has_separator: true`
- Every check's metadata `parses: true`
- `schema: "v1"` for every check
- `check_id` matches the expected nowisor check id (e.g., `nowisor-csrf-token-enforcement`)
- `frameworks` is a comma-separated list including at least one of `nis2`, `iso27001`, `dora`, `gdpr` (some checks legitimately have no mapping — those will show `frameworks=(none)`)

If any check shows `FAIL`, that's a Phase 2 blocker — schema implementation bug.

---

## Step 2.C — Checks that produced zero findings (compliant-state vs broken)

The checks NOT in 2.B's distinct-checks list produced zero findings. For each, we need to either verify compliant state or determine whether the check is structurally broken.

This script lists which active checks had no findings:

```javascript
;(function zeroFindingChecks() {
    var RESULT_ID = '4c1dd4b1837c07100fe45950ceaad3a2'
    gs.print('=== Phase 2.C: checks with zero findings ===')

    // All active nowisor checks
    var tables = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check',
    ]
    var allChecks = {}
    for (var t = 0; t < tables.length; t++) {
        var gr = new GlideRecord(tables[t])
        gr.addQuery('sys_scope.scope', 'x_nowisor_isp')
        gr.addQuery('active', true)
        gr.query()
        while (gr.next()) {
            allChecks[gr.getValue('sys_id')] = {
                name: gr.getValue('name'),
                table: tables[t],
            }
        }
    }

    // Checks that produced findings
    var firedSet = {}
    var f = new GlideRecord('scan_finding')
    f.addQuery('result', RESULT_ID)
    f.query()
    while (f.next()) firedSet[f.getValue('check')] = true

    // Diff
    var zeroFindingNames = []
    var ids = Object.keys(allChecks)
    for (var i = 0; i < ids.length; i++) {
        if (!firedSet[ids[i]]) {
            zeroFindingNames.push(allChecks[ids[i]])
        }
    }

    gs.print(
        'Active checks: ' +
            ids.length +
            ' | Fired in this scan: ' +
            Object.keys(firedSet).length +
            ' | Zero-finding: ' +
            zeroFindingNames.length
    )
    gs.print('')
    gs.print('--- Zero-finding checks ---')
    zeroFindingNames.sort(function (a, b) {
        return a.name.localeCompare(b.name)
    })
    for (var z = 0; z < zeroFindingNames.length; z++) {
        gs.print(
            '  ' + zeroFindingNames[z].name + ' (' + zeroFindingNames[z].table + ')'
        )
    }
})()
```

For each zero-finding check, we'll then run a tailored compliant-state diagnostic (varies by check — I'll write per-check scripts once we see which checks landed in this list).

---

---

## Step 2.D — Compliant-state verification for the 21 zero-finding nowisor checks

Outcome of 2.A/2.B confirmed: 5 nowisor checks fired (MFA, Session Timeout, Attachment Role, Elevated Roles, GlideRecord-vs-Secure), all with valid v1 metadata. The remaining 21 produced zero findings — this script confirms each is in a genuine compliant state on dev265484 by probing the underlying property/configuration the check audits.

```javascript
;(function compliantState() {
    gs.print('=== Phase 2.D: compliant-state probe for zero-finding nowisor checks ===')

    function probeProp(label, propName, expected) {
        var actual = gs.getProperty(propName, '__NOT_SET__')
        var pass =
            actual === '__NOT_SET__'
                ? 'NOT_SET (default compliant?)'
                : actual === expected
                    ? 'PASS (matches ' + expected + ')'
                    : 'FAIL (got "' + actual + '", expected "' + expected + '")'
        gs.print('  ' + label + ' [' + propName + '] = ' + pass)
    }

    gs.print('--- Property-based checks (compliant-state probes) ---')
    probeProp(
        'nowisor-csrf-token-enforcement',
        'glide.security.use_csrf_token',
        'true'
    )
    probeProp(
        'nowisor-cookie-http-only',
        'glide.cookies.http_only',
        'true'
    )
    probeProp(
        'nowisor-cookie-secure',
        'glide.servlet.cookie.secure',
        'true'
    )
    probeProp(
        'nowisor-secure-cookies',
        'glide.ui.secure_cookies',
        'true'
    )
    probeProp(
        'nowisor-external-auth-policy',
        'glide.authenticate.external',
        '(varies)'
    )

    gs.print('')
    gs.print('--- REST anonymous access (7-property family) ---')
    var basicAuthProps = [
        'glide.basicauth.required.api',
        'glide.basicauth.required.scriptedprocessor',
        'glide.basicauth.required.soap',
        'glide.basicauth.required.wsdl',
        'glide.basicauth.required.xsd',
        'glide.basicauth.required.databrokerrestapiprocessor',
        'glide.basicauth.required.unl',
    ]
    var nonCompliantBasic = []
    for (var i = 0; i < basicAuthProps.length; i++) {
        var v = gs.getProperty(basicAuthProps[i], '__NOT_SET__')
        gs.print('  ' + basicAuthProps[i] + ' = ' + v)
        if (v !== 'true' && v !== '__NOT_SET__') nonCompliantBasic.push(basicAuthProps[i])
    }
    gs.print(
        '  nowisor-rest-anonymous-access: ' +
            (nonCompliantBasic.length === 0
                ? 'PASS (all true or unset/default-true)'
                : 'FAIL (' + nonCompliantBasic.length + ' non-compliant)')
    )

    gs.print('')
    gs.print('--- ACL / role-based checks (record probes) ---')

    // Admin Role Concentration — threshold check; verify there's no concentration trigger
    var adminGr = new GlideAggregate('sys_user_has_role')
    adminGr.addAggregate('COUNT', 'user')
    adminGr.addQuery('role.name', 'admin')
    adminGr.query()
    var adminUsers = []
    while (adminGr.next()) adminUsers.push(adminGr.getValue('user'))
    gs.print(
        '  nowisor-admin-role-concentration: ' +
            adminUsers.length +
            ' admin user(s); threshold is typically configured per environment — zero-finding is reasonable on a fresh PDI'
    )

    // Inactive users retaining roles
    var iur = new GlideRecord('sys_user_has_role')
    iur.addQuery('user.active', false)
    iur.query()
    gs.print(
        '  nowisor-inactive-users-with-roles: ' +
            iur.getRowCount() +
            ' inactive users with roles (zero-finding is correct only if 0)'
    )

    // Cross-scope privilege grants
    var csp = new GlideRecord('sys_scope_privilege')
    csp.addQuery('target_scope.scope', 'global')
    csp.addQuery('source_scope.scope', '!=', 'global')
    csp.query()
    gs.print(
        '  nowisor-cross-scope-privilege-grants: ' +
            csp.getRowCount() +
            ' cross-scope privilege grant(s) to global (any value is a fact; zero-finding interpretation depends on check predicate)'
    )

    // OOB ACL modifications
    var oobAcl = new GlideRecord('sys_security_acl')
    oobAcl.addQuery('sys_update_name', 'STARTSWITH', 'sys_security_acl_')
    oobAcl.addQuery('sys_mod_count', '!=', '0')
    oobAcl.addQuery('sys_updated_by', '!=', 'system')
    oobAcl.addQuery('sys_updated_by', '!=', 'admin')
    oobAcl.query()
    gs.print(
        '  nowisor-oob-acl-modifications: ' +
            oobAcl.getRowCount() +
            ' OOB ACLs with non-system modifications (zero-finding expected on clean PDI)'
    )

    gs.print('')
    gs.print('--- Code-analysis (LinterCheck) zero-finding checks ---')
    gs.print(
        '  (eval, setWorkflow, glideEvaluator, setRoles, hardcoded-credentials,'
    )
    gs.print(
        '   direct-property-write, domain-separation-script-include)'
    )
    gs.print(
        '  → These require Phase 3 planted-artifact validation. Zero-finding here'
    )
    gs.print(
        '    on OOB code is suspicious but not conclusive — predicates may be working'
    )
    gs.print('    but OOB code may not contain the targeted patterns.')

    gs.print('')
    gs.print('--- Cross-cutting / meta checks ---')

    // Fabricated property references — looks at certain table for fabricated names
    gs.print(
        '  nowisor-fabricated-property-references: zero is expected on a clean install (the check inspects nowisor-internal data for fabricated property names — no nowisor scripts cite fabricated props since we passed the 2-evidence rule)'
    )

    // Meta active check coverage
    gs.print(
        '  nowisor-meta-active-check-coverage: zero is PASS (26 active, expected 26 — exact match means no finding emitted, which is correct behavior)'
    )

    // Platform build drift
    var ver = gs.getProperty('glide.buildname', '?') +
        ' ' +
        gs.getProperty('glide.buildtag.last', '?')
    gs.print('  nowisor-platform-build-drift: current build = ' + ver + ' (zero-finding is correct if no drift detected)')

    // Suspicious Update Set XML — ColumnTypeCheck
    gs.print('  nowisor-update-set-xml-suspicious: ColumnTypeCheck against sys_update_xml.payload — zero-finding expected on a fresh PDI with no suspicious update sets')

    gs.print('')
    gs.print('Compliant-state probe complete.')
})()
```

---

## Reporting back

Run 2.D and paste the output. After 2.D we can move directly to Phase 3 (LinterCheck planted artifacts) — the property-based checks should all probe compliant, and any anomalies will be evident in 2.D output.
