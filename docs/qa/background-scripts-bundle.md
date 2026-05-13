# nowisor v1.0.0 — Background Scripts QA bundle
Use this artifact to systematically test every verification Background Script on dev265484.
**Method:** for each script, paste into Background Scripts on dev265484, run, confirm output structure matches expectation. Tick off as you go.
**Safety:** every script is read-only — no insert/update/delete operations. Confirm by visual inspection before running.

---

## - [ ] `nowisor-admin-role-concentration`

```javascript
/*
 * Verify nowisor-admin-role-concentration progress
 * Read-only, safe for production.
 * Reports the current admin/active-user ratio.
 */
(function adminRatio() {
    var totalActive = new GlideAggregate('sys_user');
    totalActive.addQuery('active', true);
    totalActive.addAggregate('COUNT');
    totalActive.query();
    var total = totalActive.next() ? parseInt(totalActive.getAggregate('COUNT'), 10) : 0;

    var adminHolders = {};
    var roleGr = new GlideRecord('sys_user_has_role');
    roleGr.addQuery('role.name', 'admin');
    roleGr.addQuery('user.active', true);
    roleGr.query();
    while (roleGr.next()) adminHolders[roleGr.getValue('user')] = true;
    var adminCount = 0;
    for (var k in adminHolders) if (adminHolders.hasOwnProperty(k)) adminCount++;

    var ratio = total > 0 ? (adminCount / total) : 0;
    gs.print('Total active users: ' + total);
    gs.print('Distinct admin role holders: ' + adminCount);
    gs.print('Ratio: ' + (ratio * 100).toFixed(2) + '%  (threshold: 5.00%)');
    gs.print((ratio <= 0.05) ? '[PASS] Below threshold.' : '[FAIL] Above threshold.');
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-attachment-role-restriction`

```javascript
/*
 * Verify nowisor-attachment-role-restriction
 * Read-only, safe for production.
 * Confirms glide.attachment.role is set to a non-public role.
 */
(function verifyAttachmentRole() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.attachment.role';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED.');
        gs.print('       Set to a non-public role.');
    } else if (value === '' || value.toLowerCase() === 'public') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (unrestricted).');
        gs.print('       Set to a non-public role (e.g., attachment_writer).');
    } else {
        gs.print('[PASS] ' + prop + ' = "' + value + '". Attachment access restricted.');
    }

    // Companion: file-type controls (informational)
    gs.print('');
    gs.print('Companion attachment controls:');
    gs.print('  glide.attachment.extensions = ' + gs.getProperty('glide.attachment.extensions', SENTINEL));
    gs.print('  glide.security.file.mime_type.validation = ' + gs.getProperty('glide.security.file.mime_type.validation', SENTINEL));
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-cookie-http-only`

```javascript
/*
 * Verify nowisor-cookie-http-only
 * Read-only, safe for production.
 * Confirms glide.cookies.http_only is enforced.
 */
(function verifyHttpOnly() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.cookies.http_only';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED in sys_properties.');
        gs.print('       Recreate the property with value "true".');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
        gs.print('       Update via System Properties.');
    } else {
        gs.print('[PASS] ' + prop + ' = true. HttpOnly flag enforced.');
    }

    // Companion: full cookie hardening cluster
    gs.print('');
    gs.print('Cookie cluster (informational):');
    gs.print('  glide.cookies.secure = ' + gs.getProperty('glide.cookies.secure', SENTINEL));
    gs.print('  glide.cookies.samesite = ' + gs.getProperty('glide.cookies.samesite', SENTINEL));
    gs.print('  glide.ui.secure_cookies = ' + gs.getProperty('glide.ui.secure_cookies', SENTINEL));
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-cookie-secure`

```javascript
/*
 * Verify nowisor-cookie-secure
 * Read-only, safe for production.
 * Confirms glide.cookies.secure is enforced + reports the transport-layer cluster.
 */
(function verifyCookieSecure() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.cookies.secure';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED in sys_properties.');
        gs.print('       Recreate the property with value "true".');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
        gs.print('       Update via System Properties.');
    } else {
        gs.print('[PASS] ' + prop + ' = true. Secure flag enforced on session cookies.');
    }

    // Transport-layer cluster
    gs.print('');
    gs.print('Transport-layer cluster (informational):');
    gs.print('  glide.cookies.http_only = ' + gs.getProperty('glide.cookies.http_only', SENTINEL));
    gs.print('  glide.cookies.samesite = ' + gs.getProperty('glide.cookies.samesite', SENTINEL));
    gs.print('  glide.ui.secure_cookies = ' + gs.getProperty('glide.ui.secure_cookies', SENTINEL));
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-cross-scope-privilege-grants`

```javascript
/*
 * Verify nowisor-cross-scope-privilege-grants progress
 * Read-only, safe for production.
 * Counts high-impact cross-scope grants by source scope.
 */
(function auditGrants() {
    var bySource = {};
    var gr = new GlideRecord('sys_scope_privilege');
    gr.addQuery('source_scope', '!=', 'global');
    gr.addQuery('target_scope', 'global');
    gr.addQuery('operation', 'IN', 'write,create,delete');
    gr.addQuery('status', 'allowed');
    gr.query();
    while (gr.next()) {
        var src = gr.getDisplayValue('source_scope') || gr.getValue('source_scope');
        bySource[src] = (bySource[src] || 0) + 1;
    }
    var names = Object.keys(bySource).sort();
    gs.print('=== High-impact cross-scope grants by source ===');
    gs.print('Total source scopes: ' + names.length);
    gs.print('');
    var total = 0;
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + bySource[names[i]] + ' grant(s)');
        total += bySource[names[i]];
    }
    gs.print('');
    gs.print('Total high-impact grants: ' + total);
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-csrf-token-enforcement`

```javascript
/*
 * Verify nowisor-csrf-token-enforcement
 * Read-only, safe for production.
 * Confirms glide.security.use_csrf_token is enforced.
 */
(function verifyCsrf() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.security.use_csrf_token';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED in sys_properties.');
        gs.print('       Recreate the property with value "true".');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
        gs.print('       Update via System Properties.');
    } else {
        gs.print('[PASS] ' + prop + ' = true. CSRF token enforcement active.');
    }

    // Companion check — strict validation mode
    var strict = gs.getProperty('glide.security.csrf.strict.validation.mode', SENTINEL);
    gs.print('');
    gs.print('Companion property glide.security.csrf.strict.validation.mode = ' + strict);
    gs.print('Recommended: true (default on Zurich Patch 6)');
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-domain-separation-script-include`

```javascript
/*
 * Verify nowisor-domain-separation-script-include remediation progress
 * Read-only, safe for production.
 * Lists Script Includes flagged for missing sys_overrides reference.
 */
(function pullDomainSeparationFindings() {
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'Cross-Domain Script Include Reference');
    f.query();

    gs.print('=== Domain-separation findings ===');
    gs.print('Total Script Includes flagged: ' + f.getRowCount());
    gs.print('');
    while (f.next()) {
        gs.print('  ' + f.getDisplayValue('source'));
    }

    // Instance DS context (informational)
    gs.print('');
    if (!GlideTableDescriptor.isValid('domain')) {
        gs.print('Instance domain count: 0 (domain table absent, DS plugin not active)');
        gs.print('Findings are ADVISORY (DS not in active use)');
    } else {
        var domains = new GlideRecord('domain');
        domains.addQuery('active', true);
        domains.query();
        gs.print('Instance domain count: ' + domains.getRowCount());
        if (domains.getRowCount() <= 1) {
            gs.print('Findings are ADVISORY (DS not in active use)');
        } else {
            gs.print('Findings are ACTIONABLE (DS in active use)');
        }
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-elevated-role-assignments`

```javascript
/*
 * Verify nowisor-elevated-role-assignments progress
 * Read-only, safe for production.
 * Counts users co-assigned admin and itil_admin.
 */
(function checkCoAssignment() {
    var adminUsers = {};
    var aGr = new GlideRecord('sys_user_has_role');
    aGr.addQuery('role.name', 'admin');
    aGr.addQuery('user.active', true);
    aGr.query();
    while (aGr.next()) adminUsers[aGr.getValue('user')] = true;

    var count = 0;
    var iGr = new GlideRecord('sys_user_has_role');
    iGr.addQuery('role.name', 'itil_admin');
    iGr.addQuery('user.active', true);
    iGr.query();
    while (iGr.next()) {
        if (adminUsers[iGr.getValue('user')]) count++;
    }
    gs.print('Co-assigned (admin + itil_admin): ' + count);
    if (count === 0) {
        gs.print('[PASS] Separation of duties maintained.');
    } else {
        gs.print('[REVIEW] ' + count + ' user(s) hold both roles.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-eval-usage-detector`

```javascript
/*
 * Verify nowisor-eval-usage-detector remediation progress
 * Read-only, safe for production.
 * Lists current open findings grouped by source script.
 */
(function pullEvalFindings() {
    var byScript = {};
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'eval() Usage Detector');
    f.query();

    while (f.next()) {
        var sourceName = f.getDisplayValue('source') || '(unknown)';
        if (!byScript[sourceName]) byScript[sourceName] = 0;
        byScript[sourceName]++;
    }

    var names = Object.keys(byScript).sort();
    gs.print('=== eval() findings by source ===');
    gs.print('Total scripts with findings: ' + names.length);
    gs.print('');
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + byScript[names[i]] + ' call(s)');
    }
    if (names.length === 0) {
        gs.print('Clean: no eval() calls detected in current scan.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-external-auth-policy`

```javascript
/*
 * Verify nowisor-external-auth-policy
 * Read-only, safe for production.
 * Confirms SSO is active AND local login is disabled.
 */
(function verifyExternalAuth() {
    var SENTINEL = '__NOT_REGISTERED__';

    // 1. Confirm SSO is active (precondition for the property's relevance)
    var ssoActive = false;
    try {
        var ssoGr = new GlideRecord('sso_properties');
        ssoGr.addQuery('active', true);
        ssoGr.query();
        if (ssoGr.getRowCount() > 0) ssoActive = true;
    } catch (e) {}
    var ssoProp = gs.getProperty('glide.authenticate.sso.enabled', SENTINEL);
    gs.print('SSO detection:');
    gs.print('  sso_properties active rows: ' + (ssoActive ? 'yes' : 'no'));
    gs.print('  glide.authenticate.sso.enabled = ' + ssoProp);
    if (!ssoActive && ssoProp !== 'true') {
        gs.print('[INFO] SSO is not active. This check is informational-only here.');
        return;
    }

    // 2. Audit disable_local_login
    var prop = 'glide.authentication.external.disable_local_login';
    var value = gs.getProperty(prop, SENTINEL);

    gs.print('');
    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED. Local login still permitted.');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
    } else {
        gs.print('[PASS] ' + prop + ' = true. Local login disabled.');
    }

    // 3. Break-glass account count (informational)
    gs.print('');
    var localPasswordHolders = new GlideAggregate('sys_user');
    localPasswordHolders.addQuery('active', true);
    localPasswordHolders.addQuery('user_password', '!=', '');
    localPasswordHolders.addAggregate('COUNT');
    localPasswordHolders.query();
    if (localPasswordHolders.next()) {
        gs.print(
            'Active users with non-empty user_password: ' +
                localPasswordHolders.getAggregate('COUNT') +
                ' (target: 1 break-glass admin)'
        );
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-fabricated-property-references`

```javascript
/*
 * Verify nowisor-fabricated-property-references
 * Read-only, safe for production.
 * Sample-checks a specific property name's registration.
 */
(function checkProperty(propName) {
    var SENTINEL = '__NOT_REGISTERED__';
    var value = gs.getProperty(propName, SENTINEL);
    if (value === SENTINEL) {
        gs.print('[FAIL] ' + propName + ' is NOT REGISTERED in sys_properties.');
    } else {
        gs.print('[PASS] ' + propName + ' = "' + value + '"');
    }
})('your.property.name');  // <-- replace with the property to check
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-glide-evaluator-detector`

```javascript
/*
 * Verify nowisor-glide-evaluator-detector remediation progress
 * Read-only, safe for production.
 * Lists open findings grouped by source script.
 */
(function pullGlideEvaluatorFindings() {
    var byScript = {};
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'GlideEvaluator Dynamic Evaluation Detector');
    f.query();

    while (f.next()) {
        var sourceName = f.getDisplayValue('source') || '(unknown)';
        if (!byScript[sourceName]) byScript[sourceName] = 0;
        byScript[sourceName]++;
    }

    var names = Object.keys(byScript).sort();
    gs.print('=== GlideEvaluator findings by source ===');
    gs.print('Total scripts with findings: ' + names.length);
    gs.print('');
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + byScript[names[i]] + ' reference(s)');
    }
    if (names.length === 0) {
        gs.print('Clean: no GlideEvaluator references detected in current scan.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-glide-record-vs-secure`

```javascript
/*
 * Verify nowisor-glide-record-vs-secure remediation progress
 * Read-only, safe for production.
 * Lists open findings grouped by source script.
 */
(function pullFindings() {
    var byScript = {};
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'GlideRecord vs GlideRecordSecure');
    f.query();

    while (f.next()) {
        var sourceName = f.getDisplayValue('source') || '(unknown)';
        if (!byScript[sourceName]) byScript[sourceName] = 0;
        byScript[sourceName]++;
    }

    var names = Object.keys(byScript).sort();
    gs.print('=== GlideRecord findings by source ===');
    gs.print('Total scripts with findings: ' + names.length);
    gs.print('');
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + byScript[names[i]] + ' call(s)');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-inactive-users-with-roles`

```javascript
/*
 * Verify nowisor-inactive-users-with-roles remediation progress
 * Read-only, safe for production.
 * Counts inactive users still holding role grants.
 */
(function inactiveRoleHolders() {
    var distinctUsers = {};
    var gr = new GlideRecord('sys_user_has_role');
    gr.addQuery('user.active', false);
    gr.query();
    while (gr.next()) distinctUsers[gr.getValue('user')] = true;

    var count = 0;
    for (var k in distinctUsers) if (distinctUsers.hasOwnProperty(k)) count++;
    gs.print('Distinct inactive users with active role grants: ' + count);
    if (count === 0) {
        gs.print('[PASS] No stale role grants.');
    } else {
        gs.print('[REVIEW] ' + count + ' user(s) need deprovisioning.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-meta-active-check-coverage`

```javascript
/*
 * Verify nowisor-meta-active-check-coverage
 * Read-only, safe for production.
 * Counts active nowisor checks across all four scan check tables.
 */
(function verifyMetaCoverage() {
    var tables = [
        'scan_script_only_check',
        'scan_table_check',
        'scan_linter_check',
        'scan_column_type_check'
    ];
    var EXPECTED_ACTIVE = 24;  // 26 total minus 2 deferred in v1.0.0
    var total = 0;
    for (var i = 0; i < tables.length; i++) {
        var gr = new GlideRecord(tables[i]);
        gr.addQuery('sys_scope.scope', 'x_nowisor_isp');
        gr.addQuery('active', true);
        gr.query();
        var n = gr.getRowCount();
        total += n;
        gs.print('  ' + tables[i] + ': ' + n);
    }
    gs.print('');
    gs.print('Total active: ' + total + ' (expected: ' + EXPECTED_ACTIVE + ')');
    if (total >= EXPECTED_ACTIVE) {
        gs.print('[PASS] Coverage complete.');
    } else {
        gs.print('[FAIL] ' + (EXPECTED_ACTIVE - total) + ' check(s) inactive or missing.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-mfa-enforcement`

```javascript
/*
 * Verify nowisor-mfa-enforcement
 * Read-only, safe for production.
 * Confirms glide.authenticate.multifactor is enforced + reports enrollment.
 */
(function verifyMfa() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.authenticate.multifactor';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED in sys_properties.');
        gs.print('       Configure MFA provider, then set the property to "true".');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
        gs.print('       Update via System Properties.');
    } else {
        gs.print('[PASS] ' + prop + ' = true. MFA enforced at login.');
    }

    // Enrollment snapshot (informational)
    gs.print('');
    gs.print('MFA enrollment snapshot:');
    try {
        var mfaSetup = new GlideRecord('sys_user_mfa_setup');
        mfaSetup.query();
        gs.print('  sys_user_mfa_setup rows: ' + mfaSetup.getRowCount() + ' enrolled users');
    } catch (e) {
        gs.print('  (sys_user_mfa_setup table not accessible in this scope)');
    }

    // Companion: admin role count, for context on enrollment priority
    try {
        var admins = new GlideAggregate('sys_user_has_role');
        admins.addQuery('role.name', 'admin');
        admins.addAggregate('COUNT', 'user');
        admins.query();
        var adminCount = 0;
        while (admins.next()) adminCount++;
        gs.print('  Distinct admin role holders: ' + adminCount);
    } catch (e) {}
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-oob-acl-modifications`

```javascript
/*
 * Verify nowisor-oob-acl-modifications
 * Read-only, safe for production.
 * Lists baseline ACLs modified in the last 24 hours.
 */
(function auditOobAcls() {
    var gr = new GlideRecord('sys_security_acl');
    gr.addQuery('sys_package', '');
    gr.addQuery('sys_updated_on', '>', 'javascript:gs.beginningOfYesterday()');
    gr.orderByDesc('sys_updated_on');
    gr.query();

    var count = 0;
    while (gr.next()) {
        var createdGdt = new GlideDateTime(gr.getValue('sys_created_on'));
        var updatedGdt = new GlideDateTime(gr.getValue('sys_updated_on'));
        var deltaMs = updatedGdt.getNumericValue() - createdGdt.getNumericValue();
        if (deltaMs <= 86400000) continue;  // < 1 day, skip
        count++;
        gs.print(
            '  ' +
            (gr.getValue('name') || gr.getValue('sys_id')) +
            ' (' + gr.getValue('operation') + ', updated by ' +
            gr.getValue('sys_updated_by') + ')'
        );
    }
    if (count === 0) {
        gs.print('[PASS] No OOB ACL modifications in the last day.');
    } else {
        gs.print('[FAIL] ' + count + ' OOB ACL(s) modified recently. Review each.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-platform-build-drift`

```javascript
/*
 * Verify nowisor-platform-build-drift
 * Read-only, safe for production.
 * Reports the current build tag and supported patterns.
 */
(function checkBuildDrift() {
    var SENTINEL = '__NOT_REGISTERED__';
    var buildTag = gs.getProperty('glide.buildtag.last', SENTINEL);
    gs.print('Current build tag: ' + buildTag);

    var patterns = [
        { name: 'Zurich Patch 6', re: /zurich.*patch6/i },
        { name: 'Australia GA', re: /^glide-australia/i },
        { name: 'Australia Patch N', re: /australia.*patch[0-9]+/i }
    ];

    var matched = false;
    for (var i = 0; i < patterns.length; i++) {
        if (patterns[i].re.test(buildTag)) {
            gs.print('[PASS] Matches: ' + patterns[i].name);
            matched = true;
            break;
        }
    }
    if (!matched) {
        gs.print('[FAIL] Unverified build. nowisor findings on this instance should be reviewed manually.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-rest-anonymous-access`

```javascript
/*
 * Verify nowisor-rest-anonymous-access
 * Read-only, safe for production.
 * Confirms every glide.basicauth.required.* property is set to "true".
 */
(function verifyBasicAuthFamily() {
    var SENTINEL = '__NOT_REGISTERED__';
    var family = [
        'glide.basicauth.required.api',
        'glide.basicauth.required.scriptedprocessor',
        'glide.basicauth.required.soap',
        'glide.basicauth.required.wsdl',
        'glide.basicauth.required.xsd',
        'glide.basicauth.required.databrokerrestapiprocessor',
        'glide.basicauth.required.unl'
    ];

    var fails = 0;
    for (var i = 0; i < family.length; i++) {
        var value = gs.getProperty(family[i], SENTINEL);
        if (value === SENTINEL) {
            gs.print('[FAIL] ' + family[i] + ' is NOT REGISTERED.');
            fails++;
        } else if (value !== 'true') {
            gs.print('[FAIL] ' + family[i] + ' = "' + value + '" (expected "true").');
            fails++;
        } else {
            gs.print('[PASS] ' + family[i] + ' = true.');
        }
    }
    gs.print('');
    if (fails === 0) {
        gs.print('All 7 properties enforced. Anonymous access blocked across the family.');
    } else {
        gs.print(fails + ' propert(y/ies) still allow anonymous access. Update via System Properties.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-secure-cookies`

```javascript
/*
 * Verify nowisor-secure-cookies
 * Read-only, safe for production.
 * Confirms glide.ui.secure_cookies is enforced + reports the full cluster.
 */
(function verifySecureCookies() {
    var SENTINEL = '__NOT_REGISTERED__';
    var prop = 'glide.ui.secure_cookies';
    var value = gs.getProperty(prop, SENTINEL);

    if (value === SENTINEL) {
        gs.print('[FAIL] ' + prop + ' is NOT REGISTERED in sys_properties.');
        gs.print('       Recreate the property with value "true".');
    } else if (value !== 'true') {
        gs.print('[FAIL] ' + prop + ' = "' + value + '" (expected "true").');
        gs.print('       Update via System Properties.');
    } else {
        gs.print('[PASS] ' + prop + ' = true. UI-layer secure-cookie enforcement active.');
    }

    // Cluster symmetry check
    gs.print('');
    gs.print('Cookie cluster symmetry:');
    var cluster = [
        'glide.ui.secure_cookies',
        'glide.cookies.secure',
        'glide.cookies.http_only',
        'glide.cookies.samesite'
    ];
    for (var i = 0; i < cluster.length; i++) {
        gs.print('  ' + cluster[i] + ' = ' + gs.getProperty(cluster[i], SENTINEL));
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-session-timeout`

```javascript
// Verify nowisor-session-timeout. Read-only, safe for production.
// Confirms glide.ui.session_timeout is within the recommended baseline of 30 minutes.
(function verifySessionTimeout() {
    var prop = 'glide.ui.session_timeout';
    var value = gs.getProperty(prop, 'NOT_SET');
    var n = parseInt(value, 10);
    gs.print('Property ' + prop + ' = ' + value);
    if (value === 'NOT_SET') {
        gs.print('[FAIL] Property is not registered. Set to 30.');
    } else if (isNaN(n)) {
        gs.print('[FAIL] Value is not numeric. Set to 30.');
    } else if (n > 30) {
        gs.print('[FAIL] Value of ' + n + ' exceeds baseline of 30 minutes.');
    } else {
        gs.print('[PASS] Value of ' + n + ' minutes is within baseline.');
    }
    gs.print('Companion: glide.guest.session_timeout = ' + gs.getProperty('glide.guest.session_timeout', 'NOT_SET'));
    gs.print('Companion: glide.unauthorized.session_timeout = ' + gs.getProperty('glide.unauthorized.session_timeout', 'NOT_SET'));
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-set-roles-detector`

```javascript
/*
 * Verify nowisor-set-roles-detector remediation progress
 * Read-only, safe for production.
 * Lists open findings grouped by source script.
 */
(function pullSetRolesFindings() {
    var byScript = {};
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'setRoles() Escalation Detector');
    f.query();

    while (f.next()) {
        var sourceName = f.getDisplayValue('source') || '(unknown)';
        if (!byScript[sourceName]) byScript[sourceName] = 0;
        byScript[sourceName]++;
    }

    var names = Object.keys(byScript).sort();
    gs.print('=== setRoles() findings by source ===');
    gs.print('Total scripts with findings: ' + names.length);
    gs.print('');
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + byScript[names[i]] + ' call(s)');
    }
    if (names.length === 0) {
        gs.print('Clean: no setRoles() calls detected in current scan.');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-set-workflow-false-detector`

```javascript
/*
 * Verify nowisor-set-workflow-false-detector remediation progress
 * Read-only, safe for production.
 * Lists open findings grouped by source script.
 */
(function pullSetWorkflowFindings() {
    var byScript = {};
    var f = new GlideRecord('scan_finding');
    f.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
    f.addQuery('check.name', 'setWorkflow(false) Detector');
    f.query();

    while (f.next()) {
        var sourceName = f.getDisplayValue('source') || '(unknown)';
        if (!byScript[sourceName]) byScript[sourceName] = 0;
        byScript[sourceName]++;
    }

    var names = Object.keys(byScript).sort();
    gs.print('=== setWorkflow findings by source ===');
    gs.print('Total scripts with findings: ' + names.length);
    gs.print('');
    for (var i = 0; i < names.length; i++) {
        gs.print('  ' + names[i] + ': ' + byScript[names[i]] + ' call(s)');
    }
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## - [ ] `nowisor-update-set-xml-suspicious`

```javascript
/*
 * Verify nowisor-update-set-xml-suspicious
 * Read-only, safe for production.
 * Counts sys_update_xml records matching the three patterns.
 */
(function auditUpdateXml() {
    var patterns = [
        { name: 'admin role grant', re: /<sys_user_has_role>[\s\S]*?admin[\s\S]*?<\/sys_user_has_role>/i },
        { name: 'ACL modification', re: /<sys_security_acl>/i },
        { name: 'cross-scope grant', re: /<sys_scope_privilege>/i }
    ];
    var counts = { 'admin role grant': 0, 'ACL modification': 0, 'cross-scope grant': 0 };

    var gr = new GlideRecord('sys_update_xml');
    gr.setLimit(1000);  // sample for verification; full check covers all records
    gr.query();
    while (gr.next()) {
        var payload = gr.getValue('payload') || '';
        for (var i = 0; i < patterns.length; i++) {
            if (patterns[i].re.test(payload)) counts[patterns[i].name]++;
        }
    }
    gs.print('Sample of 1,000 sys_update_xml records:');
    for (var k in counts) gs.print('  ' + k + ': ' + counts[k]);
})();
```

**Expected:** see the page's verification section for pass criteria.

---

## Pages without verification scripts

- `nowisor-direct-property-write` — no script extracted (likely a stub page or manual-only verification)
- `nowisor-hardcoded-credentials` — no script extracted (likely a stub page or manual-only verification)

