// nowisor v1.0.0 — External auth policy / disable-local-login check
// Verifies glide.authentication.external.disable_local_login = 'true' WHEN SSO is active.
// If SSO is not active, no finding is emitted (informational-only when there is no SSO to coexist with local login).
//
// SSO-detection heuristic (read-only, conservative):
//   (1) Primary signal — sso_properties has at least one active record. This is the
//       canonical OOB indicator of a configured SSO provider on Zurich Patch 6.
//   (2) Secondary signal — glide.authenticate.sso.enabled (sentinel-guarded; this
//       property is NOT in the verified Zurich Patch 6 baseline, so we treat any
//       non-sentinel 'true' value as a soft positive but do not require it).
//   If neither signal is present, the instance is treated as no-SSO and the check exits.
//
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function externalAuthPolicy(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.authentication.external.disable_local_login'
    var SSO_PROP = 'glide.authenticate.sso.enabled'

    // --- SSO-detection heuristic ---
    var ssoActive = false
    var ssoSignal = 'none'

    // Primary: active record in sso_properties
    try {
        var ssoGr = new GlideAggregate('sso_properties')
        ssoGr.addQuery('active', true)
        ssoGr.addAggregate('COUNT')
        ssoGr.query()
        if (ssoGr.next()) {
            var ssoCount = parseInt(ssoGr.getAggregate('COUNT'), 10)
            if (ssoCount > 0) {
                ssoActive = true
                ssoSignal = 'sso_properties.active>0'
            }
        }
    } catch (e) {
        // sso_properties may not exist on every variant; fall through to secondary signal
    }

    // Secondary: sentinel-guarded check on glide.authenticate.sso.enabled
    if (!ssoActive) {
        var ssoPropValue = gs.getProperty(SSO_PROP, SENTINEL)
        if (ssoPropValue !== SENTINEL && ssoPropValue === 'true') {
            ssoActive = true
            ssoSignal = 'glide.authenticate.sso.enabled=true'
        }
    }

    if (!ssoActive) return

    // SSO is active — evaluate disable_local_login
    var value = gs.getProperty(PROP, SENTINEL)
    var notSetCase = value === SENTINEL
    var disabledCase = !notSetCase && value !== 'true'

    if (!notSetCase && !disabledCase) return

    var description
    if (notSetCase) {
        description =
            'SSO is active on this instance but the disable-local-login property is not registered, so local-credential login likely still coexists with the configured IdP as a bypass path around its MFA, conditional access, and audit trail.'
    } else {
        description =
            'SSO is active on this instance but local login is not disabled. An attacker who phishes or guesses a local password bypasses the configured IdP entirely, sidestepping its MFA, conditional access, and audit trail.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-external-auth-policy',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.16'],
        },
        evidence: {
            property_name: PROP,
            expected_value: 'true',
            actual_value: notSetCase ? 'NOT_REGISTERED' : value,
            sso_detection_signal: ssoSignal,
        },
        severity: 2,
        remediation_id: 'auth-001',
        attack_path_refs: [],
    }

    var details =
        description +
        '\n\nCurrent value: ' +
        (notSetCase ? 'NOT REGISTERED' : value) +
        '. Expected: true. SSO detection: ' +
        ssoSignal +
        '.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
