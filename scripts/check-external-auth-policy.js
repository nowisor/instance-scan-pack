// nowisor v1.2.1 — External auth policy / disable-local-login check
// Verifies glide.authentication.external.disable_local_login = 'true' WHEN SSO is active.
// If SSO is not active, no finding is emitted (informational-only when there is no SSO to coexist with local login).
//
// SSO detection (read-only, conservative): sso_properties has at least one active
// record. That table is created by the Multi-Provider SSO plugin
// (com.snc.integration.sso.multi.installer) and an active row IS a configured
// IdP — the canonical OOB indicator on Zurich P6 and Australia P3. Where the
// plugin is inactive the table does not exist, the query throws, and the check
// exits as no-SSO (measured on dev371429, 2026-09-10).
//
// Evidence, not a signal: glide.authenticate.multissov2_feature.enabled is read
// sentinel-guarded and reported in every finding. It says whether the plugin is
// at MultiSSO v2 (set true by the v2 upgrade; ServiceNow docs
// platform-security/instance-security-hardening-settings/
// sc-updated-version-of-multi-sso-plugin-is-enabled.md @ e8cdeed0). It does NOT
// say an IdP is configured — the plugin can be enabled with no IdP — so it must
// never stand in for the sso_properties signal: a finding raised on it alone
// would tell a customer with no IdP to disable local login, which is a lockout.
// Property evidence: verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// (REAL_ACTIVE=true, plugin active on dev265484); absent on dev371429 with the
// plugin inactive, which is what the sentinel reports as NOT_REGISTERED.
//
// v1.0.1 (2026-09-10): removed the "secondary signal" read of a per-SSO enable
// property adjudicated FABRICATED on 2026-04-28 (vsme-app/lib/quality/
// fabricated-props-resolution-log.md; no such property exists), so the guarded
// read could never fire and was dead code that read like a signal.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function externalAuthPolicy(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.authentication.external.disable_local_login'
    var MULTISSO_V2_PROP = 'glide.authenticate.multissov2_feature.enabled'

    // --- SSO detection ---
    var ssoActive = false
    var ssoSignal = 'none'

    // Active record in sso_properties (the only signal — see header)
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
        // sso_properties does not exist when the Multi-Provider SSO plugin is
        // inactive: no plugin, no IdP, nothing for local login to bypass.
    }

    if (!ssoActive) return

    // Evidence only (three states: NOT_REGISTERED / true / false). Never a
    // reason to emit or suppress a finding — see header.
    var multiSsoV2 = gs.getProperty(MULTISSO_V2_PROP, SENTINEL)

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
        nowisor_check_version: '1.0.1',
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
            multisso_v2_feature_enabled: multiSsoV2 === SENTINEL ? 'NOT_REGISTERED' : multiSsoV2,
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
