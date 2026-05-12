// nowisor v1.0.0 — Secure cookies UI property check
// Verifies glide.ui.secure_cookies = 'true'
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function secureCookies(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.ui.secure_cookies'
    var value = gs.getProperty(PROP, SENTINEL)

    var notSetCase = value === SENTINEL
    var disabledCase = !notSetCase && value !== 'true'

    if (!notSetCase && !disabledCase) return

    var description
    if (notSetCase) {
        description =
            'UI-layer secure-cookies property is not registered in sys_properties on this instance, so the UI cookie-security contract is unverifiable.'
    } else {
        description =
            'UI-layer secure-cookies enforcement is disabled, creating an asymmetry with glide.cookies.secure that some session paths may exploit to ship cookies over insecure channels.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-secure-cookies',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.e'],
            iso27001: ['A.8.23'],
        },
        evidence: {
            property_name: PROP,
            expected_value: 'true',
            actual_value: notSetCase ? 'NOT_REGISTERED' : value,
        },
        severity: 1,
        remediation_id: 'cookie-003',
        attack_path_refs: [],
    }

    var details =
        description +
        '\n\nCurrent value: ' +
        (notSetCase ? 'NOT REGISTERED' : value) +
        '. Expected: true.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
