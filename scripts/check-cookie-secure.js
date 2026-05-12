// nowisor v1.0.0 — Cookie Secure flag enforcement check
// Verifies glide.cookies.secure = 'true'
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function cookieSecure(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.cookies.secure'
    var value = gs.getProperty(PROP, SENTINEL)

    var notSetCase = value === SENTINEL
    var disabledCase = !notSetCase && value !== 'true'

    if (!notSetCase && !disabledCase) return

    var description
    if (notSetCase) {
        description =
            'Cookie Secure-flag enforcement property is not registered in sys_properties on this instance, so transport-layer protection on session cookies is unverifiable.'
    } else {
        description =
            'Cookie Secure flag enforcement is disabled. Session cookies may be transmitted over plain HTTP, allowing a network attacker on the same path to intercept and replay the authenticated session identifier.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-cookie-secure',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.e'],
            iso27001: ['A.8.23'],
            dora: ['9'],
        },
        evidence: {
            property_name: PROP,
            expected_value: 'true',
            actual_value: notSetCase ? 'NOT_REGISTERED' : value,
        },
        severity: 1,
        remediation_id: 'cookie-002',
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
