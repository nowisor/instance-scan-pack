// nowisor v1.0.0 — MFA enforcement check
// Verifies glide.authenticate.multifactor = 'true'
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function mfaEnforcement(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.authenticate.multifactor'
    var value = gs.getProperty(PROP, SENTINEL)

    var notSetCase = value === SENTINEL
    var disabledCase = !notSetCase && value !== 'true'

    if (!notSetCase && !disabledCase) return

    var description
    if (notSetCase) {
        description =
            'Multi-factor authentication property is not registered in sys_properties on this instance, so MFA enforcement state is unverifiable.'
    } else {
        description =
            'Multi-factor authentication is not enforced. Single-factor credentials are sufficient to authenticate to the instance, removing the most effective control against credential-stuffing, phishing, and password-reuse compromise.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-mfa-enforcement',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.17'],
            dora: ['9'],
        },
        evidence: {
            property_name: PROP,
            expected_value: 'true',
            actual_value: notSetCase ? 'NOT_REGISTERED' : value,
        },
        severity: 1,
        remediation_id: 'mfa-001',
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
