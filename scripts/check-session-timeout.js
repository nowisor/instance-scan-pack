// nowisor v1.0.0 — Session idle timeout check
// Verifies glide.ui.session_timeout <= 30 (minutes)
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function sessionTimeout(finding) {
    var SENTINEL = '__NOT_SET__'
    var THRESHOLD = 30
    var PROP = 'glide.ui.session_timeout'
    var value = gs.getProperty(PROP, SENTINEL)

    var notSetCase = value === SENTINEL
    var parsed = notSetCase ? -1 : parseInt(value, 10)
    var nonNumericCase = !notSetCase && isNaN(parsed)
    var exceededCase = !notSetCase && !nonNumericCase && parsed > THRESHOLD

    if (!notSetCase && !nonNumericCase && !exceededCase) return

    var description
    if (notSetCase) {
        description =
            'Session idle timeout property is not registered in sys_properties on this instance, so the active session timeout is unverifiable against the 30-minute baseline.'
    } else if (nonNumericCase) {
        description =
            'Session idle timeout property is set to a non-numeric value and cannot be evaluated against the 30-minute baseline.'
    } else {
        description =
            'Session idle timeout exceeds the 30-minute baseline. Idle authenticated sessions remain valid longer than recommended, widening the window for session hijack and replay.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-session-timeout',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.8.5'],
            dora: ['9'],
        },
        evidence: {
            property_name: PROP,
            expected_value: '<=30',
            actual_value: notSetCase ? 'NOT_REGISTERED' : value,
        },
        severity: 2,
        remediation_id: 'session-001',
        attack_path_refs: [],
    }

    var details =
        description +
        '\n\nCurrent value: ' +
        (notSetCase ? 'NOT REGISTERED' : value) +
        '. Expected: <=30 (minutes).' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
