// nowisor v1.1.0 - Basic Auth restriction tracking active check (BASICAUTH-01)
// Verifies glide.authenticate.basic_auth.restriction.active = 'true'.
// Identifiers verified REAL on Zurich Patch 6 (dev265484), 2026-06-11.
// Schema: v1 (---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function basicAuthRestrictionInactive(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.authenticate.basic_auth.restriction.active'
    var value = gs.getProperty(PROP, SENTINEL)

    var metadata = {
        nowisor_check_id: 'nowisor-basic-auth-restriction-inactive',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.8.5'],
            dora: ['9'],
        },
        evidence: {},
        severity: 3,
        remediation_id: 'basicauth-001',
        attack_path_refs: [],
    }

    var description
    if (value === SENTINEL) {
        // Feature predates this instance, or the tracking property is unregistered.
        // Do NOT fabricate a FAIL - emit an informational not_applicable finding.
        metadata.severity = 4
        metadata.remediation_id = 'basicauth-001-na'
        metadata.evidence = {
            property_name: PROP,
            status: 'not_applicable',
            reason: 'feature_not_present',
        }
        description =
            'The Basic Auth API restriction feature does not appear to be present on this instance (' +
            PROP +
            ' is not registered). If this instance is below the release that introduced Basic Auth restrictions, plan ahead: when ServiceNow enables enforcement, interactive accounts using Basic Auth APIs will be blocked. Upgrade awareness only - no posture failure is asserted.'
    } else if (value !== 'true') {
        metadata.evidence = {
            property_name: PROP,
            expected_value: 'true',
            actual_value: value,
        }
        description =
            'Basic Auth API restriction tracking is not active (' +
            PROP +
            ' = ' +
            value +
            '). Tracking is the prerequisite for inventorying which interactive accounts use Basic Auth APIs; with it off you are blind to the hybrid-account exposure before enforcement begins.'
    } else {
        return
    }

    var details =
        description + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(metadata)
    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
