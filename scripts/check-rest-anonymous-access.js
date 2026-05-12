// nowisor v1.0.0 — REST anonymous access audit
// Verifies the glide.basicauth.required.* family — emits ONE finding if any are non-compliant
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// All 7 properties verified-real on Zurich Patch 6 PDI dev265484; default 'true'
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function restAnonymousAccess(finding) {
    var SENTINEL = '__NOT_SET__'
    var EXPECTED = 'true'

    var props = [
        'glide.basicauth.required.api',
        'glide.basicauth.required.scriptedprocessor',
        'glide.basicauth.required.soap',
        'glide.basicauth.required.wsdl',
        'glide.basicauth.required.xsd',
        'glide.basicauth.required.databrokerrestapiprocessor',
        'glide.basicauth.required.unl',
    ]

    var audited = {}
    var noncompliant = []
    var i
    var name
    var raw

    for (i = 0; i < props.length; i++) {
        name = props[i]
        raw = gs.getProperty(name, SENTINEL)
        if (raw === SENTINEL) {
            audited[name] = 'NOT_REGISTERED'
            noncompliant.push(name)
        } else {
            audited[name] = raw
            if (raw !== EXPECTED) {
                noncompliant.push(name)
            }
        }
    }

    if (noncompliant.length === 0) return

    var description =
        'One or more glide.basicauth.required.* properties are not enforcing authentication. The corresponding endpoint families (REST API, scripted REST processors, SOAP, WSDL, XSD, databroker REST processor, or UNL) accept unauthenticated requests, exposing the platform to anonymous enumeration and direct table access.'

    var metadata = {
        nowisor_check_id: 'nowisor-rest-anonymous-access',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.d'],
            iso27001: ['A.5.16'],
            dora: ['9'],
        },
        evidence: {
            audited_properties: audited,
            noncompliant_count: noncompliant.length,
            noncompliant_properties: noncompliant,
            expected_value: EXPECTED,
        },
        severity: 1,
        remediation_id: 'rest-001',
        attack_path_refs: [],
    }

    var details =
        description +
        '\n\nNon-compliant properties (' +
        noncompliant.length +
        ' of ' +
        props.length +
        '): ' +
        noncompliant.join(', ') +
        '. Expected each: true.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
