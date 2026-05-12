// nowisor v1.0.0 — Attachment role restriction check
// Flags when glide.attachment.role is empty (NOT_SET / empty string) or set to 'public'.
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function attachmentRoleRestriction(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.attachment.role'
    var value = gs.getProperty(PROP, SENTINEL)

    var notSetCase = value === SENTINEL
    var emptyCase = !notSetCase && (value === '' || value === null)
    var publicCase = !notSetCase && !emptyCase && String(value).toLowerCase() === 'public'

    if (!notSetCase && !emptyCase && !publicCase) return

    var description
    if (notSetCase) {
        description =
            'Attachment role restriction property is not registered in sys_properties on this instance. Default behavior permits any authenticated user to upload/download attachments, expanding malware ingress and data exfiltration surface.'
    } else if (emptyCase) {
        description =
            'Attachment role restriction property is empty. Any authenticated user can upload/download attachments via the standard attachment API.'
    } else {
        description =
            "Attachment role restriction is set to 'public', which the platform treats as unrestricted. Any authenticated user can upload/download attachments via the standard attachment API."
    }

    var actualValue
    if (notSetCase) {
        actualValue = 'NOT_REGISTERED'
    } else if (emptyCase) {
        actualValue = 'EMPTY'
    } else {
        actualValue = value
    }

    var metadata = {
        nowisor_check_id: 'nowisor-attachment-role-restriction',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.h'],
            iso27001: ['A.5.34'],
            dora: ['9'],
        },
        evidence: {
            property_name: PROP,
            expected: 'non-empty, non-public role name',
            actual_value: actualValue,
        },
        severity: 2,
        remediation_id: 'acl-002',
        attack_path_refs: [],
    }

    var details =
        description +
        '\n\nCurrent value: ' +
        actualValue +
        '. Expected: a non-public role name (e.g., attachment_writer).' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
