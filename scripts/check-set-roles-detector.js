// nowisor v1.0.0 — setRoles() detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of setRoles() calls.
//
// Reference: setRoles() mutates session role state. When reachable from user-controlled
// input it becomes a privilege-escalation primitive. Inventory signal: every occurrence
// warrants audit even when the role list looks static.
//
// AST predicate: NAME node whose identifier is 'setRoles' AND whose parent is a CALL.
// Method-call resolution in this AST surface is "member-access NAME under CALL"; the
// NAME-under-CALL pattern matches the canonical eval-usage detector predicate.
//
// API-uncertainty note: we do not narrow on the receiver identifier (e.g., gs.getUser()).
// 'setRoles' is a sufficiently uncommon method name that name-only matching is acceptable;
// false-positives from same-named methods in unrelated APIs would still warrant audit.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function setRolesDetector(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'setRoles'
        ) {
            var parent = node.getParent()
            if (parent && parent.getTypeName() === 'CALL') {
                line_numbers.push(node.getLineNo() + 1)
            }
        }
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-set-roles-detector',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.18'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 1,
        remediation_id: 'sr-001',
        attack_path_refs: [],
    }

    var details =
        'setRoles() detected on lines: ' +
        line_numbers.join(', ') +
        '. setRoles() mutates session role state and can be turned into a privilege-escalation primitive if reachable from user-controlled input. Audit role-list source and caller-identity checks.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
