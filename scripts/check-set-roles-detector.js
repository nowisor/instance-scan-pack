// nowisor v1.0.0 — setRoles() detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of setRoles() calls.
//
// Reference: setRoles() mutates session role state. When reachable from user-controlled
// input it becomes a privilege-escalation primitive. Inventory signal: every occurrence
// warrants audit even when the role list looks static.
//
// AST PATTERN (Tier 2 fix, 2026-05-12): function call vs method call shape
//
// setRoles is universally called as a method on a session/user receiver, e.g.,
// `gs.getUser().setRoles('admin')`. AST shape:
//     CALL
//     ├── GETPROP / PROPERTY / MEMBER_ACCESS
//     │   ├── (subexpression for gs.getUser())
//     │   └── NAME 'setRoles'      ← parent is GETPROP, GRANDPARENT is CALL
//     └── LITERAL 'admin'
//
// The v1.0.0-build predicate required `parent.getTypeName() === 'CALL'`, which is the
// function-call shape (eval('1+1')) — never matches method-call shapes. Tier 2 planted-
// artifact verification on dev265484 confirmed zero findings against
// `gs.getUser().setRoles('admin')`.
//
// Fixed predicate: NAME 'setRoles' AND (parent CALL — defensive, in case of unusual call
// shapes — OR grandparent CALL — the realistic method-call case). The shape-tolerant
// predicate matches the eval-detector for function calls AND catches method calls.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function setRolesDetector(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() !== 'NAME' ||
            node.getNameIdentifier() !== 'setRoles'
        ) {
            return
        }
        var parent = node.getParent()
        if (!parent) return
        // Function-call shape
        if (parent.getTypeName() === 'CALL') {
            line_numbers.push(node.getLineNo() + 1)
            return
        }
        // Method-call shape: NAME under GETPROP under CALL
        var grandparent = parent.getParent()
        if (grandparent && grandparent.getTypeName() === 'CALL') {
            line_numbers.push(node.getLineNo() + 1)
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
