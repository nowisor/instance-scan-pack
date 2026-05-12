// nowisor v1.0.0 — setWorkflow(false) detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of setWorkflow(false).
//
// Reference: AP-007 attack pattern (nowisor KB) — setWorkflow(false) disables Business
// Rules, audit, and notifications for the subsequent write. Combined with eval() in
// Script Includes it enables privilege escalation outside audit observation.
//
// AST predicate: NAME node whose identifier is 'setWorkflow' AND whose parent is a CALL.
// We accept any first argument value (literal false, variable, expression) — the audit
// surface is the call itself; argument-value narrowing would create false-negatives when
// the argument is a variable or computed expression that resolves to false at runtime.
//
// API-uncertainty note: the LinterCheck AST verified surface (getTypeName, getNameIdentifier,
// getParent, getLineNo) does not include a documented child-access method for CALL nodes.
// A stricter predicate — "first argument is literal false" — would require getChildren()
// or argument iteration that is not in the verified API. We implement the broader predicate
// (any setWorkflow call) and treat true-arg calls as advisory rather than excluded. To verify
// argument-value narrowing post-authoring: plant a Script Include with setWorkflow(false) and
// setWorkflow(true) on dev265484; if only the false call should fire, refine here.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function setWorkflowFalseDetector(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'setWorkflow'
        ) {
            var parent = node.getParent()
            if (parent && parent.getTypeName() === 'CALL') {
                line_numbers.push(node.getLineNo() + 1)
            }
        }
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-set-workflow-false-detector',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.f'],
            iso27001: ['A.8.15'],
            dora: ['9'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 1,
        remediation_id: 'sw-001',
        attack_path_refs: ['AP-007'],
    }

    var details =
        'setWorkflow() detected on lines: ' +
        line_numbers.join(', ') +
        '. setWorkflow(false) bypasses Business Rules, audit, and notifications for the subsequent write. Default-deny and audit each occurrence with explicit justification.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
