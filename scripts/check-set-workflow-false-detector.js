// nowisor v1.0.0 — setWorkflow(false) detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of setWorkflow(false).
//
// Reference: AP-007 attack pattern (nowisor KB) — setWorkflow(false) disables Business
// Rules, audit, and notifications for the subsequent write.
//
// AST PATTERN (Tier 2 fix, 2026-05-12): function call vs method call shape
//
// Direct function call — `eval('1+1')`:
//     CALL
//     ├── NAME 'eval'      ← parent IS CALL
//     └── LITERAL '1+1'
//
// Method call — `gr.setWorkflow(false)`:
//     CALL
//     ├── GETPROP / PROPERTY / MEMBER_ACCESS
//     │   ├── NAME 'gr'
//     │   └── NAME 'setWorkflow'  ← parent is GETPROP, GRANDPARENT is CALL
//     └── LITERAL false
//
// The v1.0.0-build version checked only `parent.getTypeName() === 'CALL'` which works for
// function-call patterns (eval, GlideEvaluator construction) but misses method-call patterns
// (any obj.method(args) shape). Tier 2 planted-artifact verification on dev265484
// (`gr.setWorkflow(false)`) produced zero findings — confirmed by walking the AST manually.
//
// The fixed predicate accepts both shapes: NAME 'setWorkflow' AND (parent is CALL OR
// grandparent is CALL). False-positive risk: someone has a property literally named
// `setWorkflow` accessed as `obj.setWorkflow` (not invoked) — very unlikely on the
// ServiceNow surface.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function setWorkflowFalseDetector(engine) {
    // _resolveArtifact (A1-DEP) — see eval-usage-detector header comment for rationale.
    function _resolveArtifact() {
        var scope = ''
        var tableName = ''
        try {
            if (engine && engine.finding && engine.finding.getValue) {
                tableName = engine.finding.getValue('table') || engine.finding.getValue('table_name') || ''
                var recId = engine.finding.getValue('record') || ''
                if (tableName && recId) {
                    var gr = new GlideRecord(tableName)
                    if (gr.get(recId)) {
                        scope = gr.getValue('sys_scope') || ''
                    }
                }
            }
        } catch (e) { /* best-effort */ }
        return { artifact_scope: scope, artifact_table: tableName }
    }
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() !== 'NAME' ||
            node.getNameIdentifier() !== 'setWorkflow'
        ) {
            return
        }
        var parent = node.getParent()
        if (!parent) return
        // Function-call shape: NAME directly under CALL
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

    var _art = _resolveArtifact()
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
            artifact_scope: _art.artifact_scope,
            artifact_table: _art.artifact_table,
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
