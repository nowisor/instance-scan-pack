// nowisor v1.0.0 — eval() usage detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of eval() calls.
//
// Reference: AP-007 attack pattern (nowisor KB) — eval() in Script Includes enables
// runtime injection bypassing static analysis. Combined with setWorkflow(false) it
// enables privilege escalation outside Business Rule observation.
//
// Predicate verified empirically against a planted Global-scope Script Include
// containing `eval('1+1')` on dev265484 (Zurich Patch 6) on 2026-05-10:
// AST visit produced eval=true, eval_in_call=true, top names included eval(1).
// LinterCheck iterates ~19,605 records across ~50 script-bearing tables on a
// stock PDI; 0 findings on a clean instance is the correct outcome, not a bug.
//
// AST node types used: NAME (identifier), CALL (function invocation).
// Detection logic: NAME node whose identifier is 'eval' AND whose parent is a CALL.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function evalUsageDetector(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (
            node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'eval' &&
            node.getParent().getTypeName() === 'CALL'
        ) {
            // getLineNo() is 0-based; convert to 1-based for human-readable output
            line_numbers.push(node.getLineNo() + 1)
        }
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-eval-usage-detector',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.d'],
            iso27001: ['A.8.28'],
            dora: ['9'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 1,
        remediation_id: 'eval-001',
        attack_path_refs: ['AP-007'],
    }

    var details =
        'eval() detected on lines: ' +
        line_numbers.join(', ') +
        '. eval() executes arbitrary string-based JavaScript at runtime, bypassing static security analysis. Replace with JSON.parse() for JSON input or direct method calls.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
