// nowisor pilot v0.1 — eval() usage detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of eval() calls.
//
// Reference: AP-007 attack pattern (nowisor KB) — eval() in Script Includes enables
// runtime injection bypassing static analysis. Combined with setWorkflow(false) it
// enables privilege escalation outside Business Rule observation.
//
// AST node types used: NAME (identifier), CALL (function invocation).
// Detection logic: NAME node whose identifier is 'eval' AND whose parent is a CALL.
//
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

    engine.finding.setValue(
        'finding_details',
        'Found eval() on lines: ' + line_numbers.join(', ')
    )
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
