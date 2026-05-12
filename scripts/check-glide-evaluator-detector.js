// nowisor v1.0.0 — GlideEvaluator detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of GlideEvaluator references.
//
// Reference: GlideEvaluator.evaluateString(...) and new GlideEvaluator() execute arbitrary
// strings as JavaScript, mirroring eval()'s injection-sink profile on a ServiceNow-specific
// API. Detection is name-based since the API is a single well-known class identifier.
//
// AST predicate: any NAME node whose identifier is 'GlideEvaluator'. This catches:
//   - new GlideEvaluator()            — NAME 'GlideEvaluator' under NEW
//   - GlideEvaluator.evaluateString() — NAME 'GlideEvaluator' as receiver of member-access
//   - var x = GlideEvaluator;         — bare reference (still suspicious, worth flagging)
// The name-only predicate is broader-than-strict but defensible: a bare reference to
// GlideEvaluator in user code is itself a smell worth audit, and false-positives from
// non-code contexts (string literals, comments) are excluded by the LITERAL/comment
// separation in the AST.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function glideEvaluatorDetector(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'GlideEvaluator'
        ) {
            line_numbers.push(node.getLineNo() + 1)
        }
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-glide-evaluator-detector',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.d'],
            iso27001: ['A.8.28'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 1,
        remediation_id: 'glide-eval-001',
        attack_path_refs: [],
    }

    var details =
        'GlideEvaluator reference detected on lines: ' +
        line_numbers.join(', ') +
        '. GlideEvaluator executes arbitrary strings as JavaScript and is a code-injection sink. Replace with direct method calls or JSON.parse() for structured input.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
