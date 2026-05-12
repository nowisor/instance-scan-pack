// nowisor v1.0.0 — GlideRecord vs GlideRecordSecure detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of `new GlideRecord(...)`.
//
// Reference: GlideRecord bypasses ACLs on read by default; GlideRecordSecure evaluates
// the caller's ACL context. Per-occurrence remediation requires knowing whether the
// caller is entitled — this detector emits an inventory signal, not a per-line defect.
//
// AST predicate: NAME node whose identifier is 'GlideRecord' AND whose parent is a NEW
// expression. We anchor on the NAME ('GlideRecord' identifier) rather than the NEW node
// to stay consistent with the eval/setWorkflow pattern.
//
// API-uncertainty note: the verified AST surface confirms NEW as a node type in the
// 7-check spec but does not specify its child structure. A stricter predicate — "NEW
// node whose target is GlideRecord and not GlideRecordSecure" — would need getChildren()
// or target-identifier introspection. We rely on the name match: GlideRecordSecure is a
// distinct identifier so we will not false-positive on it via NAME equality.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function glideRecordVsSecure(engine) {
    var line_numbers = []

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (
            node.getTypeName() === 'NAME' &&
            node.getNameIdentifier() === 'GlideRecord'
        ) {
            var parent = node.getParent()
            if (parent && parent.getTypeName() === 'NEW') {
                line_numbers.push(node.getLineNo() + 1)
            }
        }
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-glide-record-vs-secure',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.h'],
            iso27001: ['A.8.3'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 2,
        remediation_id: 'gr-001',
        attack_path_refs: [],
    }

    var details =
        'new GlideRecord() detected on lines: ' +
        line_numbers.join(', ') +
        '. GlideRecord bypasses ACL evaluation on read; consider GlideRecordSecure where the caller should be subject to row-level security. Treat as an inventory signal pending reachability analysis.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
