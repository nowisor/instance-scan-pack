// nowisor v1.0.0 — direct sys_properties write detector (LinterCheck)
// AST visitor for server-side scripts. Reports lines where `new GlideRecord(...)`
// targets the sys_properties table — i.e., a property write that bypasses
// gs.setProperty()'s cache invalidation and audit path.
//
// Reference: writing sys_properties via GlideRecord bypasses gs.setProperty()'s
// cache invalidation and audit consistency. Detection anchors on the constructor
// identifier and the table-name argument by line co-occurrence.
//
// AST PATTERN (Tier 2 fix, 2026-05-16): NAME 'GlideRecord' under NEW/CALL +
// LITERAL 'sys_properties' on the same line
//
// The v1.0.0-build predicate anchored on LITERAL 'sys_properties' and walked up
// ancestors looking for a NEW/CALL. Tier 2 planted-artifact verification on
// dev265484 (Zurich Patch 6) confirmed zero findings against
// `new GlideRecord('sys_properties').update()`. Likely cause: in the Rhino AST,
// the LITERAL argument is a child of the CALL whose function is NEW(GlideRecord),
// and the visit traversal of LITERAL.getParent() chain does not pass through a
// node typed exactly 'NEW' or 'CALL' as written. Rather than continue to chase
// the ancestor shape, this fix anchors on the part of the expression that is
// uniquely identifiable in the verified AST surface: NAME 'GlideRecord' with a
// CALL/NEW parent (proven by the active set-roles-detector pattern).
//
// Fixed predicate: track two sets of lines.
//   (a) NAME 'GlideRecord' whose parent is CALL or NEW (the constructor site)
//   (b) LITERAL whose getValue() is 'sys_properties' (with or without surrounding quotes)
// A line is flagged when both sets agree on the same line. Cross-line constructor
// calls are exceedingly rare in practice; the same-line constraint keeps false
// positives near zero.
//
// False-positive shape: `new GlideRecord('incident'); // see sys_properties` —
// comment containing 'sys_properties' produces a LITERAL on same line. The
// LITERAL.getValue() of a comment is not exposed by the AST (comments are
// stripped), so this is not a real concern. A literal pair like
// `new GlideRecord('incident'); var x = 'sys_properties';` on one line WOULD
// false-positive, but this code pattern is implausible.
// False-negative shape: indirect table-name resolution (e.g.,
// `var table = 'sys_properties'; new GlideRecord(table)`) is missed. Documented
// trade-off — the v1.0.0 surface does not include data-flow analysis.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function directPropertyWrite(engine) {
    var grLines = {}
    var sysPropLines = {}

    engine.rootNode.visit(function (node) {
        if (!node) return
        var t = node.getTypeName()

        if (t === 'NAME') {
            var id
            try {
                id = node.getNameIdentifier()
            } catch (e) {
                return
            }
            if (id !== 'GlideRecord') return
            var parent = node.getParent()
            if (!parent) return
            var pt = parent.getTypeName()
            // Direct constructor / function-call shape — covers
            // `new GlideRecord(...)` (parent CALL with NEW operator) and
            // `GlideRecord(...)` (defensive — non-idiomatic but possible).
            if (pt === 'CALL' || pt === 'NEW') {
                grLines[node.getLineNo() + 1] = true
                return
            }
            // Method-call shape: NAME 'GlideRecord' under GETPROP under CALL —
            // accept that too (e.g., x.GlideRecord, theoretically). Mirrors the
            // shape-tolerance from set-roles-detector.
            var grand = parent.getParent()
            if (grand && grand.getTypeName() === 'CALL') {
                grLines[node.getLineNo() + 1] = true
            }
            return
        }

        if (t === 'LITERAL') {
            var v
            try {
                v = node.getValue()
            } catch (e) {
                return
            }
            if (typeof v !== 'string') return
            // Tolerate engines that return quoted vs unquoted literal source
            var u = v.replace(/^['"]/, '').replace(/['"]$/, '')
            if (u === 'sys_properties') {
                sysPropLines[node.getLineNo() + 1] = true
            }
        }
    })

    var line_numbers = []
    for (var line in grLines) {
        if (!grLines.hasOwnProperty(line)) continue
        var ln = parseInt(line, 10)
        // Same-line co-occurrence only: GlideRecord constructor and its
        // table-name argument are on the same source line in normal style.
        if (sysPropLines[ln]) {
            line_numbers.push(ln)
        }
    }
    line_numbers.sort(function (a, b) {
        return a - b
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-direct-property-write',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a', '21.2.e'],
            iso27001: ['A.8.9'],
            dora: ['9'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 2,
        remediation_id: 'prop-001',
        attack_path_refs: [],
    }

    var details =
        "Direct sys_properties access via GlideRecord detected on lines: " +
        line_numbers.join(', ') +
        ". Writing sys_properties via GlideRecord bypasses gs.setProperty() cache invalidation and audit consistency. Use gs.setProperty(name, value) instead." +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
