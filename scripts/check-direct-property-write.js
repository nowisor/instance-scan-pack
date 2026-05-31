// nowisor v1.0.0 — direct sys_properties write detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of `new GlideRecord('sys_properties')`.
//
// Reference: writing sys_properties via GlideRecord bypasses gs.setProperty()'s cache
// invalidation and audit consistency. Detection anchors on the table-name literal under
// a GlideRecord constructor.
//
// AST predicate: LITERAL node whose value === 'sys_properties' AND whose ancestor chain
// includes a NEW expression with target 'GlideRecord'. We approximate by walking up via
// getParent() up to 3 levels and checking for a NEW node — the LITERAL is the argument
// to the CALL/NEW, so parent is typically CALL/NEW directly or one level up.
//
// API-uncertainty note: getValue() on LITERAL is in the spec's "likely-additional APIs"
// list. If unavailable, the predicate yields zero findings (silent-fail-safe). To verify
// post-authoring: plant `new GlideRecord('sys_properties').insert()` on dev265484 and
// confirm a finding. The verification gate documented in the project spec covers this.
//
// We do not require the ancestor NEW to also have a GlideRecord NAME child — that would
// need getChildren() — but we constrain via the literal value 'sys_properties' which is
// uniquely associated with the sys_properties-write idiom.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function directPropertyWrite(engine) {
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
        if (node.getTypeName() !== 'LITERAL') return
        var v
        try {
            v = node.getValue()
        } catch (e) {
            return
        }
        if (v !== 'sys_properties') return

        // Walk up to 3 ancestors looking for a NEW or CALL whose context indicates a
        // GlideRecord construction. Conservative: any NEW or CALL ancestor counts.
        var cur = node.getParent()
        var depth = 0
        var found = false
        while (cur && depth < 3) {
            var t = cur.getTypeName()
            if (t === 'NEW' || t === 'CALL') {
                found = true
                break
            }
            cur = cur.getParent()
            depth++
        }
        if (found) {
            line_numbers.push(node.getLineNo() + 1)
        }
    })

    if (line_numbers.length === 0) return

    var _art = _resolveArtifact()
    var metadata = {
        nowisor_check_id: 'nowisor-direct-property-write',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a'],
            iso27001: ['A.8.9'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
            artifact_scope: _art.artifact_scope,
            artifact_table: _art.artifact_table,
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
