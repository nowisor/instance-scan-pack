// nowisor v1.0.0 — cross-domain Script Include reference detector (LinterCheck)
// AST visitor for server-side scripts. Heuristic: flags scripts that mutate auth/session
// state (setRoles, setSession) AND do not reference 'sys_overrides' anywhere in the script.
//
// Reference: on domain-separated instances, auth/session mutation paths need to participate
// in the sys_overrides domain-override model. Scripts that mutate without referencing
// sys_overrides may have been written for a non-DS mental model and can produce cross-
// domain leakage when DS is active.
//
// AST predicate: two-pass over the AST:
//   pass A — flag whether any NAME node with identifier 'setRoles' or 'setSession' exists
//   pass B — flag whether any LITERAL or NAME contains/equals the string 'sys_overrides'
// If pass A is true AND pass B is false, emit a finding at the first auth-mutation line.
//
// API-uncertainty note: LITERAL.getValue() is in the spec's "likely-additional APIs" list.
// If unavailable for pass B, the script defaults to "no sys_overrides found" — over-reporting
// rather than under-reporting, which is the safer failure mode for a heuristic check. To
// verify post-authoring: plant a Script Include containing setRoles + a sys_overrides
// reference on dev265484 and confirm zero findings (negative case). The verification gate
// documented in the project spec covers this.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA---block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function domainSeparationScriptInclude(engine) {
    var auth_mutation_lines = []
    var sys_overrides_seen = false

    engine.rootNode.visit(function (node) {
        if (!node) return
        var t = node.getTypeName()
        if (t === 'NAME') {
            var n = node.getNameIdentifier()
            if (n === 'setRoles' || n === 'setSession') {
                auth_mutation_lines.push(node.getLineNo() + 1)
            }
            if (n === 'sys_overrides') {
                sys_overrides_seen = true
            }
        } else if (t === 'LITERAL') {
            var v
            try {
                v = node.getValue()
            } catch (e) {
                v = null
            }
            if (typeof v === 'string' && v.indexOf('sys_overrides') !== -1) {
                sys_overrides_seen = true
            }
        }
    })

    if (auth_mutation_lines.length === 0) return
    if (sys_overrides_seen) return

    var metadata = {
        nowisor_check_id: 'nowisor-domain-separation-script-include',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.31'],
            gdpr: ['32'],
        },
        evidence: {
            line_numbers: auth_mutation_lines,
            occurrence_count: auth_mutation_lines.length,
        },
        severity: 2,
        remediation_id: 'ds-si-001',
        attack_path_refs: [],
    }

    var details =
        'Auth/session mutation (setRoles/setSession) without sys_overrides reference on lines: ' +
        auth_mutation_lines.join(', ') +
        '. On domain-separated instances, scripts that mutate auth/session state should participate in the sys_overrides domain-override model. Heuristic check — confirm DS-context applicability before remediating.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', auth_mutation_lines.length)
    engine.finding.increment()
})(engine)
