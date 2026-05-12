// nowisor v1.0.0 — hardcoded credentials detector (LinterCheck)
// AST visitor for server-side scripts. Reports line numbers of LITERAL string nodes
// whose value matches credential-shaped patterns.
//
// Reference: credentials embedded as string literals in scripts are extractable by
// anyone with script-table read access, and they propagate across instances via update
// sets and export artifacts.
//
// AST predicate: LITERAL node whose getValue() returns a string matching one of the
// labelled-assignment credential patterns. Pattern matching is per-LITERAL because the
// verified AST surface gives us getValue() on LITERAL nodes (per the 7-check spec's
// "likely-additional APIs"); engine.getSource() is not used because it is also unverified
// and a per-literal predicate is safer (no full-source materialization).
//
// API-uncertainty note: if node.getValue() is unavailable on LITERAL nodes, this script
// will produce zero findings (silent-fail-safe — no crash, no false-positives). To verify
// post-authoring: plant a Script Include with `var password = "Pa$$w0rd"` on dev265484
// and confirm a finding. If zero, swap to engine.getSource() regex scan (left commented
// below as a fallback). The verification gate documented in the project spec covers this.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function hardcodedCredentials(engine) {
    var line_numbers = []

    // Patterns: labelled assignment of credential-shaped values. Case-insensitive.
    // These mirror the regex set in the 7-check spec and are intentionally narrow to
    // reduce false-positives from arbitrary strings containing the labels.
    var patterns = [
        /password\s*[:=]\s*['"][^'"]+['"]/i,
        /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i,
        /secret\s*[:=]\s*['"][^'"]+['"]/i,
        /token\s*[:=]\s*['"][^'"]+['"]/i,
    ]

    engine.rootNode.visit(function (node) {
        if (!node) return
        if (node.getTypeName() !== 'LITERAL') return
        // getValue() is in the spec's "likely-additional APIs" list; guard for undefined.
        var v
        try {
            v = node.getValue()
        } catch (e) {
            return
        }
        if (typeof v !== 'string') return
        for (var i = 0; i < patterns.length; i++) {
            if (patterns[i].test(v)) {
                line_numbers.push(node.getLineNo() + 1)
                return
            }
        }
    })

    // Fallback (verification-time only — commented out): if LITERAL.getValue() is
    // unavailable, the predicate above yields zero hits. Re-enable engine.getSource()
    // scanning here only after confirming getSource() is available.
    //
    // var src = engine.getSource && engine.getSource()
    // if (src && line_numbers.length === 0) {
    //     var lines = String(src).split('\n')
    //     for (var li = 0; li < lines.length; li++) {
    //         for (var pi = 0; pi < patterns.length; pi++) {
    //             if (patterns[pi].test(lines[li])) {
    //                 line_numbers.push(li + 1)
    //                 break
    //             }
    //         }
    //     }
    // }

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-hardcoded-credentials',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.i'],
            iso27001: ['A.8.5'],
            dora: ['9'],
        },
        evidence: {
            line_numbers: line_numbers,
            occurrence_count: line_numbers.length,
        },
        severity: 1,
        remediation_id: 'creds-001',
        attack_path_refs: [],
    }

    var details =
        'Hardcoded credential pattern detected on lines: ' +
        line_numbers.join(', ') +
        '. Credentials in script source are extractable via script-table read access and propagate through update sets. Move to sys_properties (non-secret), Credential records, or the Credential Vault Provider API.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    engine.finding.setValue('finding_details', details)
    engine.finding.setValue('count', line_numbers.length)
    engine.finding.increment()
})(engine)
