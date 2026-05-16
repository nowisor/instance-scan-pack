// nowisor v1.0.0 — hardcoded credentials detector (LinterCheck)
// AST visitor for server-side scripts. Reports lines where a credential-named
// identifier (NAME node) co-occurs on the same or adjacent line as a string
// LITERAL value of plausible credential length.
//
// Reference: credentials embedded as string literals in scripts are extractable by
// anyone with script-table read access, and they propagate across instances via update
// sets and export artifacts.
//
// AST PATTERN (Tier 3 fix, 2026-05-16): NAME + adjacent STRING by line co-occurrence
//
// History:
// - v1.0.0: label-plus-literal regex against LITERAL.getValue(). Failed because the
//   AST splits `var password = '…'` into NAME('password') + LITERAL('…') children of
//   a VAR node — LITERAL value alone never matches the labelled-assignment shape.
// - 2026-05-16 Tier 2 attempt: rewrote to anchor on NAME with credential identifier,
//   co-occurring with LITERAL on the same line. Test-scan on dev265147 produced zero
//   findings. Diagnostic dump (TOTAL_VISITED=27 across planted Script Include) showed
//   the actual node type for string literals is `STRING`, not `LITERAL`. The Tier 2
//   predicate never enters its STRING branch.
// - 2026-05-16 Tier 3 fix (this revision): accept `STRING` and `LITERAL` both. Same
//   line-co-occurrence shape, just with the correct node-type name.
//
// Verified node shape for `var password = "Pa$$w0rd123!";` on dev265147:
//   VAR (line 3) > NAME id='password' (line 3) + STRING (line 3) — both children of
//   the same VAR. Co-occurrence by line number is sound.
//
// Predicate: track two sets of lines.
//   (a) NAME nodes whose identifier matches the credential-name pattern
//   (b) STRING (or LITERAL) nodes whose getValue() is a string of 4..199 chars
// A line is flagged when (a) and (b) agree on the same or next line. Uses AST APIs
// verified on dev265147 by the active eval-usage-detector and set-roles-detector,
// plus STRING.getValue() — verified by the Tier 3 diagnostic round-trip.
//
// False-positive shape: `var passwordPolicy = "Default policy text"` will flag, since
// the variable IS named password-shaped. Acceptable for an audit detector — every
// flagged occurrence warrants review even if the literal is benign.
// False-negative shape: `var p = "Pa$$w0rd"` will NOT flag — heuristic detectors do
// not catch obfuscated identifier names.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function hardcodedCredentials(engine) {
    var nameLines = {}
    var literalLines = {}

    // Credential-shaped identifier names. Case-insensitive whole-identifier match
    // (no substring fuzz — too many false positives on words like "tokenize",
    // "password_reset_link", "secretary").
    var credNamePattern =
        /^(password|passwd|pwd|api[_]?key|apikey|secret|token|auth[_]?key|access[_]?token|refresh[_]?token|client[_]?secret|client[_]?key|bearer|credential)$/i

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
            if (id && credNamePattern.test(id)) {
                nameLines[node.getLineNo() + 1] = id
            }
            return
        }

        // STRING is the actual node type on the verified engine. LITERAL retained
        // defensively for releases / builds where the type-name differs.
        if (t === 'STRING' || t === 'LITERAL') {
            var v
            try {
                v = node.getValue()
            } catch (e) {
                return
            }
            if (v == null) return
            var s = String(v)
            // Tolerate engines that return quoted vs unquoted literal source
            var u = s.replace(/^['"]/, '').replace(/['"]$/, '')
            // Plausible credential length: long enough to be a password / token,
            // short enough to exclude prose. Excludes empty strings.
            if (u.length >= 4 && u.length < 200) {
                literalLines[node.getLineNo() + 1] = true
            }
        }
    })

    var line_numbers = []
    for (var line in nameLines) {
        if (!nameLines.hasOwnProperty(line)) continue
        var ln = parseInt(line, 10)
        // Same line (single-line assignment) or next line (multi-line assignment).
        if (literalLines[ln] || literalLines[ln + 1]) {
            line_numbers.push(ln)
        }
    }
    line_numbers.sort(function (a, b) {
        return a - b
    })

    if (line_numbers.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-hardcoded-credentials',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.h', '21.2.i'],
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
