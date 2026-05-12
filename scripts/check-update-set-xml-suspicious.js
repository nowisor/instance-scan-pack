// nowisor v1.0.0 — Suspicious Update Set XML (ColumnTypeCheck)
// Scans XML payload content for three privilege-escalation patterns.
//
// Runtime contract: ColumnTypeCheck exposes `engine` with source content.
// Conservative source extraction tries engine.getSource() (LinterCheck analog)
// then falls back to engine.rootNode.toString() and finally to engine itself
// coerced to string. One of these returns the column content on a real run.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function updateSetXmlSuspicious(engine) {
    var source = ''
    if (engine && typeof engine.getSource === 'function') {
        source = engine.getSource() || ''
    } else if (engine && engine.rootNode && typeof engine.rootNode.toString === 'function') {
        source = engine.rootNode.toString() || ''
    } else if (engine) {
        try {
            source = String(engine)
        } catch (e) {
            source = ''
        }
    }

    if (!source) return

    var patterns = [
        {
            name: 'admin role grant',
            regex: /<sys_user_has_role[\s\S]*?<role[\s\S]*?>[\s\S]*?admin[\s\S]*?<\/role>/i,
        },
        {
            name: 'ACL modification',
            regex: /<sys_security_acl[\s>]/i,
        },
        {
            name: 'cross-scope privilege grant',
            regex: /<sys_scope_privilege[\s>]/i,
        },
    ]

    var hits = []
    for (var i = 0; i < patterns.length; i++) {
        if (patterns[i].regex.test(source)) {
            hits.push(patterns[i].name)
        }
    }

    if (hits.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-update-set-xml-suspicious',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.f'],
            iso27001: ['A.8.32'],
        },
        evidence: {
            pattern_matches: hits,
            match_count: hits.length,
        },
        severity: 1,
        remediation_id: 'update-set-001',
        attack_path_refs: [],
    }

    var details =
        'Suspicious update set XML detected. Patterns matched: ' +
        hits.join(', ') +
        '. Review the update set source and intent before committing.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    if (engine && engine.finding && typeof engine.finding.setValue === 'function') {
        engine.finding.setValue('finding_details', details)
        engine.finding.setValue('count', hits.length)
        engine.finding.increment()
    }
})(engine)
