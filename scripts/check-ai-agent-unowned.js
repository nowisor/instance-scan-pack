// nowisor v1.2.0 - Unowned agentic entity check (AIA-001)
// Flags agentic entities whose owner field EXISTS on this release but is blank.
//
// THE RULE THAT MAKES THIS CHECK HONEST
// Three states, only one of which is a finding:
//   owner field missing on this release -> N/A  (severity 4, not_applicable)
//   owner field present, value blank    -> FINDING
//   owner field present, value set      -> pass (silent)
// Firing when the field is merely absent would flag every agent on every
// release whose owner column is named differently - an over-claim of exactly
// the kind the 2026-05-09 fabricated-property audit was about. Absence of
// evidence is not evidence of a gap.
//
// Owner column is DISCOVERED from sys_dictionary against a hint list; the
// resolved column name travels in the evidence so a reviewer can audit every
// value back to a real field. No agentic field name is asserted from memory:
// sn_aia is paid-SKU gated, so CLAUDE.md evidence leg (a) is unsatisfiable for
// that namespace and enumeration is the only defensible source.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object  - name
//   sys_dictionary - name, element
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint). ASCII-only, short lines.
;(function aiAgentUnowned(finding) {
    var CHECK_ID = 'nowisor-ai-agent-unowned'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // Candidate tables UNDER TEST, not verified identifiers.
    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var OWNER_HINTS = ['owner', 'owned_by', 'assigned_to']
    OWNER_HINTS.push('managed_by')
    OWNER_HINTS.push('owner_group')

    var NAME_HINTS = ['name', 'label', 'title']
    NAME_HINTS.push('short_description')

    var MAPPINGS = {
        nis2: ['21.2.i'],
        iso27001: ['A.5.16', 'A.8.2'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0103'],
        eu_ai_act: [{ article: '4', conditional: false }]
    }

    function tableExists(t) {
        try {
            var d = new GlideRecord('sys_db_object')
            d.addQuery('name', t)
            d.setLimit(1)
            d.query()
            return d.next() ? true : false
        } catch (e) {
            return false
        }
    }

    function pickField(t, hints) {
        var have = {}
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', t)
            d.addQuery('element', '!=', '')
            d.setLimit(ROW_CAP)
            d.query()
            while (d.next()) {
                have[d.getValue('element')] = true
            }
        } catch (e) {
            return null
        }
        for (var i = 0; i < hints.length; i++) {
            if (have[hints[i]]) return hints[i]
        }
        return null
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- gate ------------------------------------------------------------
    var present = []
    for (var i = 0; i < SOURCES.length; i++) {
        if (tableExists(SOURCES[i])) present.push(SOURCES[i])
    }

    if (present.length === 0) {
        emit(
            'No agentic entity tables are present on this instance. ' +
            'Now Assist / AI Agent Studio does not appear to be installed, ' +
            'so agent ownership cannot be assessed. This is out of scope, ' +
            'NOT a passing result.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agentic_tables',
                    tables_probed: SOURCES
                },
                severity: 4,
                remediation_id: 'ai-001-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- scan ------------------------------------------------------------
    var unowned = []
    var scanned = 0
    var unresolvedTables = []
    var resolvedMap = {}

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var ownerF = pickField(tbl, OWNER_HINTS)
        if (!ownerF) {
            // No owner column on this release -> cannot judge this table.
            unresolvedTables.push(tbl)
            continue
        }
        resolvedMap[tbl] = ownerF
        var nameF = pickField(tbl, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scanned = scanned + 1
                var val = gr.getValue(ownerF)
                if (val !== null && String(val) !== '') continue
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.owner_field = ownerF
                row.name = nameF ? gr.getValue(nameF) : null
                unowned.push(row)
            }
        } catch (e) {
            unresolvedTables.push(tbl)
        }
    }

    // Every present table lacked an owner column -> N/A, not a finding.
    if (scanned === 0) {
        emit(
            'Agentic entities are present, but no owner / ownership field ' +
            'could be resolved on this release (' +
            unresolvedTables.join(', ') +
            '). Agent ownership cannot be verified by script here - review ' +
            'ownership in AI Agent Studio directly. No posture failure is ' +
            'asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'owner_field_unresolved',
                    tables_present: present,
                    tables_unresolved: unresolvedTables
                },
                severity: 4,
                remediation_id: 'ai-001-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (unowned.length === 0) return

    var names = []
    for (var u = 0; u < unowned.length && u < 10; u++) {
        var n = unowned[u].name ? unowned[u].name : unowned[u].sys_id
        names.push(unowned[u].table + ':' + n)
    }

    emit(
        unowned.length +
        ' of ' +
        scanned +
        ' agentic entities have no assigned owner. An agent without a named ' +
        'owner has nobody accountable for its permissions, its prompt, or its ' +
        'decommissioning - and it is indistinguishable from an agent an ' +
        'attacker deployed. Examples: ' +
        names.join(', ') +
        '.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                unowned_count: unowned.length,
                entities_scanned: scanned,
                owner_fields_resolved: resolvedMap,
                tables_unresolved: unresolvedTables,
                row_cap: ROW_CAP,
                unowned: unowned
            },
            severity: 2,
            remediation_id: 'ai-001',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
