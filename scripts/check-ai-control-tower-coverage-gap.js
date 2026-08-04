// nowisor v1.2.0 - AI Control Tower coverage gap check (AIA-009)
// Flags agentic entities that exist in the instance but are absent from AI
// Control Tower's registry WHEN Control Tower is deployed.
//
// GOVERNANCE OF GOVERNANCE - AND ITS LIMIT
// Control Tower gives customers the control; this check verifies the control is
// actually covering the estate. It deliberately does NOT reproduce anything
// Control Tower reports: no risk scores, no observability, no policy content.
// It answers one question Control Tower cannot answer about itself - what is
// running here that you never registered.
//
// This is the planted-unregistered-agent POC scenario: buyers evaluate agent
// security tools by creating an unregistered agent and timing discovery. The
// evidence string therefore names WHERE the entity was found and WHERE it was
// expected, so the answer is auditable in one read.
//
// HARD PRECONDITION: Control Tower must be deployed. On an instance without it
// this check is N/A, not a finding - "you have no Control Tower" is AIG-008's
// job, and reporting every agent as an uncovered gap here would double-count
// the same defect and inflate the finding count.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object  - name
//   sys_dictionary - name, element
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiControlTowerCoverageGap(finding) {
    var CHECK_ID = 'nowisor-ai-control-tower-coverage-gap'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var REGISTRY = ['sn_ai_control_tower_asset']
    REGISTRY.push('sn_aic_ai_asset')
    REGISTRY.push('sn_ai_registry')

    // Agentic entity sources UNDER TEST, not verified identifiers.
    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']
    SOURCES.push('sn_gen_ai_capability')

    var NAME_HINTS = ['name', 'label', 'title']
    NAME_HINTS.push('short_description')

    var MAPPINGS = {
        nis2: ['21.2.f', '21.2.i'],
        iso27001: ['A.5.16', 'A.8.16'],
        dora: ['9.4.a'],
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

    function norm(v) {
        if (v === null) return ''
        return String(v).toLowerCase().replace(/^\s+|\s+$/g, '')
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- precondition: Control Tower deployed ----------------------------
    var registryTable = null
    for (var r = 0; r < REGISTRY.length; r++) {
        if (tableExists(REGISTRY[r])) {
            registryTable = REGISTRY[r]
            break
        }
    }

    if (!registryTable) {
        emit(
            'AI Control Tower does not appear to be deployed on this instance ' +
            '(no registry table found). Registry coverage cannot be measured, ' +
            'so this check is out of scope - NOT a passing result. Whether a ' +
            'governance layer SHOULD be deployed is assessed separately by the ' +
            'governance-configuration check.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'control_tower_not_deployed',
                    tables_probed: REGISTRY
                },
                severity: 4,
                remediation_id: 'ai-009-na',
                attack_path_refs: []
            }
        )
        return
    }

    var regNameF = pickField(registryTable, NAME_HINTS)
    if (!regNameF) {
        emit(
            'AI Control Tower registry table ' +
            registryTable +
            ' is present but no name field could be resolved on this release, ' +
            'so registry coverage cannot be compared. Coverage gap in this ' +
            'check, NOT a posture failure.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'registry_name_field_unresolved',
                    registry_table: registryTable
                },
                severity: 4,
                remediation_id: 'ai-009-na',
                attack_path_refs: []
            }
        )
        return
    }

    var registered = {}
    var registryCount = 0
    try {
        var rgr = new GlideRecord(registryTable)
        rgr.setLimit(ROW_CAP)
        rgr.query()
        while (rgr.next()) {
            var rn = norm(rgr.getValue(regNameF))
            if (rn) {
                registered[rn] = true
                registryCount = registryCount + 1
            }
        }
    } catch (e) {
        registryCount = -1
    }

    // ---- estate inventory -------------------------------------------------
    var uncovered = []
    var total = 0
    var scannedTables = []

    for (var s = 0; s < SOURCES.length; s++) {
        var tbl = SOURCES[s]
        if (!tableExists(tbl)) continue
        var nameF = pickField(tbl, NAME_HINTS)
        if (!nameF) continue
        scannedTables.push(tbl)
        try {
            var gr = new GlideRecord(tbl)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                total = total + 1
                var nm = gr.getValue(nameF)
                if (norm(nm) && registered[norm(nm)]) continue
                var row = {}
                row.found_in = tbl
                row.expected_in = registryTable
                row.sys_id = gr.getUniqueValue()
                row.name = nm
                row.name_field = nameF
                row.created_by = gr.getValue('sys_created_by')
                row.created_on = gr.getValue('sys_created_on')
                uncovered.push(row)
            }
        } catch (e) {
            // unreadable source - excluded from total, recorded by omission
        }
    }

    if (total === 0) return
    if (uncovered.length === 0) return

    var examples = []
    for (var x = 0; x < uncovered.length && x < 10; x++) {
        var label = uncovered[x].name ? uncovered[x].name : uncovered[x].sys_id
        examples.push(
            label + ' found in ' + uncovered[x].found_in +
            ', expected in ' + uncovered[x].expected_in
        )
    }

    emit(
        uncovered.length +
        ' of ' +
        total +
        ' agentic entities in this instance are absent from the AI Control ' +
        'Tower registry (' +
        registryTable +
        ', ' +
        registryCount +
        ' entries). Control Tower is deployed, so these are running outside ' +
        'the governance layer the organisation believes covers them - the gap ' +
        'is in coverage, not in the tool. ' +
        examples.join('; ') +
        '. Matching is by normalised name: an asset registered under a ' +
        'different label will appear here, so confirm each one before acting.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                uncovered_count: uncovered.length,
                entities_total: total,
                registry_table: registryTable,
                registry_entry_count: registryCount,
                sources_scanned: scannedTables,
                match_basis: 'normalized_name_comparison',
                row_cap: ROW_CAP,
                uncovered: uncovered
            },
            severity: 2,
            remediation_id: 'ai-009',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
