// nowisor v1.2.0 - Sensitive-data handling absent on LLM-bound payloads (AIG-002)
// Flags an active agentic surface with no observable data-protection control on
// the fields it can read.
//
// WHAT IS OBSERVABLE, AND WHAT IS NOT
// Observable: whether the instance has ANY of the platform's data-protection
// mechanisms configured over sensitive tables - data policies, field-level
// encryption, data-classification records, or masked/encrypted dictionary
// attributes. Not observable: whether a given prompt actually carried personal
// data. A read-only scan sees configuration, never payloads, and this check
// never claims otherwise.
//
// So the finding is "the platform is not applying a data-protection control to
// what these agents can read", not "your agents leaked PII". The first is a
// verifiable configuration gap; the second would be an unfounded accusation.
//
// Fires only when an agentic surface is ACTIVE with entities - the control is
// meaningless on an instance whose agents are all switched off, and reporting it
// there would inflate the finding count.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object    - name
//   sys_dictionary   - name, element, internal_type
//   sys_data_policy2 - verified table (data policy)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiLlmPayloadMasking(finding) {
    var CHECK_ID = 'nowisor-ai-llm-payload-masking'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var AGENT_TABLES = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENT_TABLES.push('sys_cs_topic')

    // Platform data-protection mechanisms, any one of which counts.
    var PROTECTION_TABLES = ['sys_data_policy2']
    PROTECTION_TABLES.push('sys_data_classification')
    PROTECTION_TABLES.push('sys_encrypted_field')
    PROTECTION_TABLES.push('sys_column_encryption')
    PROTECTION_TABLES.push('sys_data_preserver')

    // Tables whose contents would matter in an LLM payload.
    var SENSITIVE = ['sys_user', 'incident']
    SENSITIVE.push('sn_hr_core_case')
    SENSITIVE.push('sys_credential')

    var MAPPINGS = {
        nis2: ['21.2.h', '21.2.i'],
        iso27001: ['A.8.24', 'A.5.15'],
        dora: ['9.3.b'],
        owasp_llm: ['LLM02:2025'],
        mitre_atlas: ['AML.T0024'],
        eu_ai_act: [{ article: '50', conditional: true }]
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

    function fieldsOf(t) {
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
        return have
    }

    function countRows(t, activeOnly) {
        try {
            var have = fieldsOf(t)
            var gr = new GlideRecord(t)
            if (activeOnly && have && have['active']) gr.addQuery('active', true)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n = n + 1
            return n
        } catch (e) {
            return -1
        }
    }

    // Encrypted / masked dictionary attributes on sensitive tables.
    function encryptedFieldCount() {
        var n = 0
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('internal_type', 'IN', 'password2,password,encrypted_text')
            d.setLimit(ROW_CAP)
            d.query()
            while (d.next()) n = n + 1
        } catch (e) {
            return -1
        }
        return n
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- gate: active agentic surface -------------------------------------
    var activeAgents = 0
    var agentTables = []
    for (var i = 0; i < AGENT_TABLES.length; i++) {
        if (!tableExists(AGENT_TABLES[i])) continue
        agentTables.push(AGENT_TABLES[i])
        var n = countRows(AGENT_TABLES[i], true)
        if (n > 0) activeAgents = activeAgents + n
    }

    if (agentTables.length === 0) {
        emit(
            'No agentic entity tables are present on this instance, so ' +
            'data-protection coverage of LLM-bound payloads cannot be assessed. ' +
            'Out of scope, NOT a pass.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agentic_tables',
                    tables_probed: AGENT_TABLES
                },
                severity: 4,
                remediation_id: 'aig-002-na',
                attack_path_refs: []
            }
        )
        return
    }

    // All agents inactive: the control is moot here.
    if (activeAgents === 0) return

    // ---- protection mechanisms present? ----------------------------------
    var mechanisms = []
    var probed = []
    for (var p = 0; p < PROTECTION_TABLES.length; p++) {
        var pt = PROTECTION_TABLES[p]
        if (!tableExists(pt)) {
            probed.push({ table: pt, present: false, count: -1 })
            continue
        }
        var c = countRows(pt, true)
        probed.push({ table: pt, present: true, count: c })
        if (c > 0) mechanisms.push(pt + ' (' + c + ')')
    }

    var encFields = encryptedFieldCount()
    if (encFields > 0) mechanisms.push('encrypted dictionary fields (' + encFields + ')')

    // Any mechanism configured: not a finding.
    if (mechanisms.length > 0) return

    var sensitivePresent = []
    for (var s = 0; s < SENSITIVE.length; s++) {
        if (tableExists(SENSITIVE[s])) sensitivePresent.push(SENSITIVE[s])
    }

    emit(
        activeAgents +
        ' active agentic entit(ies) operate on this instance with no ' +
        'data-protection control configured over the data they can read: no ' +
        'active data policies, no data classification records, no field ' +
        'encryption, and no encrypted dictionary attributes were found. ' +
        'Sensitive tables present: ' +
        sensitivePresent.join(', ') +
        '. WHAT THIS DOES NOT CLAIM: a read-only scan sees configuration, never ' +
        'payloads, so no assertion is made that any prompt carried personal ' +
        'data. The finding is that the platform is applying no data-protection ' +
        'control to what these agents can read - a verifiable configuration ' +
        'gap, not an observed disclosure.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                claim_boundary: 'configuration_only_no_payload_inspection',
                active_agent_count: activeAgents,
                agent_tables: agentTables,
                mechanisms_found: mechanisms,
                mechanisms_probed: probed,
                encrypted_field_count: encFields,
                sensitive_tables_present: sensitivePresent,
                row_cap: ROW_CAP
            },
            severity: 2,
            remediation_id: 'aig-002',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
