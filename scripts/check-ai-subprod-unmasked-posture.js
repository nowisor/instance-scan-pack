// nowisor v1.2.0 - Agentic plugins on an unmasked sub-prod instance (AIA-004)
// Emits INVESTIGATE when three posture signals coincide on a non-production
// instance. Never CRITICAL - see the claim boundary below.
//
// THE CLAIM BOUNDARY, WHICH IS THE WHOLE POINT OF THIS CHECK
// A connected scan CANNOT observe whether a clone was masked. It cannot read
// what the clone process did, and sampling record contents to look for real PII
// would be both unreliable and an unacceptable thing for a security scanner to
// do to a customer's data. So this check detects RISK POSTURE only:
//   (a) the instance identifies as non-production, AND
//   (b) agentic plugins/tables are active, AND
//   (c) no data preservers / masking configuration exist for sensitive tables
// That combination is INVESTIGATE. It is NOT escalated to CRITICAL without
// positive evidence of unmasked sensitive data, which this check does not and
// will not gather. Over-claiming here would destroy credibility with precisely
// the buyer this module targets - a CISO who will clone a sub-prod and check.
//
// Why the combination still matters: sub-prod clones routinely carry production
// data, and agentic features on a clone will happily send that data to a model
// endpoint configured for testing, under looser controls, with fewer people
// watching. The posture is worth a look even though the outcome is unproven.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object      - name
//   sys_data_preserver - verified table (clone data preservation)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiSubprodUnmaskedPosture(finding) {
    var CHECK_ID = 'nowisor-ai-subprod-unmasked-posture'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var AGENTIC = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENTIC.push('sn_gen_ai_capability')
    AGENTIC.push('sys_cs_topic')

    var NONPROD_TOKENS = ['dev', 'test', 'qa']
    NONPROD_TOKENS.push('sandbox')
    NONPROD_TOKENS.push('uat')
    NONPROD_TOKENS.push('train')
    NONPROD_TOKENS.push('clone')
    NONPROD_TOKENS.push('staging')

    // Tables whose contents would matter if a clone were unmasked.
    var SENSITIVE = ['sys_user', 'sys_user_has_role']
    SENSITIVE.push('sys_credential')

    var MAPPINGS = {
        nis2: ['21.2.e', '21.2.i'],
        iso27001: ['A.8.33', 'A.5.15'],
        dora: ['9.3.d'],
        owasp_llm: ['LLM02:2025'],
        mitre_atlas: ['AML.T0025'],
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

    function countRows(t) {
        try {
            var gr = new GlideRecord(t)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n = n + 1
            return n
        } catch (e) {
            return -1
        }
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- signal (a): non-production identity ------------------------------
    var instName = ''
    try {
        instName = String(gs.getProperty('instance_name', '') || '')
    } catch (e) {
        instName = ''
    }
    if (instName === '') return

    var lower = instName.toLowerCase()
    var matchedToken = null
    for (var i = 0; i < NONPROD_TOKENS.length; i++) {
        if (lower.indexOf(NONPROD_TOKENS[i]) !== -1) {
            matchedToken = NONPROD_TOKENS[i]
            break
        }
    }
    // Prod-looking (or unrecognisable) instance: not this check's scope.
    if (!matchedToken) return

    // ---- signal (b): agentic surface active -------------------------------
    var agenticTables = []
    for (var a = 0; a < AGENTIC.length; a++) {
        if (tableExists(AGENTIC[a])) agenticTables.push(AGENTIC[a])
    }
    if (agenticTables.length === 0) return

    // Only worth reporting if agents actually exist, not just the tables.
    var agentRows = 0
    for (var g = 0; g < agenticTables.length; g++) {
        var c = countRows(agenticTables[g])
        if (c > 0) agentRows = agentRows + c
    }
    if (agentRows === 0) return

    // ---- signal (c): no masking / preservation configuration --------------
    var preserverTablePresent = tableExists('sys_data_preserver')
    var preserverCount = preserverTablePresent ? countRows('sys_data_preserver') : -1

    // Preservers configured -> the customer is managing clone data. Silent.
    if (preserverCount > 0) return

    // Cannot read the preserver table at all -> we lack signal (c), so we
    // cannot even claim the posture. Say nothing rather than guess.
    if (!preserverTablePresent || preserverCount < 0) return

    var sensitivePresent = []
    for (var s = 0; s < SENSITIVE.length; s++) {
        if (tableExists(SENSITIVE[s])) sensitivePresent.push(SENSITIVE[s])
    }

    emit(
        'INVESTIGATE: this instance identifies as non-production ("' +
        instName +
        '", matched on "' +
        matchedToken +
        '"), has an active agentic surface (' +
        agenticTables.join(', ') +
        ' with ' +
        agentRows +
        ' entit(ies)), and has no data preservers configured. Sub-production ' +
        'clones commonly carry production data, and agentic features on a clone ' +
        'will send whatever they can read to whatever model endpoint is ' +
        'configured for testing - under looser controls and with fewer people ' +
        'watching. ' +
        'WHAT THIS FINDING DOES NOT CLAIM: a connected scan cannot observe ' +
        'whether this clone was masked, and this check deliberately does not ' +
        'sample record contents to find out. No unmasked sensitive data has ' +
        'been observed and none is asserted. Confirm your clone masking ' +
        'process covers ' +
        sensitivePresent.join(', ') +
        ', then close this as accepted risk if it does.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'investigate',
                claim_boundary: 'posture_only_no_data_inspection',
                signal_a_instance_name: instName,
                signal_a_matched_token: matchedToken,
                signal_a_basis: 'instance_name_token_heuristic',
                signal_b_agentic_tables: agenticTables,
                signal_b_agentic_entities: agentRows,
                signal_c_preserver_table_present: preserverTablePresent,
                signal_c_preserver_count: preserverCount,
                sensitive_tables_present: sensitivePresent,
                row_cap: ROW_CAP,
                escalation_rule:
                    'CRITICAL requires positive evidence of unmasked ' +
                    'sensitive data, which this check does not gather'
            },
            severity: 3,
            remediation_id: 'ai-004-investigate',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
