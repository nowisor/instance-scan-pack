// nowisor v1.2.0 - Governance controls deployed but unconfigured (AIG-008)
// Flags AI Control Tower / Now Assist Guardian present on the instance with
// default or empty policy sets, no activated compliance controls, or
// observability that does not cover the active agent classes.
//
// THE GOVERNANCE-OF-GOVERNANCE PRINCIPLE, STATED PRECISELY
// Native tooling gives customers controls. We verify the controls are actually
// configured. This check never reproduces what Control Tower reports - it
// reports on Control Tower itself, which is the one thing Control Tower cannot
// do. A shelfware governance layer is worse than none, because it manufactures
// the confidence that stops anyone looking.
//
// PRECONDITION AND ITS MIRROR
// A governance layer must be PRESENT for this to fire. On an instance without
// one there is nothing to call unconfigured, so the check reports N/A - and
// AIA-009 does the same in reverse, staying N/A when Control Tower is absent.
// Between them: absent layer = one honest N/A pair, not two findings about the
// same gap. Deployed-and-empty is this check's finding; deployed-and-incomplete
// is AIA-009's.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object   - name
//   sys_dictionary  - name, element
//   v_plugin        - id   (ONLY id is verified)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiGovernanceUnconfigured(finding) {
    var CHECK_ID = 'nowisor-ai-governance-unconfigured'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // Governance-layer surfaces UNDER TEST, not verified identifiers.
    var REGISTRY_TABLES = ['sn_ai_control_tower_asset']
    REGISTRY_TABLES.push('sn_aic_ai_asset')
    REGISTRY_TABLES.push('sn_ai_registry')

    var POLICY_TABLES = ['sn_ai_control_tower_policy']
    POLICY_TABLES.push('sn_aic_policy')
    POLICY_TABLES.push('sn_ai_governance_policy')
    POLICY_TABLES.push('sn_ai_guardrail')

    var GOV_PLUGINS = ['com.snc.ai_control_tower']
    GOV_PLUGINS.push('com.glide.ai_control_tower')

    // Agent classes whose coverage the governance layer should span.
    var AGENT_TABLES = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENT_TABLES.push('sys_cs_topic')
    AGENT_TABLES.push('sys_mcp_server')

    var MAPPINGS = {
        nis2: ['21.2.a', '21.2.f'],
        iso27001: ['A.5.15', 'A.8.16'],
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

    function pluginPresent(id) {
        try {
            var p = new GlideRecord('v_plugin')
            p.addQuery('id', id)
            p.setLimit(1)
            p.query()
            return p.next() ? true : false
        } catch (e) {
            return false
        }
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- precondition: a governance layer is deployed ---------------------
    var registryTable = null
    for (var r = 0; r < REGISTRY_TABLES.length; r++) {
        if (tableExists(REGISTRY_TABLES[r])) {
            registryTable = REGISTRY_TABLES[r]
            break
        }
    }
    var govPlugin = null
    for (var g = 0; g < GOV_PLUGINS.length; g++) {
        if (pluginPresent(GOV_PLUGINS[g])) {
            govPlugin = GOV_PLUGINS[g]
            break
        }
    }

    if (!registryTable && !govPlugin) {
        emit(
            'No AI governance layer is deployed on this instance: neither an AI ' +
            'Control Tower registry table nor its plugin was found. There is ' +
            'nothing to report as unconfigured, so this check is out of scope - ' +
            'NOT a passing result. Whether a governance layer should be deployed ' +
            'is a procurement decision this scan does not make.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_governance_layer_deployed',
                    registry_tables_probed: REGISTRY_TABLES,
                    plugins_probed: GOV_PLUGINS
                },
                severity: 4,
                remediation_id: 'aig-008-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- signal 1: registry populated? -----------------------------------
    var registryCount = registryTable ? countRows(registryTable, false) : -1

    // ---- signal 2: any policy set configured? ----------------------------
    var policyTable = null
    var policyCount = -1
    for (var p2 = 0; p2 < POLICY_TABLES.length; p2++) {
        if (!tableExists(POLICY_TABLES[p2])) continue
        policyTable = POLICY_TABLES[p2]
        policyCount = countRows(policyTable, true)
        break
    }

    // ---- signal 3: does coverage span the active agent classes? ----------
    var activeClasses = []
    var totalAgents = 0
    for (var a = 0; a < AGENT_TABLES.length; a++) {
        if (!tableExists(AGENT_TABLES[a])) continue
        var n = countRows(AGENT_TABLES[a], true)
        if (n > 0) {
            activeClasses.push({ table: AGENT_TABLES[a], active_entities: n })
            totalAgents = totalAgents + n
        }
    }

    var problems = []
    if (registryTable && registryCount === 0) {
        problems.push('registry is empty')
    }
    if (policyTable && policyCount === 0) {
        problems.push('no active policy records in ' + policyTable)
    }
    if (!policyTable) {
        problems.push('no policy table could be resolved on this release')
    }
    if (totalAgents > 0 && registryTable && registryCount >= 0 &&
        registryCount < totalAgents) {
        problems.push(
            'registry holds ' + registryCount + ' entr(ies) against ' +
            totalAgents + ' active agentic entit(ies)'
        )
    }

    if (problems.length === 0) return

    var classNames = []
    for (var c = 0; c < activeClasses.length; c++) {
        classNames.push(
            activeClasses[c].table + ' (' + activeClasses[c].active_entities + ')'
        )
    }

    emit(
        'An AI governance layer is deployed on this instance but is not doing ' +
        'governance work: ' +
        problems.join('; ') +
        '. Active agent classes present: ' +
        (classNames.length ? classNames.join(', ') : 'none detected') +
        '. A deployed-but-empty governance layer is worse than none, because a ' +
        'populated-looking dashboard manufactures the confidence that stops ' +
        'anyone looking for what it does not cover. This check reports on the ' +
        'governance tool itself and deliberately reproduces nothing the tool ' +
        'reports.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                problems: problems,
                governance_plugin: govPlugin,
                registry_table: registryTable,
                registry_entry_count: registryCount,
                policy_table: policyTable,
                active_policy_count: policyCount,
                active_agent_classes: activeClasses,
                active_agent_total: totalAgents,
                row_cap: ROW_CAP,
                scope_note: 'reports on the governance layer, not through it'
            },
            severity: 2,
            remediation_id: 'aig-008',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
