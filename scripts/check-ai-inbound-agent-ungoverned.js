// nowisor v1.2.0 - Ungoverned inbound external agent check (AIA-008)
// Flags inbound agent surfaces (MCP Server / Action Fabric) whose registered
// external agents are absent from AI Control Tower or any sanctioned catalog.
//
// WHY THIS IS THE LAUNCH FINDING
// Action Fabric and MCP Server let an agent built anywhere - Claude, Copilot,
// something homegrown - act inside the instance headlessly, under an OAuth
// client, against role-scoped tool packages. That is the system of action
// reachable by a caller no ITSM control was designed around. An inbound agent
// nobody registered is unowned privileged access with no lifecycle: nothing
// reviews it, nothing revokes it, and it predates most incumbent check
// libraries.
//
// THE THREE-WAY SPLIT THIS CHECK REFUSES TO COLLAPSE
//   no inbound surface at all           -> N/A (out of scope, not a pass)
//   inbound surface, no registry        -> INVESTIGATE: cannot judge
//                                          registration without a catalog;
//                                          the missing catalog is AIG-008's
//                                          finding, not N unregistered agents
//   inbound surface + registry + misses -> CRITICAL, names each miss
// Reporting "N ungoverned agents" on an instance that simply has no Control
// Tower would be an artifact of our own detection, not a customer defect.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object  - name
//   sys_dictionary - name, element
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiInboundAgentUngoverned(finding) {
    var CHECK_ID = 'nowisor-ai-inbound-agent-ungoverned'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // Inbound-agent surfaces UNDER TEST, not verified identifiers.
    var INBOUND = ['sys_mcp_server', 'sys_mcp_tool_package']
    INBOUND.push('sn_mcp_server')
    INBOUND.push('sn_mcp_tool_package')
    INBOUND.push('sys_action_fabric_action')

    var REGISTRY = ['sn_ai_control_tower_asset']
    REGISTRY.push('sn_aic_ai_asset')
    REGISTRY.push('sn_ai_registry')

    var NAME_HINTS = ['name', 'label', 'title']
    NAME_HINTS.push('short_description')

    var ACTIVE_HINTS = ['active', 'state', 'status']

    var MAPPINGS = {
        nis2: ['21.2.d', '21.2.i'],
        iso27001: ['A.5.15', 'A.8.2'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM03:2025', 'LLM06:2025'],
        mitre_atlas: ['AML.T0103', 'AML.T0108'],
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

    // ---- gate ------------------------------------------------------------
    var surfaces = []
    for (var i = 0; i < INBOUND.length; i++) {
        if (tableExists(INBOUND[i])) surfaces.push(INBOUND[i])
    }

    if (surfaces.length === 0) {
        emit(
            'No inbound external-agent surface is present on this instance: ' +
            'no MCP Server or Action Fabric tables were found. External ' +
            'agents cannot currently reach the instance through that path, so ' +
            'this control is out of scope - NOT a passing result. Re-run this ' +
            'check after any Now Assist SKU change, since Action Fabric and ' +
            'MCP Server ship inside Now Assist entitlements.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_inbound_surface',
                    tables_probed: INBOUND
                },
                severity: 4,
                remediation_id: 'ai-008-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- registry ---------------------------------------------------------
    var registryTable = null
    var registryNames = {}
    var registryCount = 0
    for (var r = 0; r < REGISTRY.length; r++) {
        if (!tableExists(REGISTRY[r])) continue
        registryTable = REGISTRY[r]
        var rNameF = pickField(registryTable, NAME_HINTS)
        if (!rNameF) break
        try {
            var rgr = new GlideRecord(registryTable)
            rgr.setLimit(ROW_CAP)
            rgr.query()
            while (rgr.next()) {
                var rn = norm(rgr.getValue(rNameF))
                if (rn) {
                    registryNames[rn] = true
                    registryCount = registryCount + 1
                }
            }
        } catch (e) {
            registryTable = null
        }
        break
    }

    // ---- inbound inventory -----------------------------------------------
    var agents = []
    for (var s = 0; s < surfaces.length; s++) {
        var tbl = surfaces[s]
        var nameF = pickField(tbl, NAME_HINTS)
        var actF = pickField(tbl, ACTIVE_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.name = nameF ? gr.getValue(nameF) : null
                row.name_field = nameF
                row.active = actF ? gr.getValue(actF) : null
                row.created_by = gr.getValue('sys_created_by')
                row.created_on = gr.getValue('sys_created_on')
                agents.push(row)
            }
        } catch (e) {
            // unreadable surface - recorded via surfaces list, not fatal
        }
    }

    if (agents.length === 0) return

    // No catalog to compare against -> INVESTIGATE, never "N ungoverned".
    if (!registryTable || registryCount === 0) {
        emit(
            'An inbound external-agent surface is active (' +
            surfaces.join(', ') +
            ') with ' +
            agents.length +
            ' registered entr(ies), but no sanctioned AI catalog was found on ' +
            'this instance to compare them against. Governance of headless ' +
            'external access cannot be verified: either AI Control Tower is ' +
            'not deployed, or its registry is empty. Establish the catalog ' +
            'first - this finding does NOT assert that these agents are ' +
            'unauthorised.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'investigate',
                    reason: 'no_registry_to_compare',
                    inbound_surfaces: surfaces,
                    inbound_entry_count: agents.length,
                    registry_table: registryTable,
                    registry_entry_count: registryCount,
                    inbound: agents
                },
                severity: 3,
                remediation_id: 'ai-008-investigate',
                attack_path_refs: ['AP-013']
            }
        )
        return
    }

    var missing = []
    for (var a = 0; a < agents.length; a++) {
        var key = norm(agents[a].name)
        // An unnamed inbound entry cannot be matched to a catalog entry; treat
        // it as ungoverned and say why in the evidence.
        if (!key) {
            agents[a].match_basis = 'unnamed_entry'
            missing.push(agents[a])
            continue
        }
        if (registryNames[key]) continue
        agents[a].match_basis = 'name_absent_from_registry'
        missing.push(agents[a])
    }

    if (missing.length === 0) return

    var examples = []
    for (var x = 0; x < missing.length && x < 10; x++) {
        var nm = missing[x].name ? missing[x].name : '(unnamed ' + missing[x].sys_id + ')'
        examples.push(nm + ' [found in ' + missing[x].table + ']')
    }

    emit(
        missing.length +
        ' of ' +
        agents.length +
        ' inbound external-agent entries are absent from the sanctioned AI ' +
        'catalog (' +
        registryTable +
        ', ' +
        registryCount +
        ' entries). These have headless, OAuth-scoped access to the system of ' +
        'action with no governance record: nothing reviews their tool scope ' +
        'and nothing owns their revocation. Found here, expected in ' +
        registryTable +
        ': ' +
        examples.join('; ') +
        '. Registration is matched by name, so a catalog entry under a ' +
        'different label will appear here - confirm before revoking.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                ungoverned_count: missing.length,
                inbound_entry_count: agents.length,
                inbound_surfaces: surfaces,
                registry_table: registryTable,
                registry_entry_count: registryCount,
                match_basis: 'normalized_name_comparison',
                row_cap: ROW_CAP,
                ungoverned: missing
            },
            severity: 1,
            remediation_id: 'ai-008',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
