// nowisor v1.2.0 - MCP / Action Fabric exposure scope (AIG-007)
// Two independent questions about the inbound surface, reported together:
//   (a) are write-capable tool packages granted where read-only would serve?
//   (b) do the OAuth clients used by inbound agents have expiry / rotation?
//
// COMPLEMENT, NOT DUPLICATE, OF THE UNGOVERNED-INBOUND CHECK
// AIA-008 asks WHO is connected and whether they are catalogued. This asks HOW
// MUCH the connection can do. An agent can be perfectly registered, owned and
// reviewed and still hold a write-everything tool package on a non-expiring
// OAuth client - which is the more common real-world failure, because
// registration is a governance task somebody owns and scope minimisation is not.
//
// SCOPE IS INFERRED FROM WHAT THE INSTANCE EXPOSES, NOT ASSUMED
// Tool-package shape differs across releases. The check resolves the columns it
// needs from sys_dictionary and reports N/A per question when they are absent,
// rather than guessing at a schema. Question (a) and (b) are independent: one
// can be answerable while the other is not.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object   - name
//   sys_dictionary  - name, element
//   oauth_entity    - verified table (OAuth client registry)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiMcpExposureScope(finding) {
    var CHECK_ID = 'nowisor-ai-mcp-exposure-scope'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var MCP_TABLES = ['sys_mcp_server', 'sys_mcp_tool_package']
    MCP_TABLES.push('sys_mcp_tool')
    MCP_TABLES.push('sn_mcp_server')
    MCP_TABLES.push('sn_mcp_tool_package')
    MCP_TABLES.push('sys_action_fabric_action')

    var OAUTH_TABLES = ['oauth_entity']

    // Column hints for the tool-package scope signal.
    var SCOPE_HINTS = ['tool_package', 'tools', 'scope']
    SCOPE_HINTS.push('operations')
    SCOPE_HINTS.push('operation')
    SCOPE_HINTS.push('access')

    var NAME_HINTS = ['name', 'label', 'title']

    // Tokens indicating a write-capable grant.
    var WRITE_TOKENS = ['write', 'create', 'update']
    WRITE_TOKENS.push('delete')
    WRITE_TOKENS.push('insert')
    WRITE_TOKENS.push('all')
    WRITE_TOKENS.push('admin')

    // Column hints for OAuth lifetime / rotation.
    var EXPIRY_HINTS = ['refresh_token_lifespan', 'access_token_lifespan']
    EXPIRY_HINTS.push('expires_in')
    EXPIRY_HINTS.push('expiry')

    var MAPPINGS = {
        nis2: ['21.2.i', '21.2.d'],
        iso27001: ['A.8.2', 'A.5.15'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025', 'LLM03:2025'],
        mitre_atlas: ['AML.T0012', 'AML.T0053'],
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

    function pick(have, hints) {
        if (!have) return null
        for (var i = 0; i < hints.length; i++) {
            if (have[hints[i]]) return hints[i]
        }
        return null
    }

    function writeToken(val) {
        if (!val) return null
        var lower = String(val).toLowerCase()
        for (var i = 0; i < WRITE_TOKENS.length; i++) {
            if (lower.indexOf(WRITE_TOKENS[i]) !== -1) return WRITE_TOKENS[i]
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

    // ---- gate: inbound surface present -----------------------------------
    var mcpPresent = []
    for (var i = 0; i < MCP_TABLES.length; i++) {
        if (tableExists(MCP_TABLES[i])) mcpPresent.push(MCP_TABLES[i])
    }
    if (mcpPresent.length === 0) {
        emit(
            'No MCP Server or Action Fabric surface is present on this ' +
            'instance, so inbound exposure scope cannot be assessed. Out of ' +
            'scope, NOT a pass. Re-run after any Now Assist SKU change - the ' +
            'inbound surface ships inside Now Assist entitlements.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_inbound_surface',
                    tables_probed: MCP_TABLES
                },
                severity: 4,
                remediation_id: 'aig-007-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- (a) broad tool packages -----------------------------------------
    var broad = []
    var scopeRowsRead = 0
    var scopeUnresolved = []

    for (var m = 0; m < mcpPresent.length; m++) {
        var tbl = mcpPresent[m]
        var have = fieldsOf(tbl)
        var scopeF = pick(have, SCOPE_HINTS)
        if (!scopeF) {
            scopeUnresolved.push(tbl)
            continue
        }
        var nameF = pick(have, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.addQuery(scopeF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scopeRowsRead = scopeRowsRead + 1
                var sv = gr.getValue(scopeF)
                var hit = writeToken(sv)
                if (!hit) continue
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.name = nameF ? gr.getValue(nameF) : null
                row.scope_column = scopeF
                row.scope_value = sv
                row.write_token = hit
                broad.push(row)
            }
        } catch (e) {
            scopeUnresolved.push(tbl)
        }
    }

    // ---- (b) OAuth clients without expiry --------------------------------
    var noExpiry = []
    var oauthRead = 0
    var oauthUnresolved = []

    for (var o = 0; o < OAUTH_TABLES.length; o++) {
        var otbl = OAUTH_TABLES[o]
        if (!tableExists(otbl)) {
            oauthUnresolved.push(otbl)
            continue
        }
        var ohave = fieldsOf(otbl)
        var expF = pick(ohave, EXPIRY_HINTS)
        if (!expF) {
            oauthUnresolved.push(otbl)
            continue
        }
        var onameF = pick(ohave, NAME_HINTS)
        try {
            var og = new GlideRecord(otbl)
            og.setLimit(ROW_CAP)
            og.query()
            while (og.next()) {
                oauthRead = oauthRead + 1
                var ev = og.getValue(expF)
                // Empty or 0 means no bounded lifetime on this client.
                if (ev !== null && String(ev) !== '' && String(ev) !== '0') continue
                var orow = {}
                orow.table = otbl
                orow.sys_id = og.getUniqueValue()
                orow.name = onameF ? og.getValue(onameF) : null
                orow.expiry_column = expF
                orow.expiry_value = ev
                noExpiry.push(orow)
            }
        } catch (e) {
            oauthUnresolved.push(otbl)
        }
    }

    // Neither question answerable: N/A rather than a silent pass.
    if (scopeRowsRead === 0 && oauthRead === 0) {
        emit(
            'An inbound agent surface exists (' +
            mcpPresent.join(', ') +
            ') but neither tool-package scope nor OAuth client lifetime could ' +
            'be read on this release. Exposure scope is unverified - review the ' +
            'granted tool packages and OAuth client expiry manually. No posture ' +
            'failure is asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'scope_and_oauth_columns_unresolved',
                    inbound_surfaces: mcpPresent,
                    scope_tables_unresolved: scopeUnresolved,
                    oauth_tables_unresolved: oauthUnresolved
                },
                severity: 4,
                remediation_id: 'aig-007-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (broad.length === 0 && noExpiry.length === 0) return

    var parts = []
    if (broad.length > 0) {
        var bex = []
        for (var x = 0; x < broad.length && x < 5; x++) {
            var bn = broad[x].name ? broad[x].name : broad[x].sys_id
            bex.push(bn + ' [' + broad[x].write_token + ' in ' + broad[x].scope_column + ']')
        }
        parts.push(
            broad.length +
            ' write-capable tool grant(s) on the inbound surface: ' +
            bex.join('; ')
        )
    }
    if (noExpiry.length > 0) {
        var oex = []
        for (var y = 0; y < noExpiry.length && y < 5; y++) {
            var on = noExpiry[y].name ? noExpiry[y].name : noExpiry[y].sys_id
            oex.push(on)
        }
        parts.push(
            noExpiry.length +
            ' OAuth client(s) with no bounded token lifetime: ' +
            oex.join(', ')
        )
    }

    emit(
        'Inbound agent exposure is broader than necessary. ' +
        parts.join('. ') +
        '. An external agent reaching the system of action should hold the ' +
        'narrowest tool package that satisfies its use case, on a credential ' +
        'that expires: write tools granted where read-only would serve, or a ' +
        'client whose access outlives the project that justified it, both turn ' +
        'a scoped integration into standing privileged access. This check ' +
        'reports configured scope, not observed use.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                broad_tool_grant_count: broad.length,
                oauth_without_expiry_count: noExpiry.length,
                scope_rows_read: scopeRowsRead,
                oauth_rows_read: oauthRead,
                inbound_surfaces: mcpPresent,
                write_tokens_watched: WRITE_TOKENS,
                scope_tables_unresolved: scopeUnresolved,
                oauth_tables_unresolved: oauthUnresolved,
                row_cap: ROW_CAP,
                detection_basis: 'configured_scope_not_observed_use',
                broad_tool_grants: broad,
                oauth_without_expiry: noExpiry
            },
            severity: 2,
            remediation_id: 'aig-007',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
