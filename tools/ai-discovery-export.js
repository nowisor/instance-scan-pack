// Read-only: safe for production use
//
// nowisor ai-discovery-export tool v1.0.0 - emits ai-discovery schema v1
// Paste-into-Background-Script sensor for the ai-agent-security category.
//
// Sensor #3 (after security-log-export and incident-june-2026-check). It maps
// the agentic surface of the connected instance: which plugins are present,
// which agentic tables actually exist, which FIELDS those tables actually have,
// which external LLM endpoints are reachable, and where the log sources the
// least-privilege correlation depends on begin. NO correlation logic and NO
// verdicts live here - this script is a pure sensor. The advisor decides.
//
// Output: one JSON envelope to gs.print (schema version: ai-discovery v1).
//
// WHY THIS IS ENUMERATION-DRIVEN, NOT NAME-DRIVEN
// ServiceNow's agentic surface is release-unstable and largely paid-SKU gated
// (sn_aia cannot be activated on any PDI, so CLAUDE.md evidence leg (a) is
// unsatisfiable for that namespace). Asserting table or field names from
// memory is exactly how the sn_now_assist.* / sn_aia.* fabrications entered
// the KB in 2026-05. So this sensor asserts almost nothing: it enumerates
// sys_db_object by scope prefix, then reads sys_dictionary per resolved table
// to report the fields that are really there. Downstream checks consume the
// envelope and must not reference a table or field it did not confirm.
//
// The *_CANDIDATES arrays below are names UNDER TEST, not claims. A name in
// them is a probe target; the envelope reports resolved vs absent for each.
// Never copy a candidate name into KB content or a user-facing string on the
// strength of its appearing here.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object      - name, label, sys_class_name, super_class.name
//   sys_dictionary     - name, element, internal_type, column_label
//   v_plugin           - id  (ONLY id is verified; do not read name/active)
//   sn_aia_use_case    - active, execution_mode
//   sys_cb_ai_agent    - existence only (zero fields verified)
//   sys_properties     - name, value
//
// ES5-only (Rhino ES0 in Background Scripts). ASCII-only and short lines:
// long lines wrap on paste and break string literals. One statement per line.

(function aiDiscoveryExport() {
    var SCHEMA_VERSION = 'v1'
    var PACK_VERSION = '1.2.0'
    var TABLE_CAP = 400
    var ROW_CAP = 200
    var SAMPLE_CAP = 50

    var now = new GlideDateTime()
    var generatedAt = now.getValue()

    var coverageNotes = []
    var sourcesAvailable = []
    var sourcesMissing = []

    // Scope prefixes to enumerate in sys_db_object. Prefixes are search
    // patterns, not identifier claims - whatever comes back is ground truth.
    var SCOPE_PREFIXES = [
        'sn_aia',
        'sn_gen_ai',
        'sys_generative',
        'sys_one_extend',
        'sys_cb',
        'sn_now_assist',
        'sn_ai',
        'sys_cs'
    ]

    // Plugin ids under test. Absence is reported, never treated as a pass.
    var PLUGIN_CANDIDATES = [
        'com.glide.now_assist',
        'com.snc.now_assist',
        'com.glide.generative_ai_controller',
        'com.snc.generative_ai_controller',
        'com.glide.one_extend',
        'com.glide.cs.chatbot',
        'com.snc.ai_control_tower',
        'com.glide.ai_control_tower',
        'com.glide.mcp_server',
        'com.snc.mcp_server',
        'com.glide.action_fabric',
        'com.glide.domain_tracking'
    ]

    // Tables under test per capability surface.
    var CONTROL_TOWER_CANDIDATES = [
        'sn_ai_control_tower_asset',
        'sn_aic_ai_asset',
        'sn_ai_registry',
        'sn_ai_control_tower_policy'
    ]
    var MCP_CANDIDATES = [
        'sys_mcp_server',
        'sys_mcp_tool',
        'sys_mcp_tool_package',
        'sn_mcp_server',
        'sn_mcp_tool_package',
        'sys_action_fabric_action'
    ]
    var LLM_CONN_CANDIDATES = [
        'sys_rest_message',
        'sys_rest_message_fn',
        'sys_alias',
        'sys_connection',
        'sys_connection_alias',
        'sn_gen_ai_provider_config'
    ]
    var OAUTH_CANDIDATES = [
        'oauth_entity',
        'oauth_credential',
        'oauth_entity_profile'
    ]
    // Where skill/agent input bindings and flow variable maps may live.
    // AIG-004 consumes whatever resolves here; if nothing resolves it must
    // emit N/A rather than guess.
    var BINDING_CANDIDATES = [
        'sn_aia_tool_input_binding',
        'sn_aia_agent_input',
        'sys_cb_input_variable',
        'sys_variable_value',
        'sys_hub_flow_input',
        'sys_hub_action_input'
    ]
    // Execution/usage log sources for the Phase B lookback.
    var LOG_CANDIDATES = [
        'sn_aia_execution_log',
        'sn_aia_agent_execution',
        'sys_cb_conversation',
        'sys_cs_conversation',
        'sys_flow_context',
        'syslog_transaction',
        'sys_audit'
    ]

    // Host fragments that indicate an external model provider. Matching is
    // reported as a fact (matched_host); the shadow-AI verdict is app-side.
    var LLM_HOST_HINTS = [
        'openai.com',
        'openai.azure.com',
        'anthropic.com',
        'generativelanguage.googleapis.com',
        'bedrock',
        'mistral.ai',
        'cohere.ai',
        'huggingface.co',
        'googleapis.com/v1beta'
    ]

    // ---- helpers -------------------------------------------------------------

    // sys_db_object is the primary existence signal, NOT
    // GlideTableDescriptor.isValid(): isValid() returned false for real tables
    // (sys_audit, syslog_transaction, sysevent) on dev265147 2026-05-22, see
    // ff40848 Section A. Same helper shape as tools/security-log-export.js.
    function tableExists(tableName) {
        try {
            var dbo = new GlideRecord('sys_db_object')
            dbo.addQuery('name', tableName)
            dbo.setLimit(1)
            dbo.query()
            if (dbo.next()) return true
            try {
                var probe = new GlideRecord(tableName)
                probe.setLimit(1)
                probe.query()
                return true
            } catch (e2) {
                return false
            }
        } catch (e) {
            return false
        }
    }

    // Fields that really exist on a table, per sys_dictionary. This is what
    // makes downstream checks honest: they read the envelope, not a guess.
    function fieldsOf(tableName) {
        var out = []
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', tableName)
            d.addQuery('element', '!=', '')
            d.setLimit(ROW_CAP)
            d.query()
            while (d.next()) {
                var el = d.getValue('element')
                if (!el) continue
                var one = {}
                one.field = el
                one.type = d.getValue('internal_type') || ''
                out.push(one)
            }
        } catch (e) {
            coverageNotes.push('field probe failed: ' + tableName)
        }
        return out
    }

    function countRows(tableName) {
        try {
            var ga = new GlideAggregate(tableName)
            ga.addAggregate('COUNT')
            ga.query()
            if (ga.next()) {
                return parseInt(ga.getAggregate('COUNT'), 10)
            }
        } catch (e) {
            // fall through to capped GR count
        }
        try {
            var gr = new GlideRecord(tableName)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n++
            return n
        } catch (e2) {
            return -1
        }
    }

    // Earliest record on a log source. This is the coverage FLOOR that Phase B
    // needs: a DORMANT verdict is only legitimate when the floor predates the
    // full lookback window. Emitted as a fact; the engine does the comparing.
    function earliestRecord(tableName) {
        try {
            var gr = new GlideRecord(tableName)
            gr.orderBy('sys_created_on')
            gr.setLimit(1)
            gr.query()
            if (gr.next()) {
                return gr.getValue('sys_created_on') || null
            }
        } catch (e) {
            return null
        }
        return null
    }

    function propOrNull(name) {
        try {
            var v = gs.getProperty(name, null)
            if (v === null) return null
            if (String(v) === '') return null
            return String(v)
        } catch (e) {
            return null
        }
    }

    function matchedHost(url) {
        if (!url) return null
        var lower = String(url).toLowerCase()
        for (var i = 0; i < LLM_HOST_HINTS.length; i++) {
            var hint = LLM_HOST_HINTS[i]
            if (lower.indexOf(hint) !== -1) return hint
        }
        return null
    }

    // Resolve a candidate list into present/absent, with fields for present.
    function resolveCandidates(list) {
        var out = {}
        out.resolved = []
        out.absent = []
        for (var i = 0; i < list.length; i++) {
            var name = list[i]
            if (!tableExists(name)) {
                out.absent.push(name)
                continue
            }
            var entry = {}
            entry.table = name
            entry.row_count = countRows(name)
            entry.fields = fieldsOf(name)
            out.resolved.push(entry)
        }
        return out
    }

    // ---- 1. plugins ----------------------------------------------------------
    // Only v_plugin.id is a verified field, so id is all we read. A plugin
    // absent from v_plugin entirely is reported as absent - the 2026-05-20 DS
    // finding showed paid-SKU plugins are not even listed, which is a
    // materially different state from listed-but-inactive.
    var pluginsPresent = []
    var pluginsAbsent = []
    if (!tableExists('v_plugin')) {
        sourcesMissing.push('v_plugin')
        coverageNotes.push('v_plugin not queryable - plugin state unknown')
    } else {
        sourcesAvailable.push('v_plugin')
        for (var pi = 0; pi < PLUGIN_CANDIDATES.length; pi++) {
            var pid = PLUGIN_CANDIDATES[pi]
            var found = false
            try {
                var pgr = new GlideRecord('v_plugin')
                pgr.addQuery('id', pid)
                pgr.setLimit(1)
                pgr.query()
                found = pgr.next() ? true : false
            } catch (e) {
                found = false
            }
            if (found) {
                pluginsPresent.push(pid)
            } else {
                pluginsAbsent.push(pid)
            }
        }
    }

    // ---- 2. namespace enumeration -------------------------------------------
    var namespaceTables = []
    var namespaceCounts = {}
    if (!tableExists('sys_db_object')) {
        sourcesMissing.push('sys_db_object')
        coverageNotes.push('sys_db_object not queryable - no table discovery')
    } else {
        sourcesAvailable.push('sys_db_object')
        for (var si = 0; si < SCOPE_PREFIXES.length; si++) {
            var prefix = SCOPE_PREFIXES[si]
            namespaceCounts[prefix] = 0
            try {
                var tgr = new GlideRecord('sys_db_object')
                tgr.addQuery('name', 'STARTSWITH', prefix)
                tgr.orderBy('name')
                tgr.setLimit(TABLE_CAP)
                tgr.query()
                while (tgr.next()) {
                    var row = {}
                    row.table = tgr.getValue('name')
                    row.label = tgr.getValue('label') || ''
                    row.prefix = prefix
                    namespaceTables.push(row)
                    namespaceCounts[prefix] = namespaceCounts[prefix] + 1
                }
            } catch (e) {
                coverageNotes.push('prefix scan failed: ' + prefix)
            }
        }
    }

    // ---- 3. capability surfaces ---------------------------------------------
    var controlTower = resolveCandidates(CONTROL_TOWER_CANDIDATES)
    var mcpSurface = resolveCandidates(MCP_CANDIDATES)
    var bindingSurface = resolveCandidates(BINDING_CANDIDATES)
    var oauthSurface = resolveCandidates(OAUTH_CANDIDATES)

    // Known-verified agentic tables get an explicit presence probe so the
    // envelope always carries their state even if a prefix scan is capped.
    var knownAgentic = {}
    knownAgentic.sn_aia_use_case = tableExists('sn_aia_use_case')
    knownAgentic.sys_cb_ai_agent = tableExists('sys_cb_ai_agent')

    // Active/autonomous use-case counts use ONLY verified fields.
    var useCaseSummary = {}
    useCaseSummary.available = knownAgentic.sn_aia_use_case
    useCaseSummary.active_count = -1
    useCaseSummary.autonomous_active_count = -1
    if (knownAgentic.sn_aia_use_case) {
        try {
            var ucA = new GlideRecord('sn_aia_use_case')
            ucA.addQuery('active', true)
            ucA.setLimit(ROW_CAP)
            ucA.query()
            var acount = 0
            while (ucA.next()) acount++
            useCaseSummary.active_count = acount
        } catch (e) {
            coverageNotes.push('sn_aia_use_case active count failed')
        }
        try {
            var ucB = new GlideRecord('sn_aia_use_case')
            ucB.addQuery('active', true)
            ucB.addQuery('execution_mode', 'autonomous')
            ucB.setLimit(ROW_CAP)
            ucB.query()
            var bcount = 0
            while (ucB.next()) bcount++
            useCaseSummary.autonomous_active_count = bcount
        } catch (e2) {
            coverageNotes.push('sn_aia_use_case autonomous count failed')
        }
    }

    // ---- 4. external LLM endpoints ------------------------------------------
    // Endpoint fields are release-unstable, so the field name is discovered
    // from sys_dictionary rather than assumed. Anything endpoint-shaped is
    // sampled; the sanctioned-vs-shadow call belongs to the advisor.
    var ENDPOINT_FIELD_HINTS = ['endpoint', 'rest_endpoint', 'url', 'host']
    var llmConnections = []
    var llmTablesScanned = []
    for (var li = 0; li < LLM_CONN_CANDIDATES.length; li++) {
        var lname = LLM_CONN_CANDIDATES[li]
        if (!tableExists(lname)) continue
        llmTablesScanned.push(lname)
        var lfields = fieldsOf(lname)
        var endpointField = null
        for (var fi = 0; fi < lfields.length; fi++) {
            var fname = lfields[fi].field
            for (var hi = 0; hi < ENDPOINT_FIELD_HINTS.length; hi++) {
                if (fname === ENDPOINT_FIELD_HINTS[hi]) {
                    endpointField = fname
                    break
                }
            }
            if (endpointField) break
        }
        if (!endpointField) {
            coverageNotes.push('no endpoint field on ' + lname)
            continue
        }
        try {
            var lgr = new GlideRecord(lname)
            lgr.addQuery(endpointField, '!=', '')
            lgr.setLimit(SAMPLE_CAP)
            lgr.query()
            while (lgr.next()) {
                var ep = lgr.getValue(endpointField) || ''
                var hit = matchedHost(ep)
                if (!hit) continue
                var conn = {}
                conn.source_table = lname
                conn.endpoint_field = endpointField
                conn.sys_id = lgr.getUniqueValue()
                conn.endpoint = ep
                conn.matched_host = hit
                llmConnections.push(conn)
            }
        } catch (e) {
            coverageNotes.push('endpoint scan failed: ' + lname)
        }
    }

    // ---- 5. log sources + coverage floor ------------------------------------
    var logSources = []
    for (var gi = 0; gi < LOG_CANDIDATES.length; gi++) {
        var gname = LOG_CANDIDATES[gi]
        var entry = {}
        entry.table = gname
        entry.present = tableExists(gname)
        entry.earliest_record = null
        entry.row_count = -1
        if (entry.present) {
            entry.earliest_record = earliestRecord(gname)
            entry.row_count = countRows(gname)
            if (!entry.earliest_record) {
                coverageNotes.push('no earliest_record for ' + gname)
            }
        }
        logSources.push(entry)
    }

    // ---- 6. instance identity (prod vs sub-prod signal for AIA-004) ---------
    // Facts only. The non-prod determination is a judgement and stays app-side.
    var instanceInfo = {}
    instanceInfo.instance_name = propOrNull('instance_name')
    instanceInfo.buildtag = propOrNull('glide.buildtag')
    instanceInfo.builddate = propOrNull('glide.builddate')
    instanceInfo.data_preserver_table_present = tableExists('sys_data_preserver')
    instanceInfo.data_preserver_count = -1
    if (instanceInfo.data_preserver_table_present) {
        instanceInfo.data_preserver_count = countRows('sys_data_preserver')
    }

    // ---- envelope -----------------------------------------------------------
    var anyAgenticSurface = false
    if (pluginsPresent.length > 0) anyAgenticSurface = true
    if (namespaceTables.length > 0) anyAgenticSurface = true
    if (knownAgentic.sn_aia_use_case) anyAgenticSurface = true
    if (knownAgentic.sys_cb_ai_agent) anyAgenticSurface = true

    var noteParts = []
    noteParts.push(sourcesAvailable.length + ' discovery sources available')
    noteParts.push(namespaceTables.length + ' agentic tables resolved')
    if (!anyAgenticSurface) {
        noteParts.push('no agentic surface found - checks must report N/A')
    }
    if (coverageNotes.length) {
        noteParts.push(coverageNotes.join('; '))
    }
    var coverageNoteStr = noteParts.join(' - ')

    var envelope = {
        nowisor_aidiscovery_schema: SCHEMA_VERSION,
        pack_version: PACK_VERSION,
        generated_at: generatedAt,
        agentic_surface_present: anyAgenticSurface,
        instance: instanceInfo,
        plugins: {
            probed: PLUGIN_CANDIDATES,
            present: pluginsPresent,
            absent: pluginsAbsent
        },
        namespaces: {
            prefixes_scanned: SCOPE_PREFIXES,
            per_prefix_count: namespaceCounts,
            table_cap: TABLE_CAP,
            tables: namespaceTables
        },
        known_agentic_tables: knownAgentic,
        use_case_summary: useCaseSummary,
        capability_surfaces: {
            ai_control_tower: controlTower,
            mcp_action_fabric: mcpSurface,
            input_bindings: bindingSurface,
            oauth_clients: oauthSurface
        },
        llm_connections: {
            tables_scanned: llmTablesScanned,
            host_hints: LLM_HOST_HINTS,
            sample_cap: SAMPLE_CAP,
            matches: llmConnections
        },
        log_sources: logSources,
        coverage: {
            sources_available: sourcesAvailable,
            sources_missing: sourcesMissing,
            coverage_note: coverageNoteStr,
            notes: coverageNotes
        }
    }

    gs.print('nowisor ai-discovery-export ' + SCHEMA_VERSION)
    gs.print('pack ' + PACK_VERSION)
    gs.print('Agentic surface present: ' + anyAgenticSurface)
    gs.print('Coverage: ' + coverageNoteStr)
    gs.print('')
    gs.print('---NOWISOR_AIDISCOVERY---')
    gs.print(JSON.stringify(envelope, null, 2))
})()
