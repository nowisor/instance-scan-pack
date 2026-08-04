// Read-only: safe for production use
//
// nowisor ai-bom-export tool v1.0.0 - emits ai-bom schema v1
// Paste-into-Background-Script sensor for the ai-agent-security category.
//
// Sensor #4. Emits one record per agentic entity: Now Assist / AI Agent use
// cases, conversational agents, LLM-backed VA topics, Gen AI definitions,
// external LLM connections, and inbound external agents arriving over MCP /
// Action Fabric. The advisor assembles ai_bom.json plus a CycloneDX export
// from this envelope. NO verdicts here - this script is a pure sensor.
//
// Output: one JSON envelope to gs.print (schema version: ai-bom v1).
//
// THE CENTRAL HONESTY RULE OF THIS SENSOR
// Every attribute is emitted with a resolution state, never a bare value:
//   'set'        - the field exists on this release AND carries a value
//   'empty'      - the field exists AND is genuinely blank  -> a real finding
//   'unresolved' - no such field on this release            -> N/A, NOT a finding
// AIA-001 (unowned agents) is only allowed to fire on 'empty'. Firing on
// 'unresolved' would report every agent on every release where the owner field
// happens to be named differently - an over-claim that destroys credibility
// with exactly the buyer this module targets. Same discipline as AIA-004.
//
// Field names are DISCOVERED from sys_dictionary and matched against hint
// lists; the hints are search patterns, not identifier claims. The envelope
// records which field actually supplied each attribute (`*_field`) so a
// reviewer can audit every value back to a real column.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object   - name, label
//   sys_dictionary  - name, element, internal_type
//   sn_aia_use_case - active, execution_mode
//   sys_cb_ai_agent - existence only (zero fields verified)
//
// ES5-only (Rhino ES0). ASCII-only, short lines, one statement per line.

(function aiBomExport() {
    var SCHEMA_VERSION = 'v1'
    var PACK_VERSION = '1.2.0'
    var ENTITY_CAP = 200
    var FIELD_CAP = 200

    var now = new GlideDateTime()
    var generatedAt = now.getValue()

    var notes = []
    var entities = []
    var scanned = []

    // Attribute hint lists. First match in sys_dictionary wins; the chosen
    // column is reported so every value is auditable.
    var NAME_HINTS = ['name', 'label', 'title']
    NAME_HINTS.push('short_description')

    var OWNER_HINTS = ['owner', 'owned_by', 'assigned_to']
    OWNER_HINTS.push('managed_by')
    OWNER_HINTS.push('owner_group')

    var STATE_HINTS = ['lifecycle_state', 'state', 'status']
    STATE_HINTS.push('active')

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')
    RUNAS_HINTS.push('caller')

    var REVIEW_HINTS = ['last_review', 'last_reviewed']
    REVIEW_HINTS.push('last_review_date')
    REVIEW_HINTS.push('sys_updated_on')

    var SCOPE_HINTS = ['sys_scope', 'scope']

    // Entity-type sources. Candidate table names UNDER TEST, not claims.
    var ENTITY_SOURCES = [
        { table: 'sn_aia_use_case', kind: 'ai_agent_use_case' },
        { table: 'sys_cb_ai_agent', kind: 'ai_agent' },
        { table: 'sys_cb_topic', kind: 'va_topic' },
        { table: 'sys_cs_topic', kind: 'va_topic' },
        { table: 'sn_gen_ai_capability', kind: 'gen_ai_capability' },
        {
            table: 'sys_generative_ai_definition',
            kind: 'gen_ai_definition'
        },
        {
            table: 'sys_one_extend_capability',
            kind: 'one_extend_capability'
        },
        { table: 'sys_mcp_server', kind: 'inbound_agent_surface' },
        { table: 'sys_mcp_tool_package', kind: 'inbound_tool_package' },
        { table: 'sn_mcp_tool_package', kind: 'inbound_tool_package' }
    ]

    // ---- helpers ---------------------------------------------------------

    // ES5 has no Object.hasOwn; keep the guard short so lines stay unwrapped.
    function hasOwn(obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key)
    }

    // sys_db_object first, GR probe as fallback. NOT
    // GlideTableDescriptor.isValid(), which returned false for real tables on
    // dev265147 2026-05-22 (ff40848 Section A).
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

    function fieldSet(tableName) {
        var map = {}
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', tableName)
            d.addQuery('element', '!=', '')
            d.setLimit(FIELD_CAP)
            d.query()
            while (d.next()) {
                var el = d.getValue('element')
                if (el) map[el] = d.getValue('internal_type') || ''
            }
        } catch (e) {
            notes.push('field probe failed: ' + tableName)
        }
        return map
    }

    // Pick the first hint that is a real column on this table.
    function pickField(fields, hints) {
        for (var i = 0; i < hints.length; i++) {
            var h = hints[i]
            if (hasOwn(fields, h)) return h
        }
        return null
    }

    // The honesty primitive: value + resolution state + source column.
    function attr(gr, fieldName) {
        var out = {}
        out.field = fieldName
        if (!fieldName) {
            out.state = 'unresolved'
            out.value = null
            return out
        }
        var raw = null
        try {
            raw = gr.getValue(fieldName)
        } catch (e) {
            out.state = 'unresolved'
            out.value = null
            return out
        }
        if (raw === null || String(raw) === '') {
            out.state = 'empty'
            out.value = null
            return out
        }
        out.state = 'set'
        out.value = String(raw)
        return out
    }

    // Display value for a reference field, best-effort and never fatal.
    function refLabel(gr, fieldName) {
        if (!fieldName) return null
        try {
            var dv = gr.getDisplayValue(fieldName)
            if (dv && String(dv) !== '') return String(dv)
        } catch (e) {
            return null
        }
        return null
    }

    // ---- entity harvest ------------------------------------------------------
    for (var si = 0; si < ENTITY_SOURCES.length; si++) {
        var src = ENTITY_SOURCES[si]
        if (!tableExists(src.table)) continue

        var fields = fieldSet(src.table)
        var nameF = pickField(fields, NAME_HINTS)
        var ownerF = pickField(fields, OWNER_HINTS)
        var stateF = pickField(fields, STATE_HINTS)
        var runasF = pickField(fields, RUNAS_HINTS)
        var reviewF = pickField(fields, REVIEW_HINTS)
        var scopeF = pickField(fields, SCOPE_HINTS)

        var scanRow = {}
        scanRow.table = src.table
        scanRow.kind = src.kind
        scanRow.field_map = {
            name: nameF,
            owner: ownerF,
            state: stateF,
            run_as: runasF,
            last_review: reviewF,
            scope: scopeF
        }
        scanRow.field_count = 0
        for (var k in fields) {
            if (hasOwn(fields, k)) {
                scanRow.field_count = scanRow.field_count + 1
            }
        }
        scanned.push(scanRow)

        var capped = false
        try {
            var gr = new GlideRecord(src.table)
            gr.setLimit(ENTITY_CAP)
            gr.query()
            var seen = 0
            while (gr.next()) {
                seen = seen + 1
                var ent = {}
                ent.entity_id = gr.getUniqueValue()
                ent.entity_kind = src.kind
                ent.source_table = src.table
                ent.name = attr(gr, nameF)
                ent.owner = attr(gr, ownerF)
                ent.owner_display = refLabel(gr, ownerF)
                ent.lifecycle_state = attr(gr, stateF)
                ent.run_as = attr(gr, runasF)
                ent.run_as_display = refLabel(gr, runasF)
                ent.last_review = attr(gr, reviewF)
                ent.scope = attr(gr, scopeF)
                ent.scope_display = refLabel(gr, scopeF)
                ent.created_by = attr(gr, 'sys_created_by')
                ent.created_on = attr(gr, 'sys_created_on')
                ent.updated_on = attr(gr, 'sys_updated_on')
                // Only sn_aia_use_case has execution_mode as a verified field.
                var emField = null
                if (hasOwn(fields, 'execution_mode')) {
                    emField = 'execution_mode'
                }
                ent.execution_mode = attr(gr, emField)
                entities.push(ent)
            }
            if (seen >= ENTITY_CAP) capped = true
        } catch (e) {
            notes.push('entity harvest failed: ' + src.table)
        }
        scanRow.capped = capped
        if (capped) {
            notes.push('entity cap hit on ' + src.table)
        }
    }

    // ---- governance registry cross-reference --------------------------------
    // Names present in a sanctioned catalog, so the advisor can compute the
    // registration gap (AIA-009 / the planted-agent POC). Facts only: we emit
    // the registry contents, not the diff.
    var REGISTRY_CANDIDATES = [
        'sn_ai_control_tower_asset',
        'sn_aic_ai_asset',
        'sn_ai_registry'
    ]
    var registry = {}
    registry.table = null
    registry.available = false
    registry.entries = []
    for (var ri = 0; ri < REGISTRY_CANDIDATES.length; ri++) {
        var rname = REGISTRY_CANDIDATES[ri]
        if (!tableExists(rname)) continue
        var rfields = fieldSet(rname)
        var rNameF = pickField(rfields, NAME_HINTS)
        registry.table = rname
        registry.available = true
        registry.name_field = rNameF
        try {
            var rgr = new GlideRecord(rname)
            rgr.setLimit(ENTITY_CAP)
            rgr.query()
            while (rgr.next()) {
                var rent = {}
                rent.registry_id = rgr.getUniqueValue()
                rent.name = attr(rgr, rNameF)
                registry.entries.push(rent)
            }
        } catch (e) {
            notes.push('registry read failed: ' + rname)
        }
        break
    }
    if (!registry.available) {
        notes.push('no sanctioned AI registry table on this instance')
    }

    // ---- envelope -----------------------------------------------------------
    var unresolvedOwner = 0
    var emptyOwner = 0
    for (var ei = 0; ei < entities.length; ei++) {
        var st = entities[ei].owner.state
        if (st === 'unresolved') unresolvedOwner = unresolvedOwner + 1
        if (st === 'empty') emptyOwner = emptyOwner + 1
    }

    var noteParts = []
    noteParts.push(entities.length + ' agentic entities harvested')
    noteParts.push(scanned.length + ' source tables resolved')
    if (unresolvedOwner > 0) {
        noteParts.push(unresolvedOwner + ' entities: no owner FIELD (N/A)')
    }
    if (notes.length) {
        noteParts.push(notes.join('; '))
    }
    var coverageNoteStr = noteParts.join(' - ')

    var envelope = {
        nowisor_aibom_schema: SCHEMA_VERSION,
        pack_version: PACK_VERSION,
        generated_at: generatedAt,
        entity_cap: ENTITY_CAP,
        entity_count: entities.length,
        sources_scanned: scanned,
        entities: entities,
        governance_registry: registry,
        owner_resolution: {
            unresolved_field: unresolvedOwner,
            empty_value: emptyOwner
        },
        coverage: {
            coverage_note: coverageNoteStr,
            notes: notes
        }
    }

    gs.print('nowisor ai-bom-export ' + SCHEMA_VERSION)
    gs.print('pack ' + PACK_VERSION)
    gs.print('Entities: ' + entities.length)
    gs.print('Coverage: ' + coverageNoteStr)
    gs.print('')
    gs.print('---NOWISOR_AIBOM---')
    gs.print(JSON.stringify(envelope, null, 2))
})()
