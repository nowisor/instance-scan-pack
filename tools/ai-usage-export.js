// Read-only: safe for production use
//
// nowisor ai-usage-export tool v1.0.0 - emits ai-usage schema v1
// Paste-into-Background-Script companion to the ai-agent-security check group.
//
// Sensor #5. Emits, per agentic entity, the PERMISSION ENVELOPE (what the
// entity is allowed to do) and the INVOCATION EVIDENCE (what it was observed
// doing), plus the retention floor of every log source that evidence came from.
// The advisor's agent anchor turns those into one verdict per
// (entity, permission) pair. NO correlation logic and NO verdicts live here -
// this script is a pure sensor, exactly like tools/security-log-export.js.
//
// Output: one JSON envelope to gs.print (schema version: ai-usage v1).
//
// WHY THE RETENTION FLOOR IS NOT OPTIONAL
// The advisor may only emit DORMANT - "this permission is held and never used,
// you can revoke it" - when telemetry spans the whole lookback. That decision
// is made app-side from the earliest_record values below. If this sensor cannot
// establish a floor for a source it reports earliest_record:null, and every
// permission evidenced by that source degrades to UNKNOWN-USAGE rather than
// licensing a revocation on an artifact of log retention.
//
// QUERY BUDGET
// Read-only is not load-free. The sensor stops issuing queries at MAX_QUERIES
// and records what it actually covered in `budget`, including a shortened
// effective_lookback_days. A truncated run is reported, never silently passed
// off as a full one.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object          - name
//   sys_dictionary         - name, element
//   sys_user_has_role      - user, role
//   sys_user_role_contains - verified table (role inheritance)
//   sys_security_acl       - name, operation, active
//   sys_security_acl_role  - sys_security_acl, sys_user_role
//   sys_scope_privilege    - verified table (cross-scope grants)
//   sys_audit              - sys_created_by, sys_created_on
//
// ES5-only (Rhino ES0). ASCII-only, short lines, one statement per line.

(function aiUsageExport() {
    var SCHEMA_VERSION = 'v1'
    var PACK_VERSION = '1.2.0'
    var LOOKBACK_DAYS = 90
    var ROW_CAP = 200
    var MAX_QUERIES = 400
    var ENTITY_CAP = 100

    var queries = 0
    var budgetExhausted = false
    var effectiveLookback = LOOKBACK_DAYS

    var now = new GlideDateTime()
    var generatedAt = now.getValue()
    var windowStart = new GlideDateTime()
    windowStart.addDaysUTC(-LOOKBACK_DAYS)
    var windowStartIso = windowStart.getValue()

    var notes = []

    // Agentic entity sources UNDER TEST, not verified identifiers.
    var AGENT_TABLES = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENT_TABLES.push('sys_cs_topic')
    AGENT_TABLES.push('sys_mcp_server')

    // Log sources whose retention floor the advisor needs.
    var LOG_CANDIDATES = ['sn_aia_execution_log']
    LOG_CANDIDATES.push('sn_aia_agent_execution')
    LOG_CANDIDATES.push('sys_cs_conversation')
    LOG_CANDIDATES.push('sys_flow_context')
    LOG_CANDIDATES.push('sys_audit')

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')
    RUNAS_HINTS.push('caller')

    var NAME_HINTS = ['name', 'label', 'title']

    var TOOLPKG_HINTS = ['tool_package', 'tools', 'scope']
    TOOLPKG_HINTS.push('operations')

    // ---- budget-aware helpers ----------------------------------------------

    function spend() {
        queries = queries + 1
        if (queries >= MAX_QUERIES) {
            budgetExhausted = true
        }
        return !budgetExhausted
    }

    function tableExists(tableName) {
        if (budgetExhausted) return false
        spend()
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

    function fieldsOf(tableName) {
        var have = {}
        if (budgetExhausted) return have
        spend()
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', tableName)
            d.addQuery('element', '!=', '')
            d.setLimit(ROW_CAP)
            d.query()
            while (d.next()) {
                var el = d.getValue('element')
                if (el) have[el] = true
            }
        } catch (e) {
            notes.push('field probe failed: ' + tableName)
        }
        return have
    }

    function pick(have, hints) {
        for (var i = 0; i < hints.length; i++) {
            if (have[hints[i]]) return hints[i]
        }
        return null
    }

    // Earliest record on a source = the retention floor the advisor compares
    // against the window. null means "unknown", which is NOT the same as "old".
    function earliestRecord(tableName) {
        if (budgetExhausted) return null
        spend()
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

    function countRows(tableName) {
        if (budgetExhausted) return -1
        spend()
        try {
            var gr = new GlideRecord(tableName)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n = n + 1
            return n
        } catch (e) {
            return -1
        }
    }

    // ---- permission envelope ------------------------------------------------

    // Roles held by an identity, with lineage. granted_by present => an explicit
    // grant record exists. Absent => inherited or OOB; the advisor caps those at
    // CONDITIONAL unless a COMPLETE inheritance chain is supplied below.
    function rolesOf(userId) {
        var out = []
        if (budgetExhausted) return out
        spend()
        try {
            var gr = new GlideRecord('sys_user_has_role')
            gr.addQuery('user', userId)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                var rn = gr.getDisplayValue('role')
                if (!rn) continue
                var row = {}
                row.role = String(rn)
                row.role_id = gr.getValue('role')
                var gb = null
                try {
                    gb = gr.getValue('granted_by')
                } catch (e2) {
                    gb = null
                }
                row.granted_by = gb ? String(gb) : null
                row.lineage = gb ? 'explicit_grant' : 'derived_or_oob'
                out.push(row)
            }
        } catch (e) {
            notes.push('role read failed for identity')
        }
        return out
    }

    // Walk sys_user_role_contains upward from a role. Returns the chain AND
    // whether the walk reached a root without hitting the depth cap - the
    // advisor only auto-resolves a CONDITIONAL when the chain is COMPLETE.
    function inheritanceChain(roleId, roleName) {
        var chain = [roleName]
        var complete = true
        var seen = {}
        seen[roleId] = true
        var frontier = [roleId]
        var depth = 0
        var MAX_DEPTH = 6
        while (frontier.length > 0) {
            if (depth >= MAX_DEPTH) {
                complete = false
                break
            }
            if (budgetExhausted) {
                complete = false
                break
            }
            var next = []
            for (var i = 0; i < frontier.length; i++) {
                spend()
                try {
                    var gr = new GlideRecord('sys_user_role_contains')
                    gr.addQuery('contains', frontier[i])
                    gr.setLimit(25)
                    gr.query()
                    while (gr.next()) {
                        var parentId = gr.getValue('role')
                        if (!parentId || seen[parentId]) continue
                        seen[parentId] = true
                        var pn = gr.getDisplayValue('role')
                        chain.push(pn ? String(pn) : parentId)
                        next.push(parentId)
                    }
                } catch (e) {
                    complete = false
                }
            }
            frontier = next
            depth = depth + 1
        }
        return { chain: chain, complete: complete }
    }

    // Tables a role can write, from active write ACLs referencing that role.
    function writeTablesForRole(roleId) {
        var tables = []
        var seen = {}
        if (budgetExhausted) return tables
        spend()
        try {
            var ar = new GlideRecord('sys_security_acl_role')
            ar.addQuery('sys_user_role', roleId)
            ar.setLimit(ROW_CAP)
            ar.query()
            var aclIds = []
            while (ar.next()) {
                var aid = ar.getValue('sys_security_acl')
                if (aid) aclIds.push(aid)
            }
            for (var i = 0; i < aclIds.length && i < 50; i++) {
                if (budgetExhausted) break
                spend()
                var acl = new GlideRecord('sys_security_acl')
                if (!acl.get(aclIds[i])) continue
                if (acl.getValue('operation') !== 'write') continue
                if (acl.getValue('active') !== '1') continue
                var nm = acl.getValue('name')
                if (!nm) continue
                var tbl = String(nm).split('.')[0]
                if (tbl && !seen[tbl]) {
                    seen[tbl] = true
                    tables.push(tbl)
                }
            }
        } catch (e) {
            notes.push('ACL reach probe failed')
        }
        return tables
    }

    function crossScopeGrants(scopeName) {
        var out = []
        if (!scopeName) return out
        if (!tableExists('sys_scope_privilege')) return out
        if (budgetExhausted) return out
        spend()
        try {
            var gr = new GlideRecord('sys_scope_privilege')
            gr.addQuery('source_scope', scopeName)
            gr.setLimit(50)
            gr.query()
            while (gr.next()) {
                var row = {}
                row.target = gr.getValue('target_name') || gr.getValue('target_scope') || ''
                row.operation = gr.getValue('operation') || ''
                row.status = gr.getValue('status') || ''
                out.push(row)
            }
        } catch (e) {
            notes.push('cross-scope probe failed')
        }
        return out
    }

    // ---- invocation evidence ------------------------------------------------
    // Attributed by run-as identity within the window. The sensor reports COUNTS
    // per source; matching a count to a specific permission is the advisor's job.
    function invocationsFor(userName, sourceTable) {
        if (!userName) return null
        if (!tableExists(sourceTable)) return null
        if (budgetExhausted) return null
        spend()
        try {
            var gr = new GlideRecord(sourceTable)
            gr.addQuery('sys_created_by', userName)
            gr.addQuery('sys_created_on', '>=', windowStartIso)
            gr.orderByDesc('sys_created_on')
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            var last = null
            while (gr.next()) {
                n = n + 1
                if (last === null) last = gr.getValue('sys_created_on')
            }
            if (n === 0) return null
            var out = {}
            out.source = sourceTable
            out.count = n
            out.last_seen = last
            return out
        } catch (e) {
            return null
        }
    }

    // ---- log sources --------------------------------------------------------
    var logSources = []
    var primaryLogSource = null
    // Per-source completeness. The run-level budget flag cannot say WHICH table
    // was cut short, and the advisor needs that: a budget that died harvesting
    // the fourth candidate says nothing about the first three, whose rows are
    // already in hand. Sources probed before exhaustion keep their coverage.
    //
    // The truncation VERDICT is deliberately not stamped here. This loop runs
    // before the entity harvest, and the entity harvest is where the budget
    // actually runs out - so a flag written now is a snapshot that goes stale.
    // It was emitted as truncated:false while the run-level flag said
    // exhausted:true, and the advisor believed the optimistic half and issued a
    // revocation from a truncated run. Only the probe-time fact is recorded
    // here; stampLogSourceTruncation() below finishes the job post-harvest.
    for (var li = 0; li < LOG_CANDIDATES.length; li++) {
        var lt = LOG_CANDIDATES[li]
        var truncatedBefore = budgetExhausted
        var entry = {}
        entry.table = lt
        entry.present = tableExists(lt)
        entry.earliest_record = null
        entry.row_count = -1
        if (entry.present) {
            entry.earliest_record = earliestRecord(lt)
            entry.row_count = countRows(lt)
            if (primaryLogSource === null && lt !== 'sys_audit') {
                primaryLogSource = lt
            }
            if (!entry.earliest_record) {
                notes.push('no retention floor for ' + lt)
            }
        }
        // Probe-time fact only. Not the final verdict - see the note above.
        entry.truncated_at_probe = truncatedBefore || budgetExhausted
        logSources.push(entry)
    }
    if (primaryLogSource === null) primaryLogSource = 'sys_audit'

    // ---- entities -----------------------------------------------------------
    var entities = []
    for (var ai = 0; ai < AGENT_TABLES.length; ai++) {
        var atbl = AGENT_TABLES[ai]
        if (!tableExists(atbl)) continue
        var have = fieldsOf(atbl)
        var runF = pick(have, RUNAS_HINTS)
        var nameF = pick(have, NAME_HINTS)
        var pkgF = pick(have, TOOLPKG_HINTS)
        if (budgetExhausted) break

        spend()
        try {
            var gr2 = new GlideRecord(atbl)
            gr2.setLimit(ENTITY_CAP)
            gr2.query()
            while (gr2.next()) {
                if (budgetExhausted) break
                var ent = {}
                ent.entity_id = gr2.getUniqueValue()
                ent.entity_kind = atbl === 'sys_mcp_server'
                    ? 'inbound_agent_surface'
                    : 'ai_agent_use_case'
                ent.name = nameF ? gr2.getValue(nameF) : null
                ent.source_table = atbl
                ent.run_as = runF ? gr2.getValue(runF) : null
                ent.run_as_display = runF ? (gr2.getDisplayValue(runF) || null) : null
                ent.permissions = []
                ent.invocations = []

                var scope = null
                try {
                    scope = gr2.getValue('sys_scope')
                } catch (e3) {
                    scope = null
                }

                // roles -> permissions (with inheritance chain + ACL reach)
                if (ent.run_as) {
                    var roles = rolesOf(ent.run_as)
                    for (var ri = 0; ri < roles.length; ri++) {
                        var r = roles[ri]
                        var wt = writeTablesForRole(r.role_id)
                        var perm = {}
                        perm.kind = 'role'
                        perm.id = r.role
                        perm.label = r.role
                        perm.write = wt.length > 0
                        perm.tables = wt
                        perm.lineage = r.lineage
                        perm.evidence_source = primaryLogSource
                        if (r.lineage !== 'explicit_grant') {
                            var chain = inheritanceChain(r.role_id, r.role)
                            perm.lineage_path = chain.chain
                            perm.lineage_complete = chain.complete
                            perm.source_artifact = 'role contains: ' + chain.chain.join(' -> ')
                        }
                        ent.permissions.push(perm)
                    }
                }

                // cross-scope privileges
                var xs = crossScopeGrants(scope)
                for (var xi = 0; xi < xs.length; xi++) {
                    var xperm = {}
                    xperm.kind = 'cross_scope'
                    xperm.id = 'xscope:' + xs[xi].target
                    xperm.label = scope + ' -> ' + xs[xi].target
                    xperm.write = String(xs[xi].operation) === 'write'
                    xperm.tables = [xs[xi].target]
                    xperm.lineage = 'derived_or_oob'
                    xperm.lineage_complete = false
                    xperm.evidence_source = primaryLogSource
                    xperm.source_artifact = 'sys_scope_privilege: ' + scope
                    ent.permissions.push(xperm)
                }

                // MCP tool package
                if (pkgF) {
                    var pkgVal = gr2.getValue(pkgF)
                    if (pkgVal) {
                        var lower = String(pkgVal).toLowerCase()
                        var isWrite = false
                        if (lower.indexOf('write') !== -1) isWrite = true
                        if (lower.indexOf('all') !== -1) isWrite = true
                        if (lower.indexOf('admin') !== -1) isWrite = true
                        var mperm = {}
                        mperm.kind = 'mcp_tool_package'
                        mperm.id = 'toolpkg:' + pkgVal
                        mperm.label = String(pkgVal)
                        mperm.write = isWrite
                        mperm.tables = isWrite ? ['*'] : []
                        mperm.lineage = 'explicit_grant'
                        mperm.evidence_source = primaryLogSource
                        ent.permissions.push(mperm)
                    }
                }

                // invocation evidence, attributed by run-as identity
                if (ent.run_as_display) {
                    for (var gi = 0; gi < logSources.length; gi++) {
                        if (!logSources[gi].present) continue
                        var inv = invocationsFor(ent.run_as_display, logSources[gi].table)
                        if (!inv) continue
                        // Attribute the observed activity to every permission
                        // evidenced by that source. The advisor decides what a
                        // count means; this sensor only reports it.
                        for (var pi = 0; pi < ent.permissions.length; pi++) {
                            if (ent.permissions[pi].evidence_source !== inv.source) continue
                            var rec = {}
                            rec.permission_id = ent.permissions[pi].id
                            rec.source = inv.source
                            rec.count = inv.count
                            rec.last_seen = inv.last_seen
                            ent.invocations.push(rec)
                        }
                    }
                }

                entities.push(ent)
            }
        } catch (e) {
            notes.push('entity harvest failed: ' + atbl)
        }
    }

    // ---- log-source truncation, stamped POST-HARVEST ------------------------
    // Runs after the entity loop above, because that loop is what spends the
    // budget. Invocation evidence for every log source is gathered there, so if
    // the budget died during the harvest then EVERY source's evidence is short -
    // regardless of how complete it looked when it was first probed.
    for (var si = 0; si < logSources.length; si++) {
        var se = logSources[si]
        se.truncated = se.truncated_at_probe || budgetExhausted
        se.effective_lookback_days = se.truncated ? 0 : LOOKBACK_DAYS
        delete se.truncated_at_probe
        if (se.truncated) {
            notes.push('query budget exhausted - ' + se.table + ' evidence is partial')
        }
    }

    // ---- envelope -----------------------------------------------------------
    if (budgetExhausted) {
        notes.push('query budget exhausted - coverage is partial')
        effectiveLookback = 0
    }

    var permCount = 0
    for (var ei = 0; ei < entities.length; ei++) {
        permCount = permCount + entities[ei].permissions.length
    }

    var noteParts = []
    noteParts.push(entities.length + ' entities')
    noteParts.push(permCount + ' permissions')
    noteParts.push(queries + '/' + MAX_QUERIES + ' queries')
    if (notes.length) noteParts.push(notes.join('; '))
    var coverageNoteStr = noteParts.join(' - ')

    var envelope = {
        nowisor_aiusage_schema: SCHEMA_VERSION,
        pack_version: PACK_VERSION,
        generated_at: generatedAt,
        window: {
            lookback_days: LOOKBACK_DAYS,
            start: windowStartIso,
            end: generatedAt
        },
        budget: {
            max_queries: MAX_QUERIES,
            queries_used: queries,
            exhausted: budgetExhausted,
            effective_lookback_days: effectiveLookback,
            row_cap: ROW_CAP,
            entity_cap: ENTITY_CAP
        },
        log_sources: logSources,
        entities: entities,
        coverage: {
            coverage_note: coverageNoteStr,
            notes: notes
        }
    }

    gs.print('nowisor ai-usage-export ' + SCHEMA_VERSION)
    gs.print('pack ' + PACK_VERSION)
    gs.print('Entities: ' + entities.length + ' Permissions: ' + permCount)
    gs.print('Coverage: ' + coverageNoteStr)
    gs.print('')
    gs.print('---NOWISOR_AIUSAGE---')
    gs.print(JSON.stringify(envelope, null, 2))
})()
