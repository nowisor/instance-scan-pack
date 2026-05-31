// Read-only: safe for production use
//
// nowisor security-log-export tool v1.0.0 — emits log-export schema v1
// Paste-into-Background-Script companion to the 27 nowisor scan checks.
//
// Twin sensor #2: this tool emits runtime-activity records (sys_audit, sysevent
// discovery, syslog_transaction aggregated by user) over a configurable lookback
// window. The output envelope is consumed by the nowisor advisor's correlation
// engine alongside scan_finding metadata blocks. NO correlation logic lives here —
// this script is a pure sensor.
//
// Output: one JSON envelope to gs.print (schema version: log-export v1).
// Schema and L2-reserved keys documented in README §Log-export schema v1.
//
// Verified identifiers (Zurich Patch 6, dev265484; verified_schema sources):
//   sys_audit                — tablename, documentkey, fieldname, oldvalue, newvalue,
//                              sys_created_by, sys_created_on
//   sys_security_acl         — verified table
//   sys_user_has_role        — verified table
//   sys_properties           — name, value (audit metadata via sys_audit join)
//   syslog_transaction       — sys_created_on, sys_created_by, type, url,
//                              response_time, output_length (all PDI-verified on
//                              dev265147 2026-05-22; the NCF-catalog claim of
//                              'created' and 'response_size' was fabricated and
//                              has been scrubbed from verified_schema)
//   sys_dictionary           — audit field (for the table-level audit flag)
//
// L2 columns (NOT emitted in v1; verification gate before unlock):
//   syslog_transaction.remote_ip, syslog_transaction.user_agent — VERIFIED on
//     dev265147 (2026-05-22, internal_type=string each, see ff40848 + the
//     2026-05-22 section of fabricated-props-resolution-log.md). Schema-version
//     bump to v1.1 deferred — the app-side parser in vsme-app/lib/scan-pack-parser.js
//     must learn the L2 keys at the same time. Reserve the keys, do not emit yet.
//   sys_audit join → owning_job for property toggles — pending L2 enrichment
//
// L1.1 reserved key (NOT emitted in v1):
//   script_exec_history — needed to convert linter-NOISE rationale from static-scope
//   to runtime-non-execution. Reserve the key; do not build it now.

(function securityLogExport() {
    var LOOKBACK_DAYS = 7
    var ROW_CAP = 300
    var TOP_USERS_LIMIT = 25
    var SCHEMA_VERSION = 'v1'
    var PACK_VERSION = '1.0.0'

    var now = new GlideDateTime()
    var start = new GlideDateTime()
    start.addDaysUTC(-LOOKBACK_DAYS)

    var generatedAt = now.getValue()
    var startIso = start.getValue()
    var endIso = now.getValue()

    // Tables we expect to be present and queryable. coverage_note reports the
    // delta between expected and observed so downstream correlation can qualify
    // any DORMANT verdict by the source set actually available.
    var EXPECTED_SOURCES = ['sys_audit', 'sysevent', 'syslog_transaction']
    var sourcesAvailable = []
    var sourcesMissing = []
    var coverageNotes = []

    // ---- Layer-1 gate helper: returns true only if the table is queryable -----
    // Primary signal: sys_db_object row exists for the table. This is the
    // canonical table-metadata record and beats GlideTableDescriptor.isValid(),
    // which returned false for sys_audit / syslog_transaction / sysevent on
    // dev265147 (2026-05-22, see ff40848 Section A) despite every field being
    // present in sys_dictionary — using it as the primary signal here would
    // cause the script to emit an empty envelope on every Zurich instance.
    // GR-query last-resort fallback covers views/aliases without sys_db_object.
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

    // ---- sys_audit (security-critical tables) --------------------------------
    var sysAuditPayload = {
        schema_note:
            'Verified Zurich fields: tablename, documentkey, fieldname, oldvalue, ' +
            'newvalue, sys_created_by, sys_created_on. ' +
            'documentkey_name (additive) resolves sys_properties documentkey→name ' +
            'so the correlation engine can match a property finding to its toggle.',
        row_count: 0,
        cap_hit: false,
        filter:
            "tablename IN ('sys_user_has_role','sys_security_acl','sys_properties') " +
            'AND sys_created_on >= window.start',
        rows: [],
    }
    if (!tableExists('sys_audit')) {
        sourcesMissing.push('sys_audit')
        coverageNotes.push('sys_audit table not queryable on this instance')
    } else {
        sourcesAvailable.push('sys_audit')
        var auditedTables = ['sys_user_has_role', 'sys_security_acl', 'sys_properties']
        var auditRows = []
        var auditCount = 0
        try {
            var ar = new GlideRecord('sys_audit')
            ar.addQuery('tablename', 'IN', auditedTables.join(','))
            ar.addQuery('sys_created_on', '>=', startIso)
            ar.orderByDesc('sys_created_on')
            // ROW_CAP + 1 so a 301st row trips the cap_hit detection in the loop.
            // setLimit(ROW_CAP) alone would mean the cursor stops at exactly ROW_CAP
            // rows and the >= check never fires, leaving cap_hit structurally false.
            ar.setLimit(ROW_CAP + 1)
            ar.query()
            while (ar.next()) {
                auditCount++
                if (auditRows.length >= ROW_CAP) {
                    sysAuditPayload.cap_hit = true
                    break
                }
                auditRows.push({
                    tablename: ar.getValue('tablename'),
                    documentkey: ar.getValue('documentkey'),
                    fieldname: ar.getValue('fieldname'),
                    oldvalue: ar.getValue('oldvalue'),
                    newvalue: ar.getValue('newvalue'),
                    sys_created_by: ar.getValue('sys_created_by'),
                    sys_created_on: ar.getValue('sys_created_on'),
                })
            }
        } catch (e) {
            coverageNotes.push('sys_audit query partial: ' + (e && e.message))
        }
        // Resolve sys_properties documentkeys → property name. sys_audit stores the
        // property record's sys_id in documentkey, never the property name, so without
        // this join the correlation engine cannot tie a property finding (keyed by
        // name) to its toggle event. One batched read; read-only, safe for production.
        var propSysIds = []
        for (var pi = 0; pi < auditRows.length; pi++) {
            if (auditRows[pi].tablename === 'sys_properties' && auditRows[pi].documentkey) {
                propSysIds.push(auditRows[pi].documentkey)
            }
        }
        if (propSysIds.length) {
            try {
                var nameById = {}
                var pr = new GlideRecord('sys_properties')
                pr.addQuery('sys_id', 'IN', propSysIds.join(','))
                pr.query()
                while (pr.next()) { nameById[pr.getUniqueValue()] = pr.getValue('name') }
                for (var pj = 0; pj < auditRows.length; pj++) {
                    if (auditRows[pj].tablename === 'sys_properties') {
                        auditRows[pj].documentkey_name = nameById[auditRows[pj].documentkey] || null
                    }
                }
            } catch (pe) {
                coverageNotes.push('sys_properties name-resolve partial: ' + (pe && pe.message))
            }
        }
        sysAuditPayload.row_count = auditCount
        sysAuditPayload.rows = auditRows
    }

    // ---- sysevent (auth/security family — discovery, never hardcoded) --------
    // Canonical sysevent table is NOT present on Zurich PDI; only sysevent_register
    // and sysevent_email_action exist. We probe a name-LIKE catalog so the
    // correlation engine sees what's actually queryable rather than assuming.
    var sysEventPayload = {
        discovery: { method: "table-name probe ('sysevent', 'sysevent_register', 'sysevent_email_action')", tables_present: [] },
        schema_note:
            'Canonical sysevent table not in verified schema on Zurich. Discovery emits ' +
            'which sysevent-family tables actually exist on this instance.',
        row_count: 0,
        cap_hit: false,
        rows: [],
    }
    var sysEventCandidates = ['sysevent', 'sysevent_register', 'sysevent_email_action']
    for (var i = 0; i < sysEventCandidates.length; i++) {
        if (tableExists(sysEventCandidates[i])) {
            sysEventPayload.discovery.tables_present.push(sysEventCandidates[i])
        }
    }
    if (sysEventPayload.discovery.tables_present.length === 0) {
        sourcesMissing.push('sysevent')
        coverageNotes.push('no sysevent-family tables queryable')
    } else if (sysEventPayload.discovery.tables_present.indexOf('sysevent') === -1) {
        // Auxiliary tables exist but the canonical event log doesn't — treat as missing
        sourcesMissing.push('sysevent')
        coverageNotes.push(
            'canonical sysevent table absent; only ' +
                sysEventPayload.discovery.tables_present.join(', ') +
                ' present — runtime auth/security events not capturable'
        )
    } else {
        sourcesAvailable.push('sysevent')
        try {
            var er = new GlideRecord('sysevent')
            // name LIKE pattern — discover whatever event family this instance emits.
            // Do not hardcode event names: their existence varies across plugins.
            er.addQuery('name', 'STARTSWITH', 'login')
            var nameOR = er.addOrCondition('name', 'STARTSWITH', 'security')
            nameOR.addOrCondition('name', 'STARTSWITH', 'auth')
            er.addQuery('sys_created_on', '>=', startIso)
            er.orderByDesc('sys_created_on')
            er.setLimit(ROW_CAP + 1)
            er.query()
            var eventCount = 0
            var eventRows = []
            while (er.next()) {
                eventCount++
                if (eventRows.length >= ROW_CAP) {
                    sysEventPayload.cap_hit = true
                    break
                }
                eventRows.push({
                    name: er.getValue('name'),
                    sys_created_on: er.getValue('sys_created_on'),
                    parm1: er.getValue('parm1'),
                    parm2: er.getValue('parm2'),
                })
            }
            sysEventPayload.row_count = eventCount
            sysEventPayload.rows = eventRows
        } catch (e) {
            coverageNotes.push('sysevent query partial: ' + (e && e.message))
        }
    }

    // ---- syslog_transaction (aggregated, top-25 by user) ---------------------
    // v1 emits ONLY verified columns: created, response_size, type, url.
    // L2 columns (remote_ip, user_agent) are blocked until PDI verification.
    var sysLogPayload = {
        schema_note:
            'PDI-verified columns on dev265147 2026-05-22: sys_created_on, ' +
            'sys_created_by, type, url, response_time, output_length, remote_ip, ' +
            'user_agent. L2 columns (remote_ip, user_agent) verified populated ' +
            'but reserved for the v1.1 schema bump — app-side parser must learn ' +
            'the keys before the pack emits them. The NCF-catalog "created" and ' +
            '"response_size" fields were fabricated and have been scrubbed.',
        aggregation: 'group_by_user_top_' + TOP_USERS_LIMIT,
        row_count: 0,
        cap_hit: false,
        rows: [],
    }
    if (!tableExists('syslog_transaction')) {
        sourcesMissing.push('syslog_transaction')
        coverageNotes.push('syslog_transaction table not queryable')
    } else {
        sourcesAvailable.push('syslog_transaction')
        try {
            var agg = new GlideAggregate('syslog_transaction')
            agg.addQuery('sys_created_on', '>=', startIso)
            agg.addAggregate('COUNT')
            agg.groupBy('sys_created_by')
            // orderByAggregate's second argument is a field name, not a direction.
            // The original `'DESC'` argument silently filtered to zero results on
            // dev265147 2026-05-22. COUNT defaults to descending order.
            agg.orderByAggregate('COUNT')
            agg.setLimit(TOP_USERS_LIMIT)
            agg.query()
            var rows = []
            while (agg.next() && rows.length < TOP_USERS_LIMIT) {
                var u = agg.getValue('sys_created_by') || '<empty>'
                var c = parseInt(agg.getAggregate('COUNT'), 10) || 0
                // Pull one sample url + type for the user (read-only, capped)
                var sampleUrl = ''
                var sampleType = ''
                try {
                    var sr = new GlideRecord('syslog_transaction')
                    sr.addQuery('sys_created_by', u)
                    sr.addQuery('sys_created_on', '>=', startIso)
                    sr.orderByDesc('sys_created_on')
                    sr.setLimit(1)
                    sr.query()
                    if (sr.next()) {
                        sampleUrl = sr.getValue('url') || ''
                        sampleType = sr.getValue('type') || ''
                    }
                } catch (e2) {
                    // sample-row probe is non-critical; aggregate is the load-bearing signal
                }
                rows.push({
                    user: u,
                    txn_count: c,
                    url_sample_top1: sampleUrl,
                    type_sample: sampleType,
                })
            }
            sysLogPayload.row_count = rows.length
            sysLogPayload.rows = rows
        } catch (e) {
            coverageNotes.push('syslog_transaction query partial: ' + (e && e.message))
        }
    }

    // ---- build_drift (Console caveat input, not a verdict) -------------------
    var buildtagLast = null
    try {
        var bt = gs.getProperty('glide.buildtag.last', '__NOT_SET__')
        if (bt !== '__NOT_SET__') buildtagLast = bt
    } catch (e) {
        // glide.buildtag.last unverified on Zurich corpus — emit null per plan
    }
    var lastPlugin = null
    try {
        var lp = gs.getProperty('glide.lastplugin', '__NOT_SET__')
        if (lp !== '__NOT_SET__') lastPlugin = lp
    } catch (e) {
        // best-effort
    }
    var thirtyDayStart = new GlideDateTime()
    thirtyDayStart.addDaysUTC(-30)
    var recentPropertyChanges30d = 0
    if (sourcesAvailable.indexOf('sys_audit') !== -1) {
        try {
            var pcAgg = new GlideAggregate('sys_audit')
            pcAgg.addQuery('tablename', 'sys_properties')
            pcAgg.addQuery('sys_created_on', '>=', thirtyDayStart.getValue())
            pcAgg.addAggregate('COUNT')
            pcAgg.query()
            if (pcAgg.next()) {
                recentPropertyChanges30d = parseInt(pcAgg.getAggregate('COUNT'), 10) || 0
            }
        } catch (e) {
            coverageNotes.push('build_drift property-change count failed: ' + (e && e.message))
        }
    }

    // ---- Envelope ------------------------------------------------------------
    var coverageNoteStr =
        sourcesAvailable.length +
        ' of ' +
        EXPECTED_SOURCES.length +
        ' expected L1 sources available' +
        (coverageNotes.length ? ' — ' + coverageNotes.join('; ') : '')

    var envelope = {
        nowisor_logexport_schema: SCHEMA_VERSION,
        pack_version: PACK_VERSION,
        generated_at: generatedAt,
        window: {
            lookback_days: LOOKBACK_DAYS,
            start: startIso,
            end: endIso,
            per_category_cap: ROW_CAP,
        },
        coverage: {
            sources_expected: EXPECTED_SOURCES,
            sources_available: sourcesAvailable,
            sources_missing: sourcesMissing,
            coverage_note: coverageNoteStr,
        },
        build_drift: {
            buildtag_last: buildtagLast,
            lastplugin: lastPlugin,
            recent_property_changes_30d: recentPropertyChanges30d,
        },
        sources: {
            sys_audit: sysAuditPayload,
            sysevent: sysEventPayload,
            syslog_transaction: sysLogPayload,
        },
    }

    // Wrap in the same separator-block convention as scan findings so the
    // Console parser can extract this from a single pasted blob containing
    // both ---NOWISOR_METADATA--- and ---NOWISOR_LOGEXPORT--- markers.
    gs.print('nowisor security-log-export ' + SCHEMA_VERSION + ' (pack ' + PACK_VERSION + ')')
    gs.print('Window: ' + startIso + ' → ' + endIso + ' (' + LOOKBACK_DAYS + ' days)')
    gs.print('Coverage: ' + coverageNoteStr)
    gs.print('')
    gs.print('---NOWISOR_LOGEXPORT---')
    gs.print(JSON.stringify(envelope, null, 2))
})()
