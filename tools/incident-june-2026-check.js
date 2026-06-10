// Read-only: safe for production use
//
// nowisor incident-june-2026-check tool v1.0.0 — emits log-export schema v1.1
// Focused companion to the SN-INCIDENT-2026-06-KB3067321 advisory signature.
//
// WHAT THIS DOES (detection only — it cannot exploit anything):
//   It reads your transaction log (syslog_transaction) for requests to the
//   related-list-edit endpoint that ServiceNow patched on hosted instances on
//   2026-06-05, and emits them as a NOWISOR log-export envelope you paste into
//   the free checker at /servicenow-june-2026-incident. The verdict is computed
//   in your browser from this envelope; nothing is sent to your ServiceNow
//   instance and (in the free checker) your pasted logs never leave your browser.
//
// WHY GUEST ATTRIBUTION MATTERS:
//   The patched endpoint accepted requests with no session. ServiceNow therefore
//   had no authenticated account to attribute them to, so the activity is logged
//   against the built-in Guest user. A Guest-attributed transaction to this
//   endpoint is the primary indicator. This script records sys_created_by per row
//   so you can see the attribution yourself — it does not assume a username.
//
// EXPOSURE WINDOW:
//   Community reporting places earliest-known activity around April 2026, with a
//   high-confidence cluster on 2026-06-02/03, before the 2026-06-05 hosted patch.
//   This script does NOT lower-bound the query by date — it returns every matching
//   row your retention still holds — and it measures the true retention floor so
//   the checker can tell you honestly when your logs do not reach back far enough
//   to rule out pre-patch access (the common, and itself reportable, case).
//
// Verified identifiers (PDI-verified on dev265147 2026-05-22; same provenance as
// security-log-export.js):
//   syslog_transaction — sys_created_on, sys_created_by, type, url, remote_ip
//   sys_db_object      — name (table-presence gate)
//
// NO correlation logic lives here — this is a pure read-only sensor.

(function incidentJune2026Check() {
    // The patched endpoint path fragment. Matching the fragment (not the full
    // '/create' path) catches related_list_edit variants in one query. This is a
    // detection filter only — it contains nothing that could craft a request.
    var ENDPOINT_NEEDLE = '/api/now/related_list_edit'

    var ROW_CAP = 300
    // Earliest-known activity for this incident — used only to label the window in
    // the envelope. The query itself is NOT lower-bounded (we want every row your
    // retention holds); the checker compares this against your true retention floor.
    var WINDOW_START_ISO = '2026-04-01 00:00:00'
    var SCHEMA_VERSION = 'v1.1'
    var PACK_VERSION = '1.0.0'

    var now = new GlideDateTime()
    var generatedAt = now.getValue()

    var EXPECTED_SOURCES = ['syslog_transaction']
    var sourcesAvailable = []
    var sourcesMissing = []
    var coverageNotes = []
    var retentionFloor = null // oldest syslog_transaction row available

    // ---- table-presence gate (sys_db_object beats GlideTableDescriptor on Zurich) ----
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

    // ---- syslog_transaction — endpoint-filtered, per row (NOT aggregated) -------
    var sysLogPayload = {
        schema_note:
            'Per-row export filtered to the patched related-list-edit endpoint. ' +
            'Fields PDI-verified on dev265147 2026-05-22: sys_created_on, ' +
            'sys_created_by, url, remote_ip. user = sys_created_by so the checker ' +
            'can surface Guest attribution without assuming a username.',
        aggregation: 'per_row_endpoint_filtered',
        endpoint_filter: ENDPOINT_NEEDLE,
        row_count: 0,
        cap_hit: false,
        rows: [],
    }

    if (!tableExists('syslog_transaction')) {
        sourcesMissing.push('syslog_transaction')
        coverageNotes.push('syslog_transaction table not queryable on this instance')
    } else {
        sourcesAvailable.push('syslog_transaction')

        // True retention floor: the OLDEST syslog_transaction row, so the checker is
        // honest about whether retention reaches back to the exposure window rather
        // than implying the (short) returned set is the full history.
        try {
            var floor = new GlideRecord('syslog_transaction')
            floor.orderBy('sys_created_on')
            floor.setLimit(1)
            floor.query()
            if (floor.next()) retentionFloor = floor.getValue('sys_created_on')
        } catch (e) {
            coverageNotes.push('syslog_transaction retention-floor probe failed: ' + (e && e.message))
        }

        // The load-bearing read: every transaction to the patched endpoint your
        // retention still holds. No date lower bound — capture all of it.
        try {
            var tr = new GlideRecord('syslog_transaction')
            tr.addQuery('url', 'CONTAINS', ENDPOINT_NEEDLE)
            tr.orderByDesc('sys_created_on')
            tr.setLimit(ROW_CAP + 1)
            tr.query()
            var count = 0
            var rows = []
            while (tr.next()) {
                count++
                if (rows.length >= ROW_CAP) {
                    sysLogPayload.cap_hit = true
                    break
                }
                rows.push({
                    // user = sys_created_by; for the unauthenticated endpoint this
                    // surfaces as the Guest user. Recorded, not assumed.
                    user: tr.getValue('sys_created_by'),
                    url: tr.getValue('url'),
                    // getValue returns '' for an absent field rather than throwing,
                    // so an instance without remote_ip degrades gracefully.
                    remote_ip: tr.getValue('remote_ip'),
                    sys_created_on: tr.getValue('sys_created_on'),
                })
            }
            sysLogPayload.row_count = count
            sysLogPayload.rows = rows
        } catch (e) {
            coverageNotes.push('syslog_transaction endpoint query partial: ' + (e && e.message))
        }
    }

    // ---- Envelope (same shape security-log-export.js emits; checker reuses it) ---
    var coverageNoteStr =
        sourcesAvailable.length +
        ' of ' +
        EXPECTED_SOURCES.length +
        ' expected source available' +
        (coverageNotes.length ? ' — ' + coverageNotes.join('; ') : '')

    var envelope = {
        nowisor_logexport_schema: SCHEMA_VERSION,
        pack_version: PACK_VERSION,
        tool: 'incident-june-2026-check',
        advisory_id: 'SN-INCIDENT-2026-06-KB3067321',
        generated_at: generatedAt,
        window: {
            // Incident exposure window (label only — the query is unbounded below).
            start: WINDOW_START_ISO,
            end: generatedAt,
            note: 'Earliest-known activity ~April 2026; query is not lower-bounded.',
        },
        coverage: {
            sources_expected: EXPECTED_SOURCES,
            sources_available: sourcesAvailable,
            sources_missing: sourcesMissing,
            coverage_note: coverageNoteStr,
            // The checker compares this true floor against the exposure window. If it
            // is later than April 2026 your logs cannot rule out pre-patch access.
            audit_retention_start: retentionFloor,
        },
        sources: {
            syslog_transaction: sysLogPayload,
        },
    }

    gs.print('nowisor incident-june-2026-check ' + SCHEMA_VERSION + ' (pack ' + PACK_VERSION + ')')
    gs.print('Endpoint filter: ' + ENDPOINT_NEEDLE)
    gs.print('Coverage: ' + coverageNoteStr)
    gs.print('Retention floor (oldest syslog row): ' + (retentionFloor || 'unknown'))
    gs.print('')
    gs.print('---NOWISOR_LOGEXPORT---')
    gs.print(JSON.stringify(envelope, null, 2))
})()
