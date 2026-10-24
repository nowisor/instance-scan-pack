// Read-only: safe for production use
//
// nowisor bundle tool v2.0.0 - emits nowisor-scan-bundle schema 2
// Paste-into-Background-Script offline mode: no connection, no credentials.
//
// The fifth install-free sensor in tools/. Performs, inside your instance,
// the SAME reads the nowisor advisor makes over the REST Table API when an
// instance is connected, and prints them one section per line - the lines
// you save as nowisor-scan-bundle.json and upload (Instances > Upload
// results). The advisor replays these reads through the code a connected
// scan runs; nothing here scores, correlates or judges.
// Nothing is derived: every read is printed as the Table API would have
// answered it, encoded smaller (rows column by column, a reference as its
// value, a record's package once per read) and decoded exactly by the
// advisor. Two reads the advisor asks for are made narrower or without a
// column nothing uses; the advisor declares both.
//
// TIME: no read starts after 240 s (CAP_MS). A read not reached is recorded
// as not read, and the advisor reports its checks UNKNOWN, never passed.
//
// WHAT IS IN THE FILE (review it before you send it)
// Configuration property values - except password-type and secret-shaped
// values, which are replaced by "[redacted]" HERE, before anything is printed.
// ACL script and condition text, copied as-is. The users holding admin and
// security_admin (username, full name, last login). Scheduled-job run-as
// accounts. OAuth application names. Knowledge base titles. MID Server
// hostnames. Table and field metadata, plugin and application inventory.
// No ticket, CMDB or end-user records.
//
// INTEGRITY
// Each printed line's JSON is canonical (keys sorted at every depth, no
// whitespace); `sha256` is the SHA-256 of "<section> <sha256 of the line>\n"
// over every line, in order, and the end line carries it. The advisor
// recomputes it and refuses a file that does not match: edit nothing between
// here and the upload. The hash is printed below and appears on every report as the
// integrity reference; the printed run-by account and instance ID are the
// attribution.
//
// Run it as an admin. Every read is a GlideRecordSecure query (the rows the
// running user may read) or a GlideAggregate count - except the check reads
// added in pack 1.3.9 (the exposure, private-scope, typed dictionary and
// upgrade-history reads) and pack 1.3.10 (the origin fields on the ACL,
// script-include, job and dictionary reads, the four counted dynamic-code
// pattern reads, the table-origin read and the knowledge-base reads), which
// are plain GlideRecord queries: an admin's GlideRecordSecure query drops
// rows, so the read comes back short of its total. The 500-row empty-ACL
// summary read also carries origin fields since 1.3.10 but stays a
// GlideRecordSecure query with no total, so the advisor treats it as a floor
// ("at least N"), never the whole set. The mixed state is deliberate until
// the in-instance read plan is redesigned. Nothing is written.
//
// Verified identifiers: the tables and fields are the ones the advisor's
// connected scan reads (published at nowisor.com/access), no others.
//
// ES5-only (Rhino ES0). ASCII-only, short lines, one statement per line.

(function nowisorBundle() {
    var BUNDLE_SCHEMA = 2
    // ACL-001's paged reads - every empty ACL and the role rows on them -
    // are the largest reads and may not fit the ~300 s Background Script
    // page on a large instance. OFF by default. To include them, set this
    // to true before you run (R-PACK-1: run OFF first, then ON, and record
    // both timings). OFF: the bundle carries the smaller ACL reads only.
    var READ_EMPTY_ACLS = false
    var PACK_VERSION = '1.3.13'
    var TOOL_VERSION = '2.0.0'
    var SEPARATOR = '---NOWISOR_BUNDLE---'
    var END_SEPARATOR = '---NOWISOR_BUNDLE_END---'
    // Schema 2 prints one section per line. A read longer than this goes on
    // over "rows" lines, so no printed line, and no String, holds the bundle.
    var LINE_MAX = 500000
    // One clock for the whole run: no read starts after CAP_MS. A read not
    // started is recorded as not read (its checks are UNKNOWN, never PASS).
    var CAP_MS = 240000
    var NOT_READ = 'NOT_READ_TIME_CAP'
    var DAY_MS = 24 * 60 * 60 * 1000

    // --- The one redaction rule (vsme-app lib/secret-property.js) ---------
    var SECRET_NAME_SOURCE = '(password|passphrase|secret|token|api[_.]?key|credential)'
    var FLAG_OR_NUMBER_SOURCE = '^(true|false|yes|no|-?\\d+)$'
    var REDACTED = '[redacted]'
    var SECRET_NAME = new RegExp(SECRET_NAME_SOURCE, 'i')
    var FLAG_OR_NUMBER = new RegExp(FLAG_OR_NUMBER_SOURCE, 'i')

    function isSecretValue(name, type, value) {
        if (value === undefined || value === null) {
            return false
        }
        var v = String(value)
        if (v === '') {
            return false
        }
        if (FLAG_OR_NUMBER.test(v.replace(/^\s+|\s+$/g, ''))) {
            return false
        }
        if (type !== undefined && type !== null) {
            var tt = String(type).toLowerCase()
            if (tt === 'password' || tt === 'password2') {
                return true
            }
        }
        return SECRET_NAME.test(String(name || ''))
    }

    // An answer's rows, or [] - by an explicit null check: the instance's
    // script engine takes an EMPTY array as false, so `x || []` is never used
    function listOf(v) {
        return v === undefined || v === null ? [] : v
    }

    function redactRows(path, rows) {
        if (path !== 'sys_properties') {
            return rows
        }
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i]
            if (r.hasOwnProperty('value')) {
                if (isSecretValue(r.name, r.type, r.value)) {
                    r.value = REDACTED
                }
            }
        }
        return rows
    }

    // --- Instance facts ---------------------------------------------------
    var startMs = new Date().getTime()
    var capturedMs = Math.floor(startMs / 1000) * 1000
    var capturedAt = new Date(capturedMs).toISOString()
    capturedAt = capturedAt.replace(/\.\d{3}Z$/, 'Z')
    var base = String(gs.getProperty('glide.servlet.uri', ''))
    base = base.replace(/\/+$/, '')

    // --- The Table API, answered in-instance --------------------------------
    // A test harness may supply NOWISOR_BUNDLE_READER(kind, path, params) to
    // replace the Glide layer; in an instance it is undefined and unused.
    var hook = null
    if (typeof NOWISOR_BUNDLE_READER === 'function') {
        hook = NOWISOR_BUNDLE_READER
    }

    function fieldList(params) {
        var f = params.sysparm_fields
        if (!f) {
            return []
        }
        return String(f).split(',')
    }

    // A reference field whose dictionary names a reference_key other than
    // sys_id (sys_dictionary.internal_type -> sys_glide_object by name) is
    // linked by the Table API as <table>?<key>=<value>, not <table>/<value>.
    var refKeys = {}

    function referenceKey(path, field) {
        var ck = path + '.' + field
        if (refKeys.hasOwnProperty(ck)) {
            return refKeys[ck]
        }
        var key = ''
        try {
            // The field is defined on this table or an ancestor: walk up
            // sys_db_object.super_class until its dictionary entry is found.
            var t = path
            for (var hop = 0; hop < 20 && t; hop++) {
                var d = new GlideRecord('sys_dictionary')
                d.addQuery('name', t)
                d.addQuery('element', field)
                d.setLimit(1)
                d.query()
                if (d.next()) {
                    key = String(d.getValue('reference_key') || '')
                    break
                }
                var o = new GlideRecord('sys_db_object')
                o.addQuery('name', t)
                o.setLimit(1)
                o.query()
                t = ''
                if (o.next()) {
                    t = String(o.getElement('super_class.name') || '')
                }
            }
        } catch (e) {
            key = ''
        }
        refKeys[ck] = key
        return key
    }

    function elementValue(gr, field) {
        var el = gr.getElement(field)
        if (el === null || el === undefined) {
            return undefined
        }
        if (field.indexOf('.') === -1) {
            if (!gr.isValidField(field)) {
                return undefined
            }
        }
        var raw = el.toString()
        if (raw === null || raw === undefined) {
            raw = ''
        }
        raw = String(raw)
        var ed = el.getED()
        var itype = ed ? String(ed.getInternalType()) : ''
        if (field.indexOf('.') === -1 && itype === 'reference' && raw !== '') {
            var refTable = String(el.getReferenceTable())
            var refKey = referenceKey(String(gr.getTableName()), field)
            var link = base + '/api/now/table/' + refTable + '/' + raw
            if (refKey && refKey !== 'sys_id') {
                link = base + '/api/now/table/' + refTable + '?' + refKey + '=' + raw
            }
            return { link: link, value: raw }
        }
        return raw
    }

    function glideCount(path, query) {
        try {
            var ga = new GlideAggregate(path)
            if (query) {
                ga.addEncodedQuery(query)
            }
            ga.addAggregate('COUNT')
            ga.query()
            if (ga.next()) {
                return parseInt(ga.getAggregate('COUNT'), 10)
            }
            return 0
        } catch (e) {
            return null
        }
    }

    // A count of a plain read is taken once per query, without its ORDERBY.
    var plainCounts = {}

    function plainCount(path, query) {
        var cq = query.replace(/\^?ORDERBY(DESC)?[a-z0-9_.]+/g, '')
        var ck = path + '|' + cq
        if (!plainCounts.hasOwnProperty(ck)) {
            plainCounts[ck] = glideCount(path, cq)
        }
        return plainCounts[ck]
    }

    function glideTable(path, params, wantCount, plain, omit) {
        var gr = null
        if (plain) {
            gr = new GlideRecord(path)
        } else {
            gr = new GlideRecordSecure(path)
        }
        if (!gr.isValid()) {
            return { error: { code: 'SN_API_ERROR:400', message: 'Invalid table ' + path } }
        }
        if (!gr.canRead()) {
            return {
                error: {
                    code: 'INSUFFICIENT_PERMISSIONS',
                    message: 'Insufficient permissions for ' + path
                }
            }
        }
        var query = params.sysparm_query || ''
        if (query) {
            gr.addEncodedQuery(query)
        }
        var limit = parseInt(params.sysparm_limit || '10000', 10)
        var offset = parseInt(params.sysparm_offset || '0', 10)
        if (offset > 0) {
            gr.chooseWindow(offset, offset + limit)
        } else {
            gr.setLimit(limit)
        }
        gr.query()
        var fields = []
        var all = fieldList(params)
        for (var fi = 0; fi < all.length; fi++) {
            if (!omit || omit.indexOf(all[fi]) === -1) {
                fields.push(all[fi])
            }
        }
        var rows = []
        while (gr.next()) {
            var row = {}
            for (var i = 0; i < fields.length; i++) {
                var v = elementValue(gr, fields[i])
                if (v !== undefined) {
                    row[fields[i]] = v
                }
            }
            rows.push(row)
        }
        var total = null
        if (wantCount && plain) {
            total = plainCount(path, query)
        } else if (wantCount) {
            total = glideCount(path, query)
        }
        return { result: rows, total_count: total }
    }

    function glideStats(path) {
        return { count: glideCount(path, '') }
    }

    // --- Recording --------------------------------------------------------
    var reads = []
    // Per-read timing (owner, 2026-10-17: a run killed at 10 min had no way
    // to say where its time went). One entry per read: its index in reads,
    // table, page offset and elapsed ms. No query text, so no user name.
    var timings = []
    // Per-section time (owner R5, 2026-10-19): printed before the reads.
    var sections = []
    var current = null
    var cappedAt = null

    function section(name) {
        current = { section: name, ms: 0, reads: 0 }
        sections.push(current)
    }

    function timed(t0, path, params) {
        var ms = new Date().getTime() - t0
        timings.push({
            i: reads.length - 1,
            path: path,
            offset: String((params || {}).sysparm_offset || '0'),
            ms: ms
        })
        if (current) {
            current.ms += ms
            current.reads += 1
        }
    }

    // True once the run is past CAP_MS; the first read refused names where.
    function overCap() {
        if (new Date().getTime() - startMs < CAP_MS) {
            return false
        }
        if (cappedAt === null) {
            cappedAt = {
                read: reads.length,
                section: current ? current.section : '',
                ms: new Date().getTime() - startMs
            }
        }
        return true
    }

    function notRead() {
        var m = 'not read: the ' + (CAP_MS / 1000) + ' s time cap was reached'
        return { code: NOT_READ, message: m }
    }

    function copy(params) {
        var out = {}
        for (var k in params) {
            if (params.hasOwnProperty(k)) {
                out[k] = String(params[k])
            }
        }
        return out
    }

    // Returns { result, total } or { error }. Never throws. `wantCount` asks for
    // the row total (the Table API's X-Total-Count) - only on the reads whose
    // total the advisor uses; a COUNT on every read would scan each table twice.
    // `plain` (pack 1.3.9 check reads only) reads with GlideRecord.
    // `omit` (schema 2): columns the read asks for, as the advisor asks, and
    // does not read - only the ones the advisor declares unused.
    function table(path, params, wantCount, plain, omit) {
        var t0 = new Date().getTime()
        var p = copy(params)
        var ans = null
        try {
            if (overCap()) {
                ans = { error: notRead() }
            } else if (hook) {
                ans = hook('table', path, p)
            } else {
                ans = glideTable(path, p, wantCount, plain, omit)
            }
        } catch (e) {
            ans = { error: { code: 'SN_API_ERROR:500', message: String(e) } }
        }
        if (ans.error) {
            reads.push({ kind: 'table', path: path, params: p, error: ans.error })
            timed(t0, path, p)
            return { error: ans.error }
        }
        var rows = redactRows(path, listOf(ans.result))
        if (omit) {
            for (var oi = 0; oi < rows.length; oi++) {
                for (var oj = 0; oj < omit.length; oj++) {
                    delete rows[oi][omit[oj]]
                }
            }
        }
        var total = null
        if (wantCount && typeof ans.total_count === 'number') {
            total = ans.total_count
        }
        var entry = { kind: 'table', path: path, params: p, result: rows }
        entry.total_count = total
        if (omit) {
            entry.omit = omit
        }
        reads.push(entry)
        timed(t0, path, p)
        return { result: rows, total: total }
    }

    function stats(path) {
        var t0 = new Date().getTime()
        var ans = { count: null }
        if (!overCap()) {
            var sp = { sysparm_count: 'true' }
            ans = hook ? hook('stats', path, sp) : glideStats(path)
        }
        var count = typeof ans.count === 'number' ? ans.count : null
        reads.push({
            kind: 'stats', path: path,
            params: { sysparm_count: 'true' }, count: count
        })
        timed(t0, path, {})
        return count
    }

    function plain(path) {
        // /stats.do cannot be requested from a Background Script; the advisor
        // treats a null answer exactly as a connected scan treats a refusal.
        var text = null
        if (hook) {
            text = hook('plain', path, {}).text
        }
        reads.push({ kind: 'plain', path: path, params: {}, text: text })
        return text
    }

    function isGraceful(err) {
        if (!err) {
            return false
        }
        var c = err.code
        return c === 'INSUFFICIENT_PERMISSIONS' || c === 'SN_API_ERROR:404'
    }

    function sortedIds(rows) {
        var ids = []
        for (var i = 0; i < rows.length; i++) {
            var id = rows[i].sys_id
            if (id) {
                ids.push(String(id))
            }
        }
        ids.sort()
        return ids
    }

    function roleGated(rows) {
        var ids = sortedIds(rows)
        for (var i = 0; i < ids.length; i += 100) {
            var chunk = ids.slice(i, i + 100)
            table('sys_security_acl_role', {
                sysparm_query: 'sys_security_aclIN' + chunk.join(','),
                sysparm_fields: 'sys_security_acl',
                sysparm_limit: '5000'
            })
        }
    }

    function nameOr(names) {
        var parts = []
        for (var i = 0; i < names.length; i++) {
            parts.push('name=' + names[i])
        }
        return parts.join('^OR')
    }

    // --- The collector's reads (lib/sn-client.js collectSnapshot) ------------
    var HARDENING = ['glide.script.use.sandbox', 'glide.security.use_csrf_token']
    HARDENING.push('glide.basicauth.required.scriptedprocessor')
    HARDENING.push('glide.ui.session_timeout')
    HARDENING.push('glide.security.strict_elevate_privilege')
    HARDENING.push('glide.ui.secure_cookies')
    HARDENING.push('glide.security.file.mime_type.validation')
    HARDENING.push('glide.attachment.role')

    var SESSION = ['glide.ui.session_timeout', 'glide.authenticate.multifactor']
    SESSION.push('glide.authenticate.external')
    SESSION.push('glide.authenticate.multisso.enabled')

    var ENC_PLUGINS = ['com.glide.encryption.core', 'com.snc.db_encryption']
    ENC_PLUGINS.push('com.glide.column_encryption')

    var API_AUTH = ['api', 'soap', 'scriptedprocessor', 'jsonv2', 'csv', 'excel']
    API_AUTH.push('importprocessor')
    API_AUTH.push('pdf')
    API_AUTH.push('rss')
    API_AUTH.push('schema')
    API_AUTH.push('unl')
    API_AUTH.push('wsdl')
    API_AUTH.push('xml')
    API_AUTH.push('xsd')
    API_AUTH.push('xmloutputprocessor')
    API_AUTH.push('databrokerrestapiprocessor')
    for (var a = 0; a < API_AUTH.length; a++) {
        API_AUTH[a] = 'glide.basicauth.required.' + API_AUTH[a]
    }


    var LIKE_PATTERNS = ['eval(', 'new Function(', 'GlideEvaluator']
    LIKE_PATTERNS.push('GlideScopedEvaluator')

    var ADMIN_Q = 'role.name=admin^state=active^user.active=true'
    var SECADMIN_Q = 'role.name=security_admin^state=active^user.active=true'

    // --- The tenant reading (lib/ncf/tenant-schema-extractor.js) ------------
    // First, as a connected scan reads it (R-VER-7): it verifies every rule
    // identifier, so a run the time cap stops later keeps the checks whose
    // reads it made (pack 1.3.12).
    section('reading')
    var TARGET_TABLES = ['sys_security_acl', 'sys_security_acl_role']
    TARGET_TABLES.push('sys_user', 'sys_user_has_role', 'sys_user_group')
    TARGET_TABLES.push('sys_user_grmember', 'sys_group_has_role')
    TARGET_TABLES.push('sys_properties', 'sys_script', 'sys_script_include')
    TARGET_TABLES.push('sys_script_fix', 'sys_script_client', 'sysauto_script')
    TARGET_TABLES.push('sys_trigger', 'oauth_entity', 'oauth_credential')
    TARGET_TABLES.push('oauth_entity_profile', 'oauth_entity_scope')
    TARGET_TABLES.push('sys_ws_definition', 'sys_ws_operation', 'sys_hub_flow')
    TARGET_TABLES.push('sys_processor', 'discovery_credentials', 'sa_credential')
    TARGET_TABLES.push('sys_plugins', 'v_plugin', 'sys_attachment', 'sys_email')
    TARGET_TABLES.push('sys_email_account', 'sys_db_object', 'sys_dictionary')
    TARGET_TABLES.push('sys_documentation', 'sysevent_email_action')
    TARGET_TABLES.push('sysevent_register', 'sys_auth_profile')
    TARGET_TABLES.push('sys_certificate', 'sys_rest_message')
    TARGET_TABLES.push('sys_rest_message_fn', 'sso_saml2_configuration')
    TARGET_TABLES.push('sys_impersonation_log')

    var idq = 'name=glide.buildtag.last^ORname=glide.buildtag'
    idq += '^ORname=instance_id^ORname=instance_name'
    var ident = table('sys_properties', {
        sysparm_query: idq,
        sysparm_fields: 'name,value',
        sysparm_limit: '10'
    })
    var gotTag = false
    var gotId = false
    if (!ident.error) {
        for (var n = 0; n < ident.result.length; n++) {
            var ir = ident.result[n]
            if (ir.name === 'glide.buildtag.last' && ir.value) {
                gotTag = true
            }
            if (ir.name === 'glide.buildtag' && ir.value) {
                gotTag = true
            }
            if (ir.name === 'instance_id' && ir.value) {
                gotId = true
            }
        }
    }
    if (!gotTag || !gotId) {
        plain('/stats.do')
    }
    var found = []
    for (var c = 0; c < TARGET_TABLES.length; c += 80) {
        var tchunk = TARGET_TABLES.slice(c, c + 80)
        var tr = table('sys_db_object', {
            sysparm_query: 'nameIN' + tchunk.join(','),
            sysparm_fields: 'name,label,super_class,sys_scope',
            sysparm_limit: '500'
        })
        if (!tr.error) {
            for (var r = 0; r < tr.result.length; r++) {
                if (found.indexOf(tr.result[r].name) === -1) {
                    found.push(tr.result[r].name)
                }
            }
        }
    }
    found.sort()
    var FIELDS = 'name,element,column_label,internal_type,max_length,'
    FIELDS += 'mandatory,read_only,reference'
    for (var f = 0; f < found.length; f += 40) {
        var fchunk = found.slice(f, f + 40)
        table('sys_dictionary', {
            sysparm_query: 'nameIN' + fchunk.join(',') + '^element!=NULL',
            sysparm_fields: FIELDS,
            sysparm_limit: '10000'
        })
    }
    var offset = 0
    for (var pg = 0; pg < 10; pg++) {
        // Password-typed properties are never read (WI-CONN-1): the app's
        // fingerprint skips them, and the connection role cannot read them.
        var props = table('sys_properties', {
            sysparm_query: 'type!=password^type!=password2',
            sysparm_fields: 'name,value,type',
            sysparm_limit: '5000',
            sysparm_offset: String(offset)
        })
        if (props.error || props.result.length < 5000) {
            break
        }
        offset += 5000
    }
    // pack 1.3.10: sys_scope with its private flag and its vendor
    var INV_BASE = 'name,version,active,scope,sys_id'
    // pack 1.3.12: sys_scope (a required source) before sys_store_app
    var INV = [['sys_scope', INV_BASE + ',private,vendor'], ['sys_store_app', INV_BASE]]
    for (var iv = 0; iv < INV.length; iv++) {
        var itab = INV[iv][0]
        stats(itab)
        for (var ip = 0; ip < 50; ip++) {
            var page = table(itab, {
                sysparm_fields: INV[iv][1],
                sysparm_limit: '2000',
                sysparm_offset: String(ip * 2000)
            })
            if (page.error || page.result.length === 0) {
                break
            }
        }
    }


    // pack 1.3.12 (owner ruling (a), 2026-10-19): the plugin list is read from
    // sys_plugins, counted - a required source of an upload's reading. v_plugin
    // is never read: it is a view the platform rebuilds on a cold read (166 s
    // and 207 s on dev433526), which no time cap can bound once started. The
    // advisor answers its own v_plugin reads from this one (R-VER-7, upload).
    // `description` asked and not read: nothing uses it
    var plugins = table('sys_plugins', {
        sysparm_fields: 'sys_id,name,source,active,description,version',
        sysparm_limit: '2000'
    }, true, false, ['description'])

    section('collector')
    // hardening
    var hard = table('sys_properties', {
        sysparm_query: nameOr(HARDENING),
        sysparm_fields: 'name,value',
        sysparm_limit: '50'
    })
    if (!hard.error) {
        table('sys_properties', {
            sysparm_query: 'nameLIKEpassword^ORnameLIKEcredential^ORnameLIKEsecret'
                + '^ORnameLIKEapi_key',
            sysparm_fields: 'name',
            sysparm_limit: '1'
        }, true)
    }
    // ACL summary
    // pack 1.3.10: with the origin fields, so an upload without ACL-001's
    // paged reads still splits the first 500 by origin
    // pack 1.3.12: `type` asked (the advisor's read names it) and not read:
    // nothing uses it
    var cand = table('sys_security_acl', {
        sysparm_query: 'active=true^conditionISEMPTY^scriptISEMPTY',
        sysparm_fields: 'sys_id,name,type,operation,sys_package,'
            + 'sys_package.name,sys_package.sys_class_name,sys_policy,'
            + 'sys_created_on',
        sysparm_limit: '500'
    }, false, false, ['type'])
    if (!cand.error && cand.result.length > 0) {
        roleGated(cand.result)
    }
    table('sys_script_include', {
        sysparm_query: 'client_callable=true^active=true',
        sysparm_fields: 'name,api_name,access',
        sysparm_limit: '200'
    })
    table('sys_script', {
        sysparm_query: 'active=true',
        sysparm_fields: 'sys_id',
        sysparm_limit: '1'
    }, true)
    table('discovery_credentials', {
        sysparm_fields: 'name,type,target_type',
        sysparm_limit: '100'
    })
    table('sn_vsc_instance_hardening_settings', {
        sysparm_fields: 'harc_name,risk_score,score_impact,compliance_status',
        sysparm_limit: '500'
    })
    table('sys_security_acl', {
        sysparm_query: 'active=true^scriptISNOTEMPTY^scriptCONTAINSreturn true',
        sysparm_fields: 'name,operation,script',
        sysparm_limit: '200'
    })
    // admin role holders
    table('sys_user_has_role', {
        sysparm_query: ADMIN_Q,
        sysparm_fields: 'user.user_name,user.last_login_time,user.name',
        sysparm_limit: '500'
    })
    table('sys_user_has_role', {
        sysparm_query: SECADMIN_Q,
        sysparm_fields: 'sys_id',
        sysparm_limit: '1'
    }, true)
    // pack 1.3.10: each admin holder's web-service-only flag, and for every such
    // account its transactions over 90 days (the count only)
    var wsa = table('sys_user_has_role', {
        sysparm_query: ADMIN_Q,
        sysparm_fields: 'user.user_name,user.web_service_access_only',
        sysparm_limit: '500'
    })
    if (!wsa.error) {
        var since90 = new Date(capturedMs - 90 * DAY_MS).toISOString()
        since90 = since90.slice(0, 19).replace('T', ' ')
        var wsaUsers = []
        for (var w = 0; w < wsa.result.length; w++) {
            var wr = wsa.result[w]
            var wu = wr['user.user_name']
            // a name that would rewrite the encoded query is not read
            // (the app does not ask it either)
            var wsaFlag = String(wr['user.web_service_access_only'])
            var safeName = wu && !/[\^,=]/.test(wu)
            if (safeName && wsaFlag === 'true') {
                if (wsaUsers.indexOf(wu) === -1) {
                    wsaUsers.push(wu)
                }
            }
        }
        wsaUsers.sort()
        for (var wx = 0; wx < wsaUsers.length; wx++) {
            table('syslog_transaction', {
                sysparm_query: 'sys_created_by=' + wsaUsers[wx]
                    + '^sys_created_on>=' + since90,
                sysparm_fields: 'sys_id,sys_created_by,sys_created_on',
                sysparm_limit: '1'
            }, true)
        }
    }
    // OAuth applications (pack 1.3.10: the grant-type columns the instance
    // has - default_grant_type, inbound_grant_type; there is no grant_type)
    table('oauth_entity', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,type,default_grant_type,inbound_grant_type,'
            + 'access_token_lifespan,refresh_token_lifespan',
        sysparm_limit: '100'
    })
    // identity governance
    var igA = table('sys_user_has_role', {
        sysparm_query: ADMIN_Q,
        sysparm_fields: 'user.user_name,user.name',
        sysparm_limit: '1000'
    })
    var igS = table('sys_user_has_role', {
        sysparm_query: SECADMIN_Q,
        sysparm_fields: 'user.user_name,user.name,user.last_login_time',
        sysparm_limit: '1000'
    })
    var igO = table('oauth_entity', {
        sysparm_query: 'active=true',
        sysparm_fields: 'sys_id,name,type,access_token_lifespan,'
            + 'refresh_token_lifespan',
        sysparm_limit: '500'
    })
    if (!igA.error && !igS.error && !igO.error) {
        var since = new Date(capturedMs - 90 * DAY_MS).toISOString()
        since = since.slice(0, 19).replace('T', ' ')
        table('oauth_credential', {
            sysparm_query: 'type=access_token^sys_created_on>=' + since,
            sysparm_fields: 'peer',
            sysparm_limit: '10000'
        })
    }
    // knowledge base access: the check reads below (pack 1.3.10)
    table('ecc_agent', {
        sysparm_query: 'status=Up',
        sysparm_fields: 'name,status,version,host_name,validated',
        sysparm_limit: '50'
    })
    table('sys_db_object', {
        sysparm_query: 'super_class.name=sys_import_set_row',
        sysparm_fields: 'name,label',
        sysparm_limit: '200'
    })
    // dynamic code patterns: the four counted check reads below (pack 1.3.10)
    table('sys_ws_definition', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,api_id,enforced,version,active,sys_scope.name',
        sysparm_limit: '1000'
    })
    // pack 1.3.12: the 5,000-row active-operation read is gone (nothing
    // read it; the exposure rules read the check read below)
    table('sys_plugins', {
        sysparm_query: 'active=active',
        sysparm_fields: 'name,source',
        sysparm_limit: '500'
    })
    table('sys_properties', {
        sysparm_query: nameOr(SESSION),
        sysparm_fields: 'name,value',
        sysparm_limit: '10'
    })
    table('sys_properties', {
        sysparm_query: nameOr(API_AUTH),
        sysparm_fields: 'name,value',
        sysparm_limit: '50'
    })
    var dict = 'elementLIKEpassword^ORelementLIKEsecret^ORelementLIKEtoken'
    dict += '^ORelementLIKEkey^ORelementLIKEcredential'
    dict += '^ORcolumn_labelLIKEpassword^ORcolumn_labelLIKEsecret'
    dict += '^ORcolumn_labelLIKEtoken'
    // pack 1.3.12: the untyped 1,000-row secret-name read is gone (nothing
    // read it; DATA-006 reads the typed check read below)
    // DATA-003's encryption plugins: a targeted sys_plugins read, counted
    // (pack 1.3.12, ruling (a): both plugin reads move to sys_plugins) - the
    // advisor answers its v_plugin encryption read from it. Complete whatever
    // the size of the plugin list; the encrypted-field count is read when it
    // answered, as the advisor reads it.
    var enc = table('sys_plugins', {
        sysparm_query: 'sourceIN' + ENC_PLUGINS.join(','),
        sysparm_fields: 'sys_id,name,source,active',
        sysparm_limit: '20'
    }, true)
    if (!enc.error) {
        table('sys_dictionary', {
            sysparm_query: 'internal_type=encrypted_text^ORinternal_type=password2',
            sysparm_fields: 'sys_id',
            sysparm_limit: '1'
        }, true)
    }
    table('sys_rate_limit_rules', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,sys_id',
        sysparm_limit: '25'
    }, true)
    // No posture at all: the connected scan then asks one control question.
    var aclDenied = cand.error && cand.error.code === 'INSUFFICIENT_PERMISSIONS'
    var propDenied = hard.error && hard.error.code === 'INSUFFICIENT_PERMISSIONS'
    if (aclDenied && propDenied) {
        table('sys_user', { sysparm_fields: 'sys_id', sysparm_limit: '1' })
    }

    // --- Check reads (vsme-app lib/check-reads.js CHECK_READS), pack 1.3.9 ---
    section('check_reads')
    // Made as the advisor's readCheck replays them: the table's unfiltered
    // count, then 1,000-row pages ordered by sys_id, each with the total.
    // Page 0 always; further pages only when the total says there are more
    // rows, at most 50 (the advisor's own cap). Every planned page is recorded
    // even after one fails: the advisor asks for them concurrently, and a page
    // missing from the bundle would refuse the whole upload, not this read.
    // Plain GlideRecord, admin-run.
    var CHECK_PAGE = 1000
    var CHECK_MAX_PAGES = 50
    var unfiltered = {}

    function checkPage(path, query, fields, offset) {
        return table(path, {
            sysparm_query: query + '^ORDERBYsys_id',
            sysparm_fields: fields,
            sysparm_limit: String(CHECK_PAGE),
            sysparm_offset: String(offset)
        }, true, true)
    }

    function checkRead(path, query, fields) {
        if (!unfiltered.hasOwnProperty(path)) {
            unfiltered[path] = true
            table(path, { sysparm_fields: 'sys_id', sysparm_limit: '1' }, true, true)
        }
        var first = checkPage(path, query, fields, 0)
        if (first.error || first.total === null) {
            return null
        }
        var needed = Math.ceil(first.total / CHECK_PAGE)
        if (needed > CHECK_MAX_PAGES) {
            needed = CHECK_MAX_PAGES
        }
        // the rows of every page, for a read whose rows the app looks up
        // further; null when a page failed (the app then looks up nothing)
        var rows = listOf(first.result).slice()
        var failed = false
        for (var cp = 1; cp < needed; cp++) {
            var page = checkPage(path, query, fields, cp * CHECK_PAGE)
            if (page.error) {
                failed = true
            } else {
                rows = rows.concat(listOf(page.result))
            }
        }
        return failed ? null : rows
    }

    // EXP-001 / EXP-002 / EXP-005: operations with the checkbox cleared
    var WS_GATE = 'active=true^requires_acl_authorization=false'
    var WS_FIELDS = 'sys_id,name,http_method,operation_uri,relative_path,'
    WS_FIELDS += 'requires_acl_authorization,requires_authentication,'
    WS_FIELDS += 'enforce_acl,sys_policy,sys_created_on,sys_package,'
    WS_FIELDS += 'sys_package.name,sys_package.sys_class_name,'
    WS_FIELDS += 'web_service_definition,web_service_definition.name,'
    // pack 1.3.10: the definition's namespace and whether it is active
    WS_FIELDS += 'web_service_definition.namespace,'
    WS_FIELDS += 'web_service_definition.active'
    checkRead('sys_ws_operation', WS_GATE, WS_FIELDS)
    // R-READ-9: the gate rows in private scopes, and the =false count
    var PRIV = 'sys_package.ref_sys_scope.private'
    checkRead('sys_ws_operation', WS_GATE + '^' + PRIV + '=true', 'sys_id')
    table('sys_ws_operation', {
        sysparm_query: WS_GATE + '^' + PRIV + '=false',
        sysparm_fields: 'sys_id',
        sysparm_limit: '1'
    }, true, true)
    // pack 1.3.10: the reader app's own package, from its health table's row
    checkRead('sys_db_object', 'name=x_nowisor_vsme_health', 'name,sys_package')
    // Origin rule (d): the upgrade windows
    checkRead('sys_upgrade_history', 'upgrade_startedISNOTEMPTY',
        'upgrade_started,upgrade_finished')
    // DATA-006: the secret-name read, typed to the clear-text types
    var DICT_TYPED = dict + '^internal_typeINstring,string_full_utf8,html,'
    DICT_TYPED += 'translated_text'
    var typed = checkRead('sys_dictionary', DICT_TYPED,
        'name,element,column_label,internal_type,sys_scope')

    // --- Check reads added in pack 1.3.10 (WI-ENG-7) -------------------------
    // The origin fields every origin-split rule classifies a record by.
    var ORIGIN = 'sys_package,sys_package.name,sys_package.sys_class_name,'
    ORIGIN += 'sys_policy,sys_created_on'
    // DATA-006: the origin of the table each typed row names - pack 1.3.12:
    // only those tables (the advisor answers its every-table read with them;
    // nothing reads another row), 100 names a read. `narrowed` records how
    // many reads they are; or that the typed read did not complete - because
    // the time cap stopped it (not_read) or for another reason (incomplete).
    var narrowed = { dictTableOrigin: { state: 'incomplete', reads: 0 } }
    if (typed === null && cappedAt !== null) {
        narrowed.dictTableOrigin.state = 'not_read'
    }
    if (typed !== null) {
        narrowed.dictTableOrigin.state = 'read'
        var tnames = []
        for (var tn = 0; tn < typed.length; tn++) {
            var nm = typed[tn].name
            if (nm && tnames.indexOf(String(nm)) === -1) {
                tnames.push(String(nm))
            }
        }
        tnames.sort()
        for (var tc = 0; tc < tnames.length; tc += 100) {
            narrowed.dictTableOrigin.reads += 1
            table('sys_db_object', {
                sysparm_query: 'nameIN' + tnames.slice(tc, tc + 100).join(',')
                    + '^ORDERBYsys_id',
                sysparm_fields: 'name,sys_scope,' + ORIGIN,
                sysparm_limit: '1000'
            }, true, true)
        }
    }
    // INJ-001: one counted read per evaluation pattern
    var INJ_BASE = 'client_callable=true^active=true^scriptLIKE'
    for (var ij = 0; ij < LIKE_PATTERNS.length; ij++) {
        checkRead('sys_script_include', INJ_BASE + LIKE_PATTERNS[ij],
            'sys_id,name,api_name,' + ORIGIN)
    }
    // JOB-001: jobs that run as a named user, with their origin
    checkRead('sysauto_script', 'run_asISNOTEMPTY',
        'name,run_as,run_as.user_name,active,' + ORIGIN)
    // ACL-009: every active base, every Can Read row, the reach signals
    checkRead('kb_knowledge_base', 'active=true', 'sys_id,title,active')
    checkRead('kb_uc_can_read_mtom', 'kb_knowledge_baseISNOTEMPTY',
        'kb_knowledge_base,user_criteria')
    checkRead('user_criteria', 'roleISNOTEMPTY', 'sys_id,role')
    checkRead('sys_user_role', 'name=public', 'sys_id,name')
    checkRead('sp_page', 'idINkb_home,kb_article_view,kb_search', 'id,public')
    // the company code and the no-criteria property, by name, counted
    var OPROPS = 'nameINglide.appcreator.company.code,'
    OPROPS += 'glide.knowman.block_access_with_no_user_criteria'
    table('sys_properties', {
        sysparm_query: OPROPS,
        sysparm_fields: 'name,value',
        sysparm_limit: '4'
    }, true)
    // ACL-003: wildcard rules, with their origin
    checkRead('sys_security_acl', 'active=true^nameLIKE*^ORoperation=*',
        'name,operation,' + ORIGIN)
    // ACL-002 / ACL-008: every active rule with a script, paged with its
    // total (the 2,000-row sample earlier packs sent is not evidence)
    var scripted = checkRead('sys_security_acl', 'active=true^scriptISNOTEMPTY',
        'sys_id,name,operation,script')
    if (scripted !== null) {
        roleGated(scripted)
    }
    // ACL-005: the read rules on the PII tables and their fields
    var PII = 'active=true^operation=read'
    PII += '^nameINsys_user,sn_hr_core_profile'
    PII += '^ORnameSTARTSWITHsys_user.'
    PII += '^ORnameSTARTSWITHsn_hr_core_profile.'
    var piiRead = checkRead('sys_security_acl', PII,
        'sys_id,name,operation,condition,script')
    if (piiRead !== null) {
        roleGated(piiRead)
    }
    // AUDIT-001: the collection row of each baseline table
    var AUD = 'nameINsys_user,sys_user_has_role,sys_user_grmember,'
    AUD += 'discovery_credentials^element=NULL'
    checkRead('sys_dictionary', AUD, 'name,audit')
    // ACL-001: the empty rules and the role rows on them, both paged - the
    // largest reads, last
    if (READ_EMPTY_ACLS) {
        var ACL_EMPTY = 'active=true^conditionISEMPTY^scriptISEMPTY'
        checkRead('sys_security_acl', ACL_EMPTY,
            'sys_id,name,operation,' + ORIGIN)
        var ACL_ROLES = 'sys_security_acl.active=true'
        ACL_ROLES += '^sys_security_acl.conditionISEMPTY'
        ACL_ROLES += '^sys_security_acl.scriptISEMPTY'
        checkRead('sys_security_acl_role', ACL_ROLES, 'sys_security_acl')
    }

    // --- The capabilities probe (lib/capabilities-probe.js PROBE_TARGETS) ---
    section('probe')
    var TERMS = ['Now Assist', 'Generative AI', 'AI Agent', 'Control Tower']
    TERMS.push('Build Agent')
    var like = []
    for (var t = 0; t < TERMS.length; t++) {
        like.push('nameLIKE' + TERMS[t])
    }
    var LIKE = like.join('^OR')
    var dbo = table('sys_db_object', {
        sysparm_fields: 'name',
        sysparm_limit: '10',
        sysparm_query: 'nameINsn_aia_agent,sn_mcp_server,sys_mcp_server'
    }, true)
    table('sys_store_app', {
        sysparm_fields: 'name,active,version',
        sysparm_limit: '50',
        sysparm_query: LIKE
    }, true)
    // probe 2: scopes between Store apps and plugins
    table('sys_scope', {
        sysparm_fields: 'name,active',
        sysparm_limit: '50',
        sysparm_query: LIKE
    }, true)
    table('sys_plugins', {
        sysparm_fields: 'name,active',
        sysparm_limit: '50',
        sysparm_query: LIKE
    }, true)
    table('sys_properties', {
        sysparm_fields: 'name',
        sysparm_limit: '1',
        sysparm_query: 'nameLIKEnowassist^ORnameLIKEgenerative_ai^ORnameLIKEsn_aia'
    }, true)
    var hasAgent = false
    if (!dbo.error) {
        for (var d = 0; d < dbo.result.length; d++) {
            if (dbo.result[d].name === 'sn_aia_agent') {
                hasAgent = true
            }
        }
    }
    if (hasAgent) {
        table('sn_aia_agent', { sysparm_fields: 'sys_id', sysparm_limit: '1' }, true)
    }

    // --- The document (schema 2) ---------------------------------------------
    // One section per printed line: "<name> <json>". header, timings, then
    // one "read" line per read (a long read goes on over "rows" lines), then
    // "end". Each line's JSON is canonical (keys sorted, no whitespace); the
    // bundle's SHA-256 is taken over "<name> <sha256 of the line's JSON>\n"
    // for every line before "end", in order. No string holds the document.
    function asciiSafe(json) {
        return json.replace(/[\u0020<>&\u007f-\uffff]/g, function (ch) {
            var h = ch.charCodeAt(0).toString(16)
            while (h.length < 4) {
                h = '0' + h
            }
            return '\\u' + h
        })
    }

    function sortKeys(v) {
        if (Object.prototype.toString.call(v) === '[object Array]') {
            var arr = []
            for (var i = 0; i < v.length; i++) {
                arr.push(sortKeys(v[i]))
            }
            return arr
        }
        if (v !== null && typeof v === 'object') {
            var keys = []
            for (var key in v) {
                if (v.hasOwnProperty(key)) {
                    keys.push(key)
                }
            }
            keys.sort()
            var o = {}
            for (var j = 0; j < keys.length; j++) {
                o[keys[j]] = sortKeys(v[keys[j]])
            }
            return o
        }
        return v
    }

    // A reference cell {link, value} is printed as its value when the link is
    // the Table API's own: <base>/api/now/table/<t>/<value>, or
    // <t>?<k>=<value>. `refs` names the field's <t> (and <k>); the advisor
    // rebuilds the link. A field with any other shape is printed as read.
    var TABLE_API = base + '/api/now/table/'

    function refShape(cell) {
        if (cell === null || typeof cell !== 'object') {
            return null
        }
        // exactly {link, value}: any other shape is printed as read
        var ks = []
        for (var ck in cell) {
            if (cell.hasOwnProperty(ck)) {
                ks.push(ck)
            }
        }
        if (ks.length !== 2 || !cell.hasOwnProperty('link')) {
            return null
        }
        if (!cell.hasOwnProperty('value')) {
            return null
        }
        var link = String(cell.link)
        var v = String(cell.value)
        if (link.indexOf(TABLE_API) !== 0 || !v) {
            return null
        }
        var rest = link.substring(TABLE_API.length)
        var slash = rest.length - v.length - 1
        if (slash > 0 && rest.substring(slash) === '/' + v) {
            var t = rest.substring(0, slash)
            if (t.indexOf('/') === -1 && t.indexOf('?') === -1) {
                return { t: t }
            }
        }
        var q = rest.indexOf('?')
        if (q > 0) {
            var tq = rest.substring(0, q)
            var kv = rest.substring(q + 1)
            var eq = kv.indexOf('=')
            if (eq > 0 && kv.substring(eq + 1) === v) {
                return { t: tq, k: kv.substring(0, eq) }
            }
        }
        return null
    }

    function sameShape(a, b) {
        return a.t === b.t && (a.k || '') === (b.k || '')
    }

    // The field's reference shape when every non-empty cell has it, else null
    function columnRef(rows, f) {
        var shape = null
        for (var r = 0; r < rows.length; r++) {
            if (!rows[r].hasOwnProperty(f)) {
                continue
            }
            var cell = rows[r][f]
            if (cell === '') {
                continue
            }
            var sh = refShape(cell)
            if (!sh) {
                return null
            }
            if (shape && !sameShape(shape, sh)) {
                return null
            }
            shape = sh
        }
        return shape
    }

    var PKG = ['sys_package', 'sys_package.name', 'sys_package.sys_class_name']

    // One read -> { head, rows }: the read's facts, its column names (`cols`),
    // and its rows as arrays (null: the field was not returned).
    function encodeRead(r, idx) {
        var head = { i: idx, kind: r.kind, path: r.path, params: r.params }
        if (r.error) {
            head.error = r.error
        }
        if (r.kind === 'stats') {
            head.count = r.count
        }
        if (r.kind === 'plain') {
            head.text = r.text
        }
        if (r.omit) {
            head.omit = r.omit
        }
        // explicit: the instance's script engine takes an EMPTY array as false
        // (run 3 on dev433526 printed every zero-row read without its columns
        // and its total) - never test an array for truthiness here
        if (r.result === undefined || r.result === null) {
            return { head: head, rows: [] }
        }
        head.total_count = r.total_count
        var rows = r.result
        var cols = []
        if (r.params.sysparm_fields) {
            var asked = String(r.params.sysparm_fields).split(',')
            for (var a = 0; a < asked.length; a++) {
                if (!r.omit || r.omit.indexOf(asked[a]) === -1) {
                    cols.push(asked[a])
                }
            }
        } else {
            var seen = {}
            for (var sr = 0; sr < rows.length; sr++) {
                for (var sk in rows[sr]) {
                    if (rows[sr].hasOwnProperty(sk) && !seen[sk]) {
                        seen[sk] = true
                        cols.push(sk)
                    }
                }
            }
            cols.sort()
        }
        var refs = {}
        for (var c = 0; c < cols.length; c++) {
            var shape = columnRef(rows, cols[c])
            if (shape) {
                refs[cols[c]] = shape
            }
        }
        // The package, its name and its class, once per read (`packages`);
        // a row's sys_package cell is its index there.
        var pkg = cols.indexOf(PKG[0]) !== -1
        pkg = pkg && cols.indexOf(PKG[1]) !== -1 && cols.indexOf(PKG[2]) !== -1
        var packages = []
        var pkgIndex = {}
        var out = []
        if (pkg) {
            var kept = []
            for (var k = 0; k < cols.length; k++) {
                if (cols[k] !== PKG[1] && cols[k] !== PKG[2]) {
                    kept.push(cols[k])
                }
            }
            cols = kept
        }
        for (var ri = 0; ri < rows.length; ri++) {
            var row = rows[ri]
            var cells = []
            for (var ci = 0; ci < cols.length; ci++) {
                var f = cols[ci]
                var cell = row.hasOwnProperty(f) ? row[f] : null
                if (cell !== null && refs[f] && typeof cell === 'object') {
                    cell = String(cell.value)
                }
                if (pkg && f === PKG[0]) {
                    var triple = [cell]
                    for (var pj = 1; pj < 3; pj++) {
                        var has = row.hasOwnProperty(PKG[pj])
                        triple.push(has ? row[PKG[pj]] : null)
                    }
                    var tk = JSON.stringify(triple)
                    if (!pkgIndex.hasOwnProperty(tk)) {
                        pkgIndex[tk] = packages.length
                        packages.push(triple)
                    }
                    cell = pkgIndex[tk]
                }
                cells.push(cell)
            }
            out.push(cells)
        }
        head.cols = cols
        head.refs = refs
        if (pkg) {
            head.packages = packages
        }
        return { head: head, rows: out }
    }

    var lines = []
    var chain = ''

    function digest(text) {
        return String(new GlideDigest().getSHA256Hex(text)).toLowerCase()
    }

    function line(name, obj) {
        var canonical = JSON.stringify(sortKeys(obj))
        chain += name + ' ' + digest(canonical) + '\n'
        lines.push(name + ' ' + asciiSafe(canonical))
    }

    var duration = new Date().getTime() - startMs
    var serializeStart = new Date().getTime()
    line('header', {
        bundle_schema: BUNDLE_SCHEMA,
        pack_version: PACK_VERSION,
        tool_version: TOOL_VERSION,
        read_empty_acls: READ_EMPTY_ACLS,
        captured_at: capturedAt,
        instance_url: base,
        instance_id: String(gs.getProperty('instance_id', '')),
        release: {
            build_name: String(gs.getProperty('glide.buildname', '')),
            build_tag: String(gs.getProperty('glide.buildtag.last', '')),
            war: String(gs.getProperty('glide.war', ''))
        },
        executed_by: {
            sys_id: String(gs.getUserID()),
            user_name: String(gs.getUserName())
        },
        duration_ms: duration,
        cap_ms: CAP_MS,
        capped: cappedAt,
        narrowed: narrowed,
        reads: reads.length
    })
    line('timings', { sections: sections, reads: timings })
    for (var ix = 0; ix < reads.length; ix++) {
        var enc = encodeRead(reads[ix], ix)
        var first = []
        // lengths as printed (escaped): a space prints as six characters
        var size = asciiSafe(JSON.stringify(enc.head)).length
        var rx = 0
        // the first line carries the head and the rows that fit; then rows
        for (; rx < enc.rows.length; rx++) {
            var len = asciiSafe(JSON.stringify(enc.rows[rx])).length + 1
            if (first.length > 0 && size + len > LINE_MAX) {
                break
            }
            size += len
            first.push(enc.rows[rx])
        }
        enc.head.rows = first
        enc.head.parts = 1
        var more = []
        while (rx < enc.rows.length) {
            var chunk = []
            var csize = 20
            for (; rx < enc.rows.length; rx++) {
                var clen = asciiSafe(JSON.stringify(enc.rows[rx])).length + 1
                if (chunk.length > 0 && csize + clen > LINE_MAX) {
                    break
                }
                csize += clen
                chunk.push(enc.rows[rx])
            }
            more.push(chunk)
        }
        enc.head.parts = 1 + more.length
        line('read', enc.head)
        for (var mx = 0; mx < more.length; mx++) {
            line('rows', { i: ix, part: mx + 1, rows: more[mx] })
        }
    }
    var hash = digest(chain)

    gs.print('nowisor bundle schema ' + BUNDLE_SCHEMA)
    gs.print('pack ' + PACK_VERSION)
    gs.print('empty ACL reads ' + (READ_EMPTY_ACLS ? 'ON' : 'OFF'))
    var iid = String(gs.getProperty('instance_id', ''))
    gs.print('instance ' + base + ' (' + iid + ')')
    gs.print('captured ' + capturedAt + ' reads ' + reads.length)
    gs.print('SHA-256 ' + hash)
    gs.print('reads ms ' + duration + ', serialize and hash ms '
        + (new Date().getTime() - serializeStart))
    if (cappedAt === null) {
        gs.print('time cap ' + (CAP_MS / 1000) + ' s not reached')
    } else {
        gs.print('time cap ' + (CAP_MS / 1000) + ' s REACHED at read '
            + cappedAt.read + ' (' + cappedAt.section + '): the reads after it'
            + ' are recorded as not read, and their checks are UNKNOWN')
    }
    for (var sc = 0; sc < sections.length; sc++) {
        gs.print('section ' + sections[sc].section + ' ms ' + sections[sc].ms
            + ' reads ' + sections[sc].reads)
    }
    var slow = timings.slice(0)
    slow.sort(function (x, y) {
        return y.ms - x.ms
    })
    for (var sl = 0; sl < slow.length && sl < 5; sl++) {
        gs.print('slowest read ' + slow[sl].ms + ' ms ' + slow[sl].path
            + ' offset ' + slow[sl].offset)
    }
    gs.print('Save everything between the two markers as nowisor-scan-bundle.json')
    gs.print('')
    var printStart = new Date().getTime()
    var chars = 0
    gs.print(SEPARATOR)
    for (var pl = 0; pl < lines.length; pl++) {
        chars += lines[pl].length
        gs.print(lines[pl])
    }
    var endLine = { lines: lines.length, sha256: hash }
    gs.print('end ' + asciiSafe(JSON.stringify(endLine)))
    gs.print(END_SEPARATOR)
    gs.print('print ms ' + (new Date().getTime() - printStart) + ', lines '
        + lines.length + ', characters ' + chars)
})()
