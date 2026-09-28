// Read-only: safe for production use
//
// nowisor bundle tool v1.0.0 - emits nowisor-scan-bundle schema 1
// Paste-into-Background-Script offline mode: no connection, no credentials.
//
// The fifth install-free sensor in tools/. Performs, inside your instance,
// the SAME reads the nowisor advisor makes over the REST Table API when an
// instance is connected, and prints them as one JSON document you save as
// nowisor-scan-bundle.json and upload (Instances > Upload results). The
// advisor replays these reads through the code a connected scan runs;
// nothing here scores, correlates or judges.
// Nothing is derived: every entry in `reads` is a table read as the Table API
// would have answered it (raw values, reference fields as {link, value}).
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
// `sha256` is the SHA-256 of the canonical JSON of everything else in the
// document (keys sorted at every depth, no whitespace). The advisor recomputes
// it and refuses a file that does not match: edit nothing between here and the
// upload. The hash is printed below and appears on every report as the
// integrity reference; the printed run-by account and instance ID are the
// attribution.
//
// Run it as an admin. Every read is a GlideRecordSecure query (the rows the
// running user may read) or a GlideAggregate count. Nothing is written.
//
// Verified identifiers: the tables and fields are the ones the advisor's
// connected scan reads (published at nowisor.com/access), no others.
//
// ES5-only (Rhino ES0). ASCII-only, short lines, one statement per line.

(function nowisorBundle() {
    var BUNDLE_SCHEMA = 1
    var PACK_VERSION = '1.3.2'
    var TOOL_VERSION = '1.0.0'
    var SEPARATOR = '---NOWISOR_BUNDLE---'
    var END_SEPARATOR = '---NOWISOR_BUNDLE_END---'
    var PRINT_CHUNK = 4000
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

    function glideTable(path, params, wantCount) {
        var gr = new GlideRecordSecure(path)
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
        var fields = fieldList(params)
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
        if (wantCount) {
            total = glideCount(path, query)
        }
        return { result: rows, total_count: total }
    }

    function glideStats(path) {
        return { count: glideCount(path, '') }
    }

    // --- Recording --------------------------------------------------------
    var reads = []

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
    function table(path, params, wantCount) {
        var p = copy(params)
        var ans = null
        try {
            if (hook) {
                ans = hook('table', path, p)
            } else {
                ans = glideTable(path, p, wantCount)
            }
        } catch (e) {
            ans = { error: { code: 'SN_API_ERROR:500', message: String(e) } }
        }
        if (ans.error) {
            reads.push({ kind: 'table', path: path, params: p, error: ans.error })
            return { error: ans.error }
        }
        var rows = redactRows(path, ans.result || [])
        var total = null
        if (wantCount && typeof ans.total_count === 'number') {
            total = ans.total_count
        }
        var entry = { kind: 'table', path: path, params: p, result: rows }
        entry.total_count = total
        reads.push(entry)
        return { result: rows, total: total }
    }

    function stats(path) {
        var ans = hook ? hook('stats', path, { sysparm_count: 'true' }) : glideStats(path)
        var count = typeof ans.count === 'number' ? ans.count : null
        reads.push({
            kind: 'stats', path: path,
            params: { sysparm_count: 'true' }, count: count
        })
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

    var ENC_PLUGINS = ['com.glide.encryption.core', 'com.snc.db_encryption']
    ENC_PLUGINS.push('com.glide.column_encryption')

    var LIKE_PATTERNS = ['eval(', 'new Function(', 'GlideEvaluator']
    LIKE_PATTERNS.push('GlideScopedEvaluator')
    LIKE_PATTERNS.push('setWorkflow(false)')

    var ADMIN_Q = 'role.name=admin^state=active^user.active=true'
    var SECADMIN_Q = 'role.name=security_admin^state=active^user.active=true'

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
    var cand = table('sys_security_acl', {
        sysparm_query: 'active=true^conditionISEMPTY^scriptISEMPTY',
        sysparm_fields: 'sys_id,name,type,operation',
        sysparm_limit: '500'
    })
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
    // OAuth applications
    table('oauth_entity', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,type,grant_type,access_token_lifespan,'
            + 'refresh_token_lifespan',
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
    // knowledge base access
    var kbs = table('kb_knowledge_base', {
        sysparm_query: 'active=true',
        sysparm_fields: 'title,sys_id',
        sysparm_limit: '20'
    })
    if (!kbs.error) {
        for (var k = 0; k < kbs.result.length; k++) {
            table('kb_uc_can_read_mtom', {
                sysparm_query: 'kb_knowledge_base=' + kbs.result[k].sys_id,
                sysparm_fields: 'user_criteria.name',
                sysparm_limit: '10'
            })
        }
    }
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
    for (var l = 0; l < LIKE_PATTERNS.length; l++) {
        table('sys_script_include', {
            sysparm_query: 'client_callable=true^active=true^scriptLIKE'
                + LIKE_PATTERNS[l],
            sysparm_fields: 'name',
            sysparm_limit: '200'
        })
    }
    table('sys_ws_definition', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,api_id,enforced,version,active,sys_scope.name',
        sysparm_limit: '1000'
    })
    table('sys_ws_operation', {
        sysparm_query: 'active=true',
        sysparm_fields: 'name,http_method,operation_uri,enforce_acl,enforced,'
            + 'web_service_definition.name',
        sysparm_limit: '5000'
    })
    table('sys_plugins', {
        sysparm_query: 'active=active',
        sysparm_fields: 'name,source',
        sysparm_limit: '500'
    })
    table('sysauto_script', {
        sysparm_query: 'ORDERBYDESCsys_updated_on',
        sysparm_fields: 'name,run_as,run_as.user_name,active',
        sysparm_limit: '500'
    })
    table('sys_dictionary', {
        sysparm_query: 'audit=true^element=',
        sysparm_fields: 'name',
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
    table('sys_dictionary', {
        sysparm_query: dict,
        sysparm_fields: 'name,element,column_label,internal_type',
        sysparm_limit: '1000'
    })
    var detailed = table('sys_security_acl', {
        sysparm_query: 'active=true',
        sysparm_fields: 'sys_id,name,type,operation,condition,script',
        sysparm_limit: '2000'
    })
    if (!detailed.error) {
        roleGated(detailed.result)
    }
    var encIds = []
    for (var e = 0; e < ENC_PLUGINS.length; e++) {
        encIds.push('id=' + ENC_PLUGINS[e])
    }
    var enc = table('v_plugin', {
        sysparm_query: encIds.join('^OR'),
        sysparm_fields: 'id,name,active',
        sysparm_limit: '20'
    })
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

    // --- The capabilities probe (lib/capabilities-probe.js PROBE_TARGETS) ---
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

    // --- The tenant reading (lib/ncf/tenant-schema-extractor.js) ------------
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
    var vp = table('v_plugin', {
        sysparm_fields: 'id,name,version,active,description,link_version',
        sysparm_limit: '2000'
    })
    if (vp.error && isGraceful(vp.error)) {
        table('sys_plugins', {
            sysparm_fields: 'sys_id,name,source,active,description,version',
            sysparm_limit: '2000'
        })
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
        var props = table('sys_properties', {
            sysparm_fields: 'name,value,type',
            sysparm_limit: '5000',
            sysparm_offset: String(offset)
        })
        if (props.error || props.result.length < 5000) {
            break
        }
        offset += 5000
    }
    var INV = [['sys_store_app'], ['sys_scope']]
    for (var iv = 0; iv < INV.length; iv++) {
        var itab = INV[iv][0]
        stats(itab)
        for (var ip = 0; ip < 50; ip++) {
            var page = table(itab, {
                sysparm_fields: 'name,version,active,scope,sys_id',
                sysparm_limit: '2000',
                sysparm_offset: String(ip * 2000)
            })
            if (page.error || page.result.length === 0) {
                break
            }
        }
    }

    // --- The document -------------------------------------------------------
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

    var doc = {
        bundle_schema: BUNDLE_SCHEMA,
        pack_version: PACK_VERSION,
        tool_version: TOOL_VERSION,
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
        duration_ms: new Date().getTime() - startMs,
        reads: reads
    }
    var canonical = JSON.stringify(sortKeys(doc))
    var hash = String(new GlideDigest().getSHA256Hex(canonical)).toLowerCase()
    doc.sha256 = hash
    // The printed form escapes every space, <, >, & and non-ASCII character as
    // \uXXXX. It is the same JSON (it parses to the same document the hash was
    // taken over) but it survives a browser: no whitespace to collapse, no
    // markup to interpret, nothing outside ASCII to re-encode.
    var out = asciiSafe(JSON.stringify(sortKeys(doc)))

    gs.print('nowisor bundle schema ' + BUNDLE_SCHEMA)
    gs.print('pack ' + PACK_VERSION)
    gs.print('instance ' + doc.instance_url + ' (' + doc.instance_id + ')')
    gs.print('captured ' + capturedAt + ' reads ' + reads.length)
    gs.print('SHA-256 ' + hash)
    gs.print('Save everything between the two markers as nowisor-scan-bundle.json')
    gs.print('')
    gs.print(SEPARATOR)
    for (var o = 0; o < out.length; o += PRINT_CHUNK) {
        gs.print(out.substring(o, o + PRINT_CHUNK))
    }
    gs.print(END_SEPARATOR)
})()
