// Read-only: safe for production use
//
// nowisor sizing probe 1.1.0: run as an admin in Scripts - Background.
// Per table carrying most of bundle.js's size: the row total, the total of each
// query the bundle reads it with, and the ms each count took. GlideAggregate
// COUNTs only: no row content, no names, no sys_ids. v_plugin is not counted
// (pack 1.3.12 never reads it: a cold read makes the platform rebuild it).
// Prints the pack version and build string. Writes nothing. ES5, ASCII.

(function nowisorProbe() {
    var PACK_VERSION = '1.3.13'
    var TOOL_VERSION = '1.1.0'
    var ON = 'sys_security_acl.active=true^sys_security_acl.'
    var EMPTY = 'conditionISEMPTY^scriptISEMPTY'
    var ON_EMPTY = ON + 'conditionISEMPTY^sys_security_acl.scriptISEMPTY'
    var WILD = 'active=true^nameLIKE*^ORoperation=*'
    var ADMIN = 'role.name=admin^state=active^user.active=true'
    var DICT = 'elementLIKEpassword^ORelementLIKEsecret^ORelementLIKEtoken'
    DICT += '^ORelementLIKEkey^ORelementLIKEcredential'
    DICT += '^ORcolumn_labelLIKEpassword^ORcolumn_labelLIKEsecret'
    DICT += '^ORcolumn_labelLIKEtoken'
    var TYPED = DICT + '^internal_typeINstring,string_full_utf8,html,'
    TYPED += 'translated_text'
    var AUD = 'nameINsys_user,sys_user_has_role,sys_user_grmember,'
    AUD += 'discovery_credentials^element=NULL'
    var COUNTS = [
        ['sys_security_acl', 'all', ''],
        ['sys_security_acl', 'wildcard', WILD],
        ['sys_security_acl', 'scripted', 'active=true^scriptISNOTEMPTY'],
        ['sys_security_acl', 'empty', 'active=true^' + EMPTY],
        ['sys_security_acl_role', 'all', ''],
        ['sys_security_acl_role', 'on_scripted', ON + 'scriptISNOTEMPTY'],
        ['sys_security_acl_role', 'on_empty', ON_EMPTY],
        ['sys_db_object', 'all', ''],
        ['sys_dictionary', 'all', ''],
        ['sys_dictionary', 'secret_typed', TYPED],
        ['sys_dictionary', 'audit_rows', AUD],
        ['sys_properties', 'all', ''],
        ['sys_properties', 'walk', 'type!=password^type!=password2'],
        ['sys_scope', 'all', ''],
        ['sys_store_app', 'all', ''],
        ['sys_user_has_role', 'all', ''],
        ['sys_user_has_role', 'admin', ADMIN],
        ['sysauto_script', 'run_as', 'run_asISNOTEMPTY'],
        ['sys_plugins', 'all', '']
    ]
    // One count, or null - never a row.
    function count(t, query) {
        try {
            var g = new GlideAggregate(t)
            if (!g.isValid()) {
                return null
            }
            if (query) {
                g.addEncodedQuery(query)
            }
            g.addAggregate('COUNT')
            g.query()
            return g.next() ? parseInt(g.getAggregate('COUNT'), 10) : null
        } catch (e) {
            return null
        }
    }

    function build() {
        var names = ['glide.buildtag.last', 'glide.buildtag', 'glide.war']
        for (var i = 0; i < names.length; i++) {
            var v = String(gs.getProperty(names[i], ''))
            if (v) {
                return v + ' (' + names[i] + ')'
            }
        }
        return 'not read'
    }
    var start = new Date().getTime()
    gs.print('nowisor probe ' + TOOL_VERSION + ' pack ' + PACK_VERSION)
    gs.print('build ' + build())
    for (var c = 0; c < COUNTS.length; c++) {
        var t0 = new Date().getTime()
        var n = count(COUNTS[c][0], COUNTS[c][2])
        // "unread", never 0: a failed count, or a total of 0 (silent fail)
        var all0 = n === 0 && COUNTS[c][1] === 'all'
        if (all0 && COUNTS[c][0] !== 'sys_store_app') {
            n = null
        }
        var rows = typeof n === 'number' && !isNaN(n) ? String(n) : 'unread'
        var line = COUNTS[c][0] + ' ' + COUNTS[c][1] + ' rows=' + rows
        gs.print(line + ' ms=' + (new Date().getTime() - t0))
    }
    gs.print('probe ms ' + (new Date().getTime() - start))
})()
