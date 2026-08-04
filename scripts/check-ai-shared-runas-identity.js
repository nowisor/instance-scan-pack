// nowisor v1.2.0 - Shared agent run-as identity check (AIA-006)
// Flags multiple agentic entities executing under one service account.
//
// WHY ATTRIBUTION LOSS IS A SECURITY FINDING, NOT HOUSEKEEPING
// When five agents share svc_ai, every row they write carries the same
// sys_created_by. Post-incident you can prove "an agent did this" but never
// which agent, under whose prompt, from which trigger. That defeats the
// forensic reconstruction NIS2 Art.21(2)(b) expects, and it makes per-agent
// least-privilege impossible: the shared account's role set is necessarily the
// union of what every agent needs, so each agent inherits the others' reach.
//
// Severity does NOT scale with the number of agents; it scales with whether the
// shared identity can write. A shared read-only reporting identity is untidy,
// a shared writer is an attribution hole with blast radius. The check reports
// both and separates them in the evidence.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object     - name
//   sys_dictionary    - name, element
//   sys_user_has_role - user, role
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiSharedRunasIdentity(finding) {
    var CHECK_ID = 'nowisor-ai-shared-runas-identity'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')
    RUNAS_HINTS.push('caller')

    var NAME_HINTS = ['name', 'label', 'title']

    var MAPPINGS = {
        nis2: ['21.2.b', '21.2.i'],
        iso27001: ['A.5.16', 'A.8.15'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0012'],
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

    // Does this identity hold any role at all? A role-holding shared identity
    // is the one that carries blast radius.
    function roleCount(userId) {
        try {
            var gr = new GlideRecord('sys_user_has_role')
            gr.addQuery('user', userId)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n = n + 1
            return n
        } catch (e) {
            return -1
        }
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- gate ------------------------------------------------------------
    var present = []
    for (var i = 0; i < SOURCES.length; i++) {
        if (tableExists(SOURCES[i])) present.push(SOURCES[i])
    }

    if (present.length === 0) {
        emit(
            'No agentic entity tables are present on this instance, so agent ' +
            'execution-identity sharing cannot be assessed. Out of scope, NOT ' +
            'a pass.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agentic_tables',
                    tables_probed: SOURCES
                },
                severity: 4,
                remediation_id: 'ai-006-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- group by run-as identity ----------------------------------------
    var byIdentity = {}
    var identities = []
    var scanned = 0
    var unresolved = []

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var runF = pickField(tbl, RUNAS_HINTS)
        if (!runF) {
            unresolved.push(tbl)
            continue
        }
        var nameF = pickField(tbl, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.addQuery(runF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scanned = scanned + 1
                var uid = gr.getValue(runF)
                if (!uid) continue
                if (!byIdentity[uid]) {
                    byIdentity[uid] = {
                        user_id: uid,
                        display: gr.getDisplayValue(runF) || uid,
                        agents: []
                    }
                    identities.push(uid)
                }
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.name = nameF ? gr.getValue(nameF) : null
                byIdentity[uid].agents.push(row)
            }
        } catch (e) {
            unresolved.push(tbl)
        }
    }

    if (scanned === 0) {
        emit(
            'Agentic entities are present, but no run-as / execution identity ' +
            'field could be resolved on this release (' +
            unresolved.join(', ') +
            '). Review execution identities in AI Agent Studio directly. No ' +
            'posture failure is asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'runas_field_unresolved',
                    tables_present: present,
                    tables_unresolved: unresolved
                },
                severity: 4,
                remediation_id: 'ai-006-na',
                attack_path_refs: []
            }
        )
        return
    }

    var shared = []
    var anyRoleHolding = false
    for (var k = 0; k < identities.length; k++) {
        var grp = byIdentity[identities[k]]
        if (grp.agents.length < 2) continue
        grp.agent_count = grp.agents.length
        grp.role_count = roleCount(grp.user_id)
        if (grp.role_count > 0) anyRoleHolding = true
        shared.push(grp)
    }

    if (shared.length === 0) return

    var examples = []
    var totalAffected = 0
    for (var x = 0; x < shared.length && x < 10; x++) {
        totalAffected = totalAffected + shared[x].agent_count
        var rc = shared[x].role_count
        var roleNote = rc < 0 ? 'roles unreadable' : rc + ' role(s)'
        examples.push(
            shared[x].display + ' runs ' + shared[x].agent_count +
            ' agents, holds ' + roleNote
        )
    }

    var tail
    if (anyRoleHolding) {
        tail =
            'At least one shared identity holds platform roles, so each agent ' +
            'inherits the union of what all of them need - per-agent ' +
            'least-privilege is not achievable while the account is shared.'
    } else {
        tail =
            'None of the shared identities hold platform roles, which bounds ' +
            'the blast radius; the attribution gap remains.'
    }

    emit(
        shared.length +
        ' execution identit(ies) are shared by multiple agentic entities (' +
        totalAffected +
        ' agents affected of ' +
        scanned +
        ' scanned). Every record these agents write carries the same actor, so ' +
        'a post-incident review can establish that an agent acted but not ' +
        'which one, under which prompt, from which trigger. ' +
        examples.join('; ') +
        '. ' +
        tail,
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                shared_identity_count: shared.length,
                agents_affected: totalAffected,
                agents_scanned: scanned,
                any_identity_holds_roles: anyRoleHolding,
                tables_unresolved: unresolved,
                row_cap: ROW_CAP,
                shared_identities: shared
            },
            severity: anyRoleHolding ? 2 : 3,
            remediation_id: 'ai-006',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
