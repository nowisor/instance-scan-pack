// nowisor v1.2.0 - Human-in-the-loop absent on write-capable agent (AIG-001)
// Flags agents that can write or delete without an approval step in their flow.
//
// WHAT "APPROVAL STEP" MEANS HERE
// Three observable signals, any one of which counts as a human gate:
//   1. execution_mode is supervised (the platform's own gate)
//   2. an approval record exists against the entity (sysapproval_approver)
//   3. the entity's flow references an approval activity
// None of the three, plus write reach, is the finding. The check does NOT treat
// "an admin could theoretically review the log afterwards" as a gate - after the
// fact is not in the loop.
//
// Write reach is evaluated from the run-as identity's roles, because that is
// what actually bounds the agent. An agent whose identity holds no roles cannot
// write regardless of what its instructions say, and is not reported.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object        - name
//   sys_dictionary       - name, element
//   sn_aia_use_case      - active, execution_mode
//   sys_user_has_role    - user, role
//   sysapproval_approver - verified table
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiGuardrailHitl(finding) {
    var CHECK_ID = 'nowisor-ai-guardrail-hitl'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')

    var NAME_HINTS = ['name', 'label', 'title']

    // Roles that imply broad write capability without needing ACL traversal.
    var WRITE_ROLES = ['admin', 'security_admin', 'itil_admin']
    WRITE_ROLES.push('itil')
    WRITE_ROLES.push('sn_incident_write')

    var MAPPINGS = {
        nis2: ['21.2.a', '21.2.i'],
        iso27001: ['A.8.2', 'A.5.15'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0053'],
        eu_ai_act: [{ article: '26', conditional: true }]
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

    function writeRoles(userId) {
        var hits = []
        try {
            var rg = new GlideRecord('sys_user_has_role')
            rg.addQuery('user', userId)
            rg.setLimit(ROW_CAP)
            rg.query()
            while (rg.next()) {
                var rn = rg.getDisplayValue('role')
                if (!rn) continue
                var lower = String(rn).toLowerCase()
                for (var i = 0; i < WRITE_ROLES.length; i++) {
                    if (lower === WRITE_ROLES[i]) hits.push(String(rn))
                }
            }
        } catch (e) {
            return null
        }
        return hits
    }

    function hasApproval(recordId) {
        try {
            var gr = new GlideRecord('sysapproval_approver')
            gr.addQuery('document_id', recordId)
            gr.setLimit(1)
            gr.query()
            return gr.next() ? true : false
        } catch (e) {
            return false
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
            'No agentic entity tables are present on this instance, so ' +
            'human-in-the-loop coverage cannot be assessed. Out of scope, NOT ' +
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
                remediation_id: 'aig-001-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- scan ------------------------------------------------------------
    var ungated = []
    var scanned = 0
    var unresolved = []

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var have = fieldsOf(tbl)
        var runF = pick(have, RUNAS_HINTS)
        if (!runF) {
            unresolved.push(tbl)
            continue
        }
        var nameF = pick(have, NAME_HINTS)
        var hasMode = have && have['execution_mode'] ? true : false
        try {
            var gr = new GlideRecord(tbl)
            if (have && have['active']) gr.addQuery('active', true)
            gr.addQuery(runF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scanned = scanned + 1
                var uid = gr.getValue(runF)
                if (!uid) continue

                var wr = writeRoles(uid)
                if (wr === null || wr.length === 0) continue

                // Gate 1: platform supervised mode.
                var mode = hasMode ? gr.getValue('execution_mode') : null
                if (mode && String(mode).toLowerCase().indexOf('supervis') !== -1) {
                    continue
                }
                // Gate 2: approval record against the entity.
                var rid = gr.getUniqueValue()
                if (hasApproval(rid)) continue

                var row = {}
                row.table = tbl
                row.sys_id = rid
                row.name = nameF ? gr.getValue(nameF) : null
                row.run_as = gr.getDisplayValue(runF) || uid
                row.execution_mode = mode
                row.execution_mode_resolved = hasMode
                row.write_roles = wr
                ungated.push(row)
            }
        } catch (e) {
            unresolved.push(tbl)
        }
    }

    if (scanned === 0) {
        emit(
            'Agentic entities are present, but no execution-identity field ' +
            'could be resolved on this release (' +
            unresolved.join(', ') +
            '), so write capability cannot be established. Review approval ' +
            'gating in AI Agent Studio directly. No posture failure is asserted.',
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
                remediation_id: 'aig-001-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (ungated.length === 0) return

    var examples = []
    for (var x = 0; x < ungated.length && x < 10; x++) {
        var nm = ungated[x].name ? ungated[x].name : ungated[x].sys_id
        examples.push(nm + ' (as ' + ungated[x].run_as + ')')
    }

    emit(
        ungated.length +
        ' of ' +
        scanned +
        ' active agents can change state with no human gate. Each holds a ' +
        'write-capable role, is not in supervised execution mode, and has no ' +
        'approval record: an agent decision becomes a platform write with ' +
        'nobody in the loop. ' +
        examples.join('; ') +
        '. Gates recognised by this check are supervised execution mode and an ' +
        'approval record against the entity. After-the-fact log review is not ' +
        'treated as a gate, because it is not in the loop.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                ungated_count: ungated.length,
                agents_scanned: scanned,
                write_roles_watched: WRITE_ROLES,
                gates_recognised: ['supervised_execution_mode', 'approval_record'],
                tables_unresolved: unresolved,
                row_cap: ROW_CAP,
                ungated: ungated
            },
            severity: 2,
            remediation_id: 'aig-001',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
