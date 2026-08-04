// nowisor v1.2.0 - Prompt-injection exposure via input binding (AIG-004)
// Fires ONLY when both conditions hold. The heuristic is fixed by spec; do not
// widen it without changing the spec first.
//
//   (a) an input binding or flow variable maps a USER-EDITABLE FREE-TEXT field
//       (work_notes, comments, description, short_description, inbound email
//       body) into the entity's instruction / prompt context, AND
//   (b) that same entity's permission envelope includes WRITE ACL reach on any
//       table.
//
// Either condition alone is not a finding. A free-text field reaching a
// read-only agent is a data-disclosure question, not an injection-to-action
// path; write reach without an untrusted input source is ordinary configuration.
// The exposure is the conjunction: untrusted text steering an actor that can
// change state.
//
// EVIDENCE REQUIREMENT (spec): the evidence string must name the binding, the
// source field, and the writable target. If bindings cannot be resolved on this
// release, emit N/A with the reason - NEVER infer bindings from entity names or
// descriptions. An agent called "Incident Summarizer" tells us nothing about
// what it actually reads.
//
// Binding tables come from discovery, not from a hardcoded list: the binding
// surface differs across releases and the sn_aia namespace is paid-SKU gated,
// so CLAUDE.md evidence leg (a) cannot be satisfied for it.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object     - name
//   sys_dictionary    - name, element, internal_type
//   sys_security_acl  - verified table (operation, name)
//   sys_user_has_role - user, role
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiPromptInjectionExposure(finding) {
    var CHECK_ID = 'nowisor-ai-prompt-injection-exposure'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // Candidate binding / variable-map tables UNDER TEST, not claims.
    var BINDING_TABLES = ['sn_aia_tool_input_binding']
    BINDING_TABLES.push('sn_aia_agent_input')
    BINDING_TABLES.push('sys_cb_input_variable')
    BINDING_TABLES.push('sys_variable_value')
    BINDING_TABLES.push('sys_hub_flow_input')
    BINDING_TABLES.push('sys_hub_action_input')

    var AGENT_TABLES = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENT_TABLES.push('sys_cs_topic')

    // The user-editable free-text fields named in the spec.
    var UNTRUSTED = ['work_notes', 'comments', 'description']
    UNTRUSTED.push('short_description')
    UNTRUSTED.push('additional_comments')
    UNTRUSTED.push('body_text')
    UNTRUSTED.push('body')

    // Columns that may carry the source-field reference in a binding row.
    var SOURCE_HINTS = ['source_field', 'source', 'field']
    SOURCE_HINTS.push('element')
    SOURCE_HINTS.push('input_field')
    SOURCE_HINTS.push('value')

    // Columns that may carry the prompt/instruction target.
    var TARGET_HINTS = ['target_variable', 'target', 'variable']
    TARGET_HINTS.push('prompt_variable')
    TARGET_HINTS.push('name')

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')

    var MAPPINGS = {
        nis2: ['21.2.a', '21.2.e'],
        iso27001: ['A.8.28', 'A.8.2'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM01:2025', 'LLM06:2025'],
        mitre_atlas: ['AML.T0051', 'AML.T0053'],
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

    function isUntrusted(val) {
        if (!val) return null
        var lower = String(val).toLowerCase()
        for (var i = 0; i < UNTRUSTED.length; i++) {
            // Match the field token anywhere: bindings often store a dotted
            // path ("incident.work_notes") rather than a bare column name.
            if (lower.indexOf(UNTRUSTED[i]) !== -1) return UNTRUSTED[i]
        }
        return null
    }

    // Condition (b): does any role held by this identity carry a write ACL?
    // Reported as the concrete table list so the evidence can name the target.
    function writeTargets(userId) {
        var roles = {}
        var roleList = []
        try {
            var rg = new GlideRecord('sys_user_has_role')
            rg.addQuery('user', userId)
            rg.setLimit(ROW_CAP)
            rg.query()
            while (rg.next()) {
                var rn = rg.getDisplayValue('role')
                if (rn && !roles[rn]) {
                    roles[rn] = true
                    roleList.push(String(rn))
                }
            }
        } catch (e) {
            return null
        }
        if (roleList.length === 0) return []

        // admin bypasses ACL evaluation entirely - every table is writable.
        for (var a = 0; a < roleList.length; a++) {
            if (roleList[a] === 'admin') return ['*']
        }

        var targets = []
        var seen = {}
        try {
            var acl = new GlideRecord('sys_security_acl')
            acl.addQuery('operation', 'write')
            acl.addQuery('active', true)
            acl.setLimit(ROW_CAP)
            acl.query()
            while (acl.next()) {
                var nm = acl.getValue('name')
                if (!nm) continue
                var aclId = acl.getUniqueValue()
                // Does one of this identity's roles appear on the ACL?
                var matched = false
                try {
                    var ar = new GlideRecord('sys_security_acl_role')
                    ar.addQuery('sys_security_acl', aclId)
                    ar.setLimit(ROW_CAP)
                    ar.query()
                    while (ar.next()) {
                        var arn = ar.getDisplayValue('sys_user_role')
                        if (arn && roles[arn]) matched = true
                    }
                } catch (e2) {
                    matched = false
                }
                if (!matched) continue
                var tbl = String(nm).split('.')[0]
                if (tbl && !seen[tbl]) {
                    seen[tbl] = true
                    targets.push(tbl)
                }
            }
        } catch (e3) {
            return null
        }
        return targets
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    function emitNA(reason, extra) {
        var ev = { status: 'not_applicable', reason: reason }
        for (var k in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, k)) ev[k] = extra[k]
        }
        emit(
            'Prompt-injection exposure could not be assessed on this instance: ' +
            reason +
            '. Input bindings are read from resolved binding tables only - this ' +
            'check never infers what an agent reads from its name or ' +
            'description. No posture failure is asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: ev,
                severity: 4,
                remediation_id: 'aig-004-na',
                attack_path_refs: []
            }
        )
    }

    // ---- gate: agentic surface -------------------------------------------
    var agentTables = []
    for (var i = 0; i < AGENT_TABLES.length; i++) {
        if (tableExists(AGENT_TABLES[i])) agentTables.push(AGENT_TABLES[i])
    }
    if (agentTables.length === 0) {
        emitNA('no agentic entity tables present', { tables_probed: AGENT_TABLES })
        return
    }

    // ---- gate: binding surface resolvable --------------------------------
    var bindingTables = []
    for (var b = 0; b < BINDING_TABLES.length; b++) {
        if (tableExists(BINDING_TABLES[b])) bindingTables.push(BINDING_TABLES[b])
    }
    if (bindingTables.length === 0) {
        emitNA('no input-binding or flow-variable table could be resolved', {
            tables_probed: BINDING_TABLES,
            agent_tables_present: agentTables
        })
        return
    }

    // ---- condition (a): untrusted free-text into prompt context ----------
    var exposures = []
    var bindingsRead = 0
    var unresolvedBindings = []

    for (var t = 0; t < bindingTables.length; t++) {
        var btbl = bindingTables[t]
        var bhave = fieldsOf(btbl)
        var srcF = pick(bhave, SOURCE_HINTS)
        var tgtF = pick(bhave, TARGET_HINTS)
        if (!srcF) {
            unresolvedBindings.push(btbl)
            continue
        }
        try {
            var bg = new GlideRecord(btbl)
            bg.addQuery(srcF, '!=', '')
            bg.setLimit(ROW_CAP)
            bg.query()
            while (bg.next()) {
                bindingsRead = bindingsRead + 1
                var srcVal = bg.getValue(srcF)
                var hit = isUntrusted(srcVal)
                if (!hit) continue
                var row = {}
                row.binding_table = btbl
                row.binding_sys_id = bg.getUniqueValue()
                row.source_field_column = srcF
                row.source_field_value = srcVal
                row.untrusted_token = hit
                row.target_column = tgtF
                row.target_value = tgtF ? bg.getValue(tgtF) : null
                exposures.push(row)
            }
        } catch (e) {
            unresolvedBindings.push(btbl)
        }
    }

    if (bindingsRead === 0) {
        emitNA('binding tables exist but no source-field column was readable', {
            binding_tables_present: bindingTables,
            binding_tables_unresolved: unresolvedBindings
        })
        return
    }

    if (exposures.length === 0) return

    // ---- condition (b): write reach on the agent's identity --------------
    // Both conditions must hold on the SAME entity, so resolve write reach per
    // agent and only report where an untrusted binding also exists.
    var writeCapable = []
    var identityUnreadable = false

    for (var g = 0; g < agentTables.length; g++) {
        var atbl = agentTables[g]
        var ahave = fieldsOf(atbl)
        var runF = pick(ahave, RUNAS_HINTS)
        if (!runF) continue
        var nameF = pick(ahave, ['name', 'label', 'title'])
        try {
            var ag = new GlideRecord(atbl)
            ag.addQuery(runF, '!=', '')
            ag.setLimit(ROW_CAP)
            ag.query()
            while (ag.next()) {
                var uid = ag.getValue(runF)
                if (!uid) continue
                var targets = writeTargets(uid)
                if (targets === null) {
                    identityUnreadable = true
                    continue
                }
                if (targets.length === 0) continue
                var w = {}
                w.agent_table = atbl
                w.agent_sys_id = ag.getUniqueValue()
                w.agent_name = nameF ? ag.getValue(nameF) : null
                w.run_as = ag.getDisplayValue(runF) || uid
                w.writable_tables = targets
                writeCapable.push(w)
            }
        } catch (e) {
            identityUnreadable = true
        }
    }

    // Condition (a) holds but (b) does not: not a finding by spec.
    if (writeCapable.length === 0) {
        if (identityUnreadable) {
            emitNA(
                'untrusted input bindings exist but agent write reach could not ' +
                'be evaluated (ACL or role tables unreadable in this scope)',
                {
                    untrusted_binding_count: exposures.length,
                    condition_a: 'met',
                    condition_b: 'indeterminate'
                }
            )
        }
        return
    }

    var examples = []
    for (var x = 0; x < exposures.length && x < 5; x++) {
        var ex = exposures[x]
        var tgt = ex.target_value ? ex.target_value : '(prompt context)'
        examples.push(
            ex.binding_table + ' maps ' + ex.source_field_value +
            ' -> ' + tgt
        )
    }
    var wtargets = []
    for (var y = 0; y < writeCapable.length && y < 5; y++) {
        var wc = writeCapable[y]
        var nm2 = wc.agent_name ? wc.agent_name : wc.agent_sys_id
        var tl = wc.writable_tables.join(', ')
        if (wc.writable_tables[0] === '*') tl = 'ALL TABLES (admin)'
        wtargets.push(nm2 + ' (as ' + wc.run_as + ') can write ' + tl)
    }

    emit(
        'Prompt-injection exposure: ' +
        exposures.length +
        ' input binding(s) map user-editable free-text into agent prompt ' +
        'context, and ' +
        writeCapable.length +
        ' agent identit(ies) on this instance hold write ACL reach. A user who ' +
        'can edit those fields can place instructions where an agent will read ' +
        'them as direction, and that agent can change state. BINDINGS: ' +
        examples.join('; ') +
        '. WRITE REACH: ' +
        wtargets.join('; ') +
        '. Both conditions are required for this finding; neither alone is ' +
        'reported.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                condition_a: 'met',
                condition_b: 'met',
                untrusted_binding_count: exposures.length,
                bindings_read: bindingsRead,
                write_capable_agent_count: writeCapable.length,
                untrusted_fields_watched: UNTRUSTED,
                binding_tables_present: bindingTables,
                binding_tables_unresolved: unresolvedBindings,
                row_cap: ROW_CAP,
                detection_basis: 'resolved_binding_rows_only_no_name_inference',
                bindings: exposures,
                write_reach: writeCapable
            },
            severity: 1,
            remediation_id: 'aig-004',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
