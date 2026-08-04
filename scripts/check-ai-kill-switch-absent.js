// nowisor v1.2.0 - Agent kill-switch absent (AIG-005)
// Checks for a MACHINE-CHECKABLE deactivation path per agent class. Emits
// INVESTIGATE with a manual-attestation field when none is found - never FAIL.
//
// WHY THIS CHECK REFUSES TO FAIL
// "A documented kill procedure exists" is not scannable. A runbook in Confluence
// is invisible to a read-only instance scan, and an organisation with an
// excellent operational procedure would score identically to one with none. So
// the check reports only what it can actually observe - the presence or absence
// of a TECHNICAL path - and asks the customer to attest to the rest. Emitting
// FAIL here would be asserting the absence of something we cannot see, which is
// the inverse of the discipline the rest of this module holds to.
//
// A technical deactivation path is any ONE of:
//   1. a per-class disable PROPERTY  (gs.getProperty resolves it)
//   2. a plugin / feature TOGGLE     (the class's plugin is separately
//                                     deactivatable, so the substrate can go)
//   3. an active FLAG on the entity  (an 'active' column that can be flipped)
//   4. a revocable ROLE whose removal stops execution (the run-as identity
//                                      holds a role that gates the agent)
// Any one of these means an operator can stop the agent from the platform
// without a code change. None of them means the only lever is a support ticket.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object     - name
//   sys_dictionary    - name, element
//   v_plugin          - id   (ONLY id is verified)
//   sys_user_has_role - user, role
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiKillSwitchAbsent(finding) {
    var CHECK_ID = 'nowisor-ai-kill-switch-absent'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // One entry per agent class we assess independently.
    var CLASSES = [
        {
            label: 'AI Agent use cases',
            table: 'sn_aia_use_case',
            plugins: ['com.glide.now_assist', 'com.snc.now_assist'],
            props: ['sn_aia.enabled', 'glide.aia.enabled']
        },
        {
            label: 'Conversational AI agents',
            table: 'sys_cb_ai_agent',
            plugins: ['com.glide.cs.chatbot'],
            props: ['glide.cs.enabled', 'sn_cs.enabled']
        },
        {
            label: 'Virtual Agent topics',
            table: 'sys_cs_topic',
            plugins: ['com.glide.cs.chatbot'],
            props: ['glide.cs.enabled']
        },
        {
            label: 'Inbound external agents (MCP / Action Fabric)',
            table: 'sys_mcp_server',
            plugins: ['com.glide.mcp_server', 'com.glide.action_fabric'],
            props: ['glide.mcp.enabled', 'sn_mcp.enabled']
        }
    ]

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')

    var MAPPINGS = {
        nis2: ['21.2.b', '21.2.c'],
        iso27001: ['A.5.24', 'A.5.26'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0053'],
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

    // NOTE: a property that resolves is a real lever. A property that does NOT
    // resolve is recorded as absent and nothing more - it is never reported as
    // a fabricated or expected name. The candidate lists above are probe
    // targets, not claims about the platform.
    function propResolves(name) {
        try {
            var v = gs.getProperty(name, '__NOWISOR_NOT_FOUND__')
            return String(v) !== '__NOWISOR_NOT_FOUND__'
        } catch (e) {
            return false
        }
    }

    function pluginPresent(id) {
        try {
            var p = new GlideRecord('v_plugin')
            p.addQuery('id', id)
            p.setLimit(1)
            p.query()
            return p.next() ? true : false
        } catch (e) {
            return false
        }
    }

    function anyRunAsRole(tbl, runF) {
        try {
            var g = new GlideRecord(tbl)
            g.addQuery(runF, '!=', '')
            g.setLimit(25)
            g.query()
            while (g.next()) {
                var uid = g.getValue(runF)
                if (!uid) continue
                var rg = new GlideRecord('sys_user_has_role')
                rg.addQuery('user', uid)
                rg.setLimit(1)
                rg.query()
                if (rg.next()) return true
            }
        } catch (e) {
            return false
        }
        return false
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- assess each present class ---------------------------------------
    var assessed = []
    var lacking = []

    for (var c = 0; c < CLASSES.length; c++) {
        var cls = CLASSES[c]
        if (!tableExists(cls.table)) continue

        var have = fieldsOf(cls.table)
        var levers = []

        // 1. per-class disable property
        var propHit = null
        for (var p = 0; p < cls.props.length; p++) {
            if (propResolves(cls.props[p])) {
                propHit = cls.props[p]
                break
            }
        }
        if (propHit) levers.push('disable_property:' + propHit)

        // 2. plugin toggle
        var plugHit = null
        for (var g2 = 0; g2 < cls.plugins.length; g2++) {
            if (pluginPresent(cls.plugins[g2])) {
                plugHit = cls.plugins[g2]
                break
            }
        }
        if (plugHit) levers.push('plugin_toggle:' + plugHit)

        // 3. per-entity active flag
        if (have && have['active']) levers.push('entity_active_flag')

        // 4. revocable role on the run-as identity
        var runF = pick(have, RUNAS_HINTS)
        if (runF && anyRunAsRole(cls.table, runF)) {
            levers.push('revocable_runas_role')
        }

        var row = {}
        row.agent_class = cls.label
        row.table = cls.table
        row.technical_levers = levers
        row.lever_count = levers.length
        assessed.push(row)
        if (levers.length === 0) lacking.push(row)
    }

    if (assessed.length === 0) {
        emit(
            'No agent classes are present on this instance, so deactivation ' +
            'paths cannot be assessed. Out of scope, NOT a pass.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agent_classes_present',
                    classes_probed: CLASSES.length
                },
                severity: 4,
                remediation_id: 'aig-005-na',
                attack_path_refs: []
            }
        )
        return
    }

    // Every present class has at least one technical lever: nothing to report.
    if (lacking.length === 0) return

    var names = []
    for (var x = 0; x < lacking.length; x++) {
        names.push(lacking[x].agent_class + ' (' + lacking[x].table + ')')
    }

    emit(
        'INVESTIGATE: ' +
        lacking.length +
        ' of ' +
        assessed.length +
        ' agent class(es) present on this instance expose no machine-checkable ' +
        'deactivation path - no per-class disable property, no separately ' +
        'deactivatable plugin, no per-entity active flag, and no revocable role ' +
        'on the execution identity. Classes: ' +
        names.join('; ') +
        '. WHAT THIS DOES NOT CLAIM: an operational kill procedure may well ' +
        'exist - a runbook, an on-call step, a vendor escalation - and a ' +
        'read-only scan cannot see any of it. This is NOT reported as a ' +
        'failure. Confirm the procedure exists and record it against the ' +
        'manual_attestation field, or add a technical lever so the control ' +
        'becomes verifiable.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'investigate',
                claim_boundary: 'technical_levers_only_procedure_not_scannable',
                classes_assessed: assessed.length,
                classes_lacking_lever: lacking.length,
                levers_tested: [
                    'per_class_disable_property',
                    'plugin_toggle',
                    'entity_active_flag',
                    'revocable_runas_role'
                ],
                manual_attestation: {
                    required: true,
                    question:
                        'Does a documented operational procedure exist to stop ' +
                        'each listed agent class, and has it been tested?',
                    answer: null
                },
                assessment: assessed
            },
            severity: 3,
            remediation_id: 'aig-005-investigate',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
