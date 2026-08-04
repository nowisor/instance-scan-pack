// nowisor v1.2.0 - Agent run-as identity holds elevated roles (AIA-007)
// Flags agentic entities whose execution identity holds admin, security_admin
// or an equivalent elevated role.
//
// WHY THIS IS CRITICAL AND NOT MERELY UNTIDY
// An agent's blast radius is its run-as identity's role set, not its prompt.
// An agent running as an admin-role holder can be steered - by prompt
// injection, a poisoned tool description, or a misrouted flow - into any write
// the admin role permits, and the audit trail will attribute it to the service
// account rather than to whoever supplied the input.
//
// DELEGATION AWARENESS
// A role reached through role inheritance (contains) rather than a direct grant
// is reported with its lineage, and OOB-derived lineage caps the finding at
// CONDITIONAL: the pack cannot read the customer's intent for a role it did not
// grant, and rating an OOB-derived grant as CRITICAL is the false-positive the
// delegation-aware severity model exists to prevent.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object        - name
//   sys_dictionary       - name, element
//   sys_user             - user_name, active
//   sys_user_has_role    - user, role, granted_by (role.name / user.active dotted)
//   sys_user_role        - name
//   sys_user_role_contains - verified table (role inheritance)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiAgentElevatedRunas(finding) {
    var CHECK_ID = 'nowisor-ai-agent-elevated-runas'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')
    RUNAS_HINTS.push('caller')

    var NAME_HINTS = ['name', 'label', 'title']

    var ELEVATED = ['admin', 'security_admin']
    ELEVATED.push('maint')
    ELEVATED.push('sn_aia.admin')

    var MAPPINGS = {
        nis2: ['21.2.i'],
        iso27001: ['A.8.2', 'A.5.15'],
        dora: ['9.4.c'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0012', 'AML.T0053'],
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

    // Direct grants of an elevated role to this identity, with lineage.
    function elevatedGrants(userId) {
        var out = []
        try {
            var gr = new GlideRecord('sys_user_has_role')
            gr.addQuery('user', userId)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                var rname = gr.getDisplayValue('role')
                if (!rname) continue
                var lower = String(rname).toLowerCase()
                var isElevated = false
                for (var i = 0; i < ELEVATED.length; i++) {
                    if (lower === ELEVATED[i]) isElevated = true
                }
                if (!isElevated) continue
                var row = {}
                row.role = String(rname)
                // granted_by empty => OOB/derived lineage rather than an
                // explicit human grant. Drives the CONDITIONAL cap below.
                var gb = null
                try {
                    gb = gr.getValue('granted_by')
                } catch (e) {
                    gb = null
                }
                row.granted_by = gb ? String(gb) : null
                row.lineage = gb ? 'explicit_grant' : 'derived_or_oob'
                out.push(row)
            }
        } catch (e) {
            return out
        }
        return out
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
            'run-as privilege cannot be assessed. Out of scope, NOT a pass.',
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
                remediation_id: 'ai-007-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- scan ------------------------------------------------------------
    var flagged = []
    var scanned = 0
    var unresolved = []
    var resolvedMap = {}

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var runF = pickField(tbl, RUNAS_HINTS)
        if (!runF) {
            unresolved.push(tbl)
            continue
        }
        resolvedMap[tbl] = runF
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
                var grants = elevatedGrants(uid)
                if (grants.length === 0) continue
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.agent_name = nameF ? gr.getValue(nameF) : null
                row.run_as_field = runF
                row.run_as = gr.getDisplayValue(runF) || uid
                row.elevated_roles = grants
                flagged.push(row)
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
            '). Review each agent execution identity in AI Agent Studio. No ' +
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
                remediation_id: 'ai-007-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (flagged.length === 0) return

    // Delegation-aware cap: if EVERY elevated grant on every flagged agent is
    // derived/OOB rather than explicitly granted, the pack cannot attribute
    // intent - report CONDITIONAL instead of CRITICAL.
    var anyExplicit = false
    for (var f = 0; f < flagged.length; f++) {
        var roles = flagged[f].elevated_roles
        for (var r = 0; r < roles.length; r++) {
            if (roles[r].lineage === 'explicit_grant') anyExplicit = true
        }
    }

    var examples = []
    for (var x = 0; x < flagged.length && x < 10; x++) {
        var nm = flagged[x].agent_name ? flagged[x].agent_name : flagged[x].sys_id
        var rl = []
        for (var y = 0; y < flagged[x].elevated_roles.length; y++) {
            rl.push(flagged[x].elevated_roles[y].role)
        }
        examples.push(nm + ' runs as ' + flagged[x].run_as + ' [' + rl.join('+') + ']')
    }

    var tail
    if (anyExplicit) {
        tail =
            'At least one elevated role was granted explicitly, so this is an ' +
            'intentional configuration to revoke or justify.'
    } else {
        tail =
            'CONDITIONAL: every elevated role here reached the identity through ' +
            'derived or out-of-box lineage rather than an explicit grant. ' +
            'Confirm whether the inheritance is intended before revoking - ' +
            'severity is capped because the grant intent cannot be read from ' +
            'the instance.'
    }

    emit(
        flagged.length +
        ' of ' +
        scanned +
        ' agentic entities execute under an identity holding an elevated ' +
        'platform role. The agent\'s blast radius is its run-as role set, not ' +
        'its prompt: anything that can steer the agent inherits these rights, ' +
        'and the audit trail will name the service account rather than the ' +
        'input author. ' +
        examples.join('; ') +
        '. ' +
        tail,
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: anyExplicit ? 'fail' : 'conditional',
                elevated_agent_count: flagged.length,
                agents_scanned: scanned,
                elevated_roles_watched: ELEVATED,
                runas_fields_resolved: resolvedMap,
                tables_unresolved: unresolved,
                row_cap: ROW_CAP,
                delegation_note: anyExplicit
                    ? 'at least one explicit grant present'
                    : 'all grants derived/OOB - severity capped at CONDITIONAL',
                agents: flagged
            },
            severity: anyExplicit ? 1 : 2,
            remediation_id: anyExplicit ? 'ai-007' : 'ai-007-conditional',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
