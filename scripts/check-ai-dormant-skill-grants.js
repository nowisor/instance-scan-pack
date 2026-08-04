// nowisor v1.2.0 - Inactive agent still holding capability grants (AIA-005)
// Flags agentic entities that are switched OFF but whose execution identity
// still holds platform roles.
//
// THE POINT: DEACTIVATION IS NOT REVOCATION
// Turning an agent off stops it being invoked; it does not remove anything from
// its run-as identity. The service account keeps its roles, its credentials
// keep working, and its OAuth tokens keep authenticating. So a decommissioned
// agent leaves behind a fully privileged identity that nobody is watching,
// because the agent it belonged to is "not in use". That is a standing
// credential with no owner and no monitoring - the classic dormant-NHI problem.
//
// SCOPE DISCIPLINE
// This check reports HELD-BUT-INACTIVE grants from configuration alone. It says
// nothing about whether those grants were ever exercised - that is the
// permission-vs-usage correlation in the Agent Least-Privilege Report, which
// requires log coverage this check does not have. Deliberately MEDIUM: the
// finding is a cleanup obligation, not an active exploit.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object     - name
//   sys_dictionary    - name, element
//   sys_user_has_role - user, role
//   sys_user          - active
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiDormantSkillGrants(finding) {
    var CHECK_ID = 'nowisor-ai-dormant-skill-grants'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var RUNAS_HINTS = ['run_as', 'run_as_user', 'execute_as']
    RUNAS_HINTS.push('user')
    RUNAS_HINTS.push('caller')

    var NAME_HINTS = ['name', 'label', 'title']

    var MAPPINGS = {
        nis2: ['21.2.i'],
        iso27001: ['A.5.16', 'A.8.2'],
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

    function rolesOf(userId) {
        var out = []
        try {
            var gr = new GlideRecord('sys_user_has_role')
            gr.addQuery('user', userId)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                var rn = gr.getDisplayValue('role')
                if (rn) out.push(String(rn))
            }
        } catch (e) {
            return out
        }
        return out
    }

    function identityActive(userId) {
        try {
            var gr = new GlideRecord('sys_user')
            if (!gr.get(userId)) return null
            return gr.getValue('active') === '1'
        } catch (e) {
            return null
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
            'residual grants on inactive agents cannot be assessed. Out of ' +
            'scope, NOT a pass.',
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
                remediation_id: 'ai-005-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- scan ------------------------------------------------------------
    var dormant = []
    var inactiveScanned = 0
    var unresolved = []

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var have = fieldsOf(tbl)
        // Needs BOTH an active flag (to know it is off) and a run-as field (to
        // know whose grants remain). Missing either -> cannot judge this table.
        if (!have || !have['active']) {
            unresolved.push(tbl)
            continue
        }
        var runF = pick(have, RUNAS_HINTS)
        if (!runF) {
            unresolved.push(tbl)
            continue
        }
        var nameF = pick(have, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.addQuery('active', false)
            gr.addQuery(runF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                inactiveScanned = inactiveScanned + 1
                var uid = gr.getValue(runF)
                if (!uid) continue
                var roles = rolesOf(uid)
                if (roles.length === 0) continue
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.name = nameF ? gr.getValue(nameF) : null
                row.run_as = gr.getDisplayValue(runF) || uid
                row.run_as_field = runF
                row.retained_roles = roles
                row.retained_role_count = roles.length
                row.identity_still_active = identityActive(uid)
                dormant.push(row)
            }
        } catch (e) {
            unresolved.push(tbl)
        }
    }

    if (unresolved.length === present.length) {
        emit(
            'Agentic entities are present, but the fields needed to judge ' +
            'residual grants (an active flag plus an execution identity) could ' +
            'not both be resolved on this release (' +
            unresolved.join(', ') +
            '). Review decommissioned agents and their service accounts ' +
            'manually. No posture failure is asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'active_or_runas_field_unresolved',
                    tables_present: present,
                    tables_unresolved: unresolved
                },
                severity: 4,
                remediation_id: 'ai-005-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (dormant.length === 0) return

    var examples = []
    var stillActiveIdentities = 0
    for (var x = 0; x < dormant.length; x++) {
        if (dormant[x].identity_still_active === true) {
            stillActiveIdentities = stillActiveIdentities + 1
        }
        if (x >= 10) continue
        var label = dormant[x].name ? dormant[x].name : dormant[x].sys_id
        examples.push(
            label + ' (off) -> ' + dormant[x].run_as + ' still holds ' +
            dormant[x].retained_role_count + ' role(s)'
        )
    }

    var tail
    if (stillActiveIdentities > 0) {
        tail =
            stillActiveIdentities +
            ' of these execution identities are still ACTIVE user records, so ' +
            'the credentials remain usable independently of the agent being ' +
            'switched off.'
    } else {
        tail =
            'The execution identities are themselves inactive, which reduces ' +
            'the exposure; the grants should still be revoked as cleanup.'
    }

    emit(
        dormant.length +
        ' of ' +
        inactiveScanned +
        ' inactive agentic entities still have an execution identity holding ' +
        'platform roles. Deactivating an agent does not revoke anything: the ' +
        'roles, credentials and tokens survive, leaving a privileged identity ' +
        'that nobody monitors because the agent is "not in use". ' +
        examples.join('; ') +
        '. ' +
        tail +
        ' This is a configuration finding - whether these grants were ever ' +
        'exercised is answered by the Agent Least-Privilege correlation, not ' +
        'by this check.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                dormant_grant_count: dormant.length,
                inactive_agents_scanned: inactiveScanned,
                identities_still_active: stillActiveIdentities,
                tables_unresolved: unresolved,
                row_cap: ROW_CAP,
                usage_basis: 'configuration_only_no_usage_correlation',
                dormant_grants: dormant
            },
            severity: 3,
            remediation_id: 'ai-005',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
