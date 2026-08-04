// nowisor v1.2.0 - Agent action logging disabled or below retention floor (AIG-003)
// Two failure modes, reported distinctly:
//   (a) auditing is OFF on the tables agent activity would land in
//   (b) auditing is on, but retention is shorter than the review window
//
// WHY (b) MATTERS AS MUCH AS (a)
// Retention shorter than the review window is a silent failure: the dashboard
// shows logs, the control looks satisfied, and the evidence for anything older
// than the window is simply gone. It is also the precondition for the entire
// permission-vs-usage correlation - a DORMANT verdict is only legitimate when
// retention spans the lookback, so an instance failing this check cannot get
// evidence-grade privilege reduction at all. That linkage is stated in the
// finding so the customer sees what else it costs them.
//
// RETENTION FLOOR: 90 days, matching the default correlation lookback. Below
// that, the Agent Least-Privilege Report degrades to UNKNOWN-USAGE rather than
// recommending revocations it cannot justify.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object   - name
//   sys_dictionary  - name, element, audit
//   sys_audit       - sys_created_on  (retention floor probe)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiAgentAuditRetention(finding) {
    var CHECK_ID = 'nowisor-ai-agent-audit-retention'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200
    var RETENTION_FLOOR_DAYS = 90

    var AGENT_TABLES = ['sn_aia_use_case', 'sys_cb_ai_agent']
    AGENT_TABLES.push('sys_cs_topic')

    // Execution-log candidates for agent activity.
    var EXEC_LOGS = ['sn_aia_execution_log']
    EXEC_LOGS.push('sn_aia_agent_execution')
    EXEC_LOGS.push('sys_cs_conversation')
    EXEC_LOGS.push('sys_flow_context')

    var MAPPINGS = {
        nis2: ['21.2.b'],
        iso27001: ['A.8.15', 'A.8.16'],
        dora: ['10.1'],
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

    // Collection row (element='') carries the table-level audit flag.
    function auditEnabled(t) {
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', t)
            d.addQuery('element', '')
            d.setLimit(1)
            d.query()
            if (!d.next()) return null
            return d.getValue('audit') === '1'
        } catch (e) {
            return null
        }
    }

    function countRows(t) {
        try {
            var gr = new GlideRecord(t)
            gr.setLimit(ROW_CAP)
            gr.query()
            var n = 0
            while (gr.next()) n = n + 1
            return n
        } catch (e) {
            return -1
        }
    }

    // Days between the earliest record on a table and now.
    function retentionDays(t) {
        try {
            var gr = new GlideRecord(t)
            gr.orderBy('sys_created_on')
            gr.setLimit(1)
            gr.query()
            if (!gr.next()) return null
            var earliest = gr.getValue('sys_created_on')
            if (!earliest) return null
            var then = new GlideDateTime(earliest)
            var now = new GlideDateTime()
            var diff = GlideDateTime.subtract(then, now)
            return Math.floor(diff.getNumericValue() / 86400000)
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
    var agentTables = []
    for (var i = 0; i < AGENT_TABLES.length; i++) {
        if (tableExists(AGENT_TABLES[i])) agentTables.push(AGENT_TABLES[i])
    }
    if (agentTables.length === 0) {
        emit(
            'No agentic entity tables are present on this instance, so agent ' +
            'action logging cannot be assessed. Out of scope, NOT a pass.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agentic_tables',
                    tables_probed: AGENT_TABLES
                },
                severity: 4,
                remediation_id: 'aig-003-na',
                attack_path_refs: []
            }
        )
        return
    }

    // ---- (a) audit flags on the agent tables themselves -------------------
    var auditOff = []
    var auditUnknown = []
    for (var a = 0; a < agentTables.length; a++) {
        var en = auditEnabled(agentTables[a])
        if (en === null) {
            auditUnknown.push(agentTables[a])
        } else if (en === false) {
            auditOff.push(agentTables[a])
        }
    }

    // ---- (b) execution-log presence + retention ---------------------------
    var logs = []
    var anyLogPresent = false
    var shallow = []
    for (var e2 = 0; e2 < EXEC_LOGS.length; e2++) {
        var lt = EXEC_LOGS[e2]
        var row = {}
        row.table = lt
        row.present = tableExists(lt)
        row.row_count = -1
        row.retention_days = null
        if (row.present) {
            anyLogPresent = true
            row.row_count = countRows(lt)
            row.retention_days = retentionDays(lt)
            if (row.retention_days !== null &&
                row.retention_days < RETENTION_FLOOR_DAYS) {
                shallow.push(lt + ' (' + row.retention_days + 'd)')
            }
        }
        logs.push(row)
    }

    // sys_audit as the fallback trail for agent-attributed writes.
    var sysAuditRetention = tableExists('sys_audit') ? retentionDays('sys_audit') : null

    var problems = []
    if (auditOff.length > 0) {
        problems.push('auditing is disabled on ' + auditOff.join(', '))
    }
    if (!anyLogPresent) {
        problems.push('no agent execution-log table is present')
    }
    if (shallow.length > 0) {
        problems.push(
            'execution-log retention is below the ' + RETENTION_FLOOR_DAYS +
            'd floor: ' + shallow.join(', ')
        )
    }
    if (sysAuditRetention !== null && sysAuditRetention < RETENTION_FLOOR_DAYS) {
        problems.push(
            'sys_audit retains only ' + sysAuditRetention + 'd (floor ' +
            RETENTION_FLOOR_DAYS + 'd)'
        )
    }

    if (problems.length === 0) return

    emit(
        'Agent action logging is insufficient for post-incident review: ' +
        problems.join('; ') +
        '. Without a durable, attributable trail you can establish that an ' +
        'agent acted but not reconstruct what it read, what it changed, or ' +
        'which input drove it. This also blocks evidence-grade privilege ' +
        'reduction: the Agent Least-Privilege correlation only issues a DORMANT ' +
        'verdict when retention spans the full lookback window, so on this ' +
        'instance those permissions will report as UNKNOWN-USAGE rather than as ' +
        'safe-to-revoke.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: 'fail',
                problems: problems,
                retention_floor_days: RETENTION_FLOOR_DAYS,
                agent_tables: agentTables,
                audit_disabled_on: auditOff,
                audit_flag_unreadable_on: auditUnknown,
                execution_logs: logs,
                sys_audit_retention_days: sysAuditRetention,
                row_cap: ROW_CAP,
                correlation_impact: 'blocks DORMANT verdicts - degrades to UNKNOWN-USAGE'
            },
            severity: 2,
            remediation_id: 'aig-003',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
