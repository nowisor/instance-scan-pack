// nowisor v1.0.0 — Cross-scope privilege grants check
//
// DESIGN (Tier 2 verification rewrite, 2026-05-12):
// Original v1.0.0-build predicate used `source.scope` / `target.scope`
// dot-walk syntax on sys_scope_privilege. Schema verification on dev265484
// (sys_dictionary dump) revealed the actual field names are flat fields,
// not dot-walks:
//   - source_scope (reference → sys_scope)
//   - target_scope (reference → sys_scope; sys_id 'global' for the Global scope)
//   - operation    (string: read, write, create, delete, execute)
//   - status       (string: 'allowed' grants are the dangerous ones; denied
//                   grants are blocked at runtime so they aren't escalation paths)
//   - target_name  (string: name of the granted target — table or include name)
//   - target_type  (string: table type — sys_db_object, sys_script_include, …)
//
// The invalid dot-walks were silently dropped by the Zurich query engine,
// causing the v1.0.0-build version to effectively run with no constraints
// and (in scoped context) return zero findings.
//
// Predicate (rewritten):
//   source_scope != 'global'  AND  target_scope = 'global'
//   AND operation IN (write, create, delete)
//   AND status = 'allowed'
//
// Severity is fixed at 2 (priority 2). Volume escalation to severity 1 is
// left to the advisor product, which has the business context the agent lacks.
//
// Cross-scope read of sys_scope_privilege from x_nowisor_isp requires the
// CrossScopePrivilege records shipped with the pack.
//
// Schema: v1 (---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function crossScopePrivilegeGrants(finding) {
    var MAX_LIST = 20
    var HIGH_IMPACT_OPS = 'write,create,delete'

    var gr = new GlideRecord('sys_scope_privilege')
    gr.addQuery('source_scope', '!=', 'global')
    gr.addQuery('target_scope', 'global')
    gr.addQuery('operation', 'IN', HIGH_IMPACT_OPS)
    gr.addQuery('status', 'allowed')
    gr.orderBy('source_scope')
    gr.query()

    var grantCount = 0
    var samples = []

    while (gr.next()) {
        grantCount++
        if (samples.length < MAX_LIST) {
            var sourceScopeName =
                gr.getDisplayValue('source_scope') || gr.getValue('source_scope')
            var operation = gr.getValue('operation') || ''
            var targetName = gr.getValue('target_name') || ''
            var targetType = gr.getValue('target_type') || ''
            samples.push(
                sourceScopeName +
                    ' -> global ' +
                    targetType +
                    '/' +
                    targetName +
                    ' (' +
                    operation +
                    ')'
            )
        }
    }

    if (grantCount === 0) return

    var sampleStr = samples.join('; ')
    var overflow = grantCount > MAX_LIST ? ' (+' + (grantCount - MAX_LIST) + ' more)' : ''

    var metadata = {
        nowisor_check_id: 'nowisor-cross-scope-privilege-grants',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a'],
            iso27001: ['A.8.3'],
        },
        evidence: {
            high_impact_grant_count: grantCount,
            high_impact_operations: ['write', 'create', 'delete'],
            status_filter: 'allowed',
            sample_count: samples.length,
            sample_grants: samples,
        },
        severity: 2,
        remediation_id: 'scope-001',
        attack_path_refs: [],
    }

    var details =
        'High-impact cross-scope privilege grants: ' +
        grantCount +
        ' sys_scope_privilege rows with status=allowed grant write/create/delete on Global-scope records to non-global applications. Sample: ' +
        sampleStr +
        overflow +
        '. Each grant is a scope-escalation path; review business justification for each.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
