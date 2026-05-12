// nowisor v1.0.0 — Cross-scope privilege grants check
// Counts sys_scope_privilege rows where source.scope != 'global' AND
// target.scope = 'global' AND operation IN (write, create, delete).
//
// Severity scales with count:
//   1 high-impact grant   → severity 2 (priority 2)
//   ≥5 high-impact grants → narrative escalated; severity unchanged at 2
//     (escalation to severity 1 requires advisor-side context)
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function crossScopePrivilegeGrants(finding) {
    var MAX_LIST = 20
    var HIGH_IMPACT_OPS = 'write,create,delete'

    var gr = new GlideRecord('sys_scope_privilege')
    gr.addQuery('source.scope', '!=', 'global')
    gr.addQuery('target.scope', 'global')
    gr.addQuery('operation', 'IN', HIGH_IMPACT_OPS)
    gr.orderBy('source.scope')
    gr.query()

    var grantCount = 0
    var samples = []

    while (gr.next()) {
        grantCount++
        if (samples.length < MAX_LIST) {
            var sourceScope = gr.getValue('source.scope') || gr.getValue('source')
            var operation = gr.getValue('operation') || ''
            samples.push(sourceScope + ' -> global (' + operation + ')')
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
        ' sys_scope_privilege rows grant write/create/delete on Global-scope records to non-global applications. Sample: ' +
        sampleStr +
        overflow +
        '. Each grant is a scope-escalation path; review business justification.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
