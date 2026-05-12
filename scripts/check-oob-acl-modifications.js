// nowisor v1.0.0 — OOB ACL modifications check
// Flags out-of-box ACLs (sys_package empty) modified more than one day post-install.
// Approximation: sys_updated_on > sys_created_on + 86_400_000 ms.
//
// Cross-scope read of sys_security_acl from x_nowisor_isp requires the
// CrossScopePrivilege records shipped with the pack (read on sys_security_acl).
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function oobAclModifications(finding) {
    var MAX_LIST = 20
    var ONE_DAY_MS = 86400000

    var gr = new GlideRecord('sys_security_acl')
    gr.addQuery('sys_package', '')
    // Filter rows where sys_updated_on > sys_created_on (a sentinel that the row
    // has been touched after seeding); precise >1-day delta computed in-loop.
    gr.addQuery('sys_updated_on', '>', 'javascript:gs.beginningOfYesterday()')
    gr.orderByDesc('sys_updated_on')
    gr.query()

    var modifiedCount = 0
    var sampleNames = []

    while (gr.next()) {
        var createdGdt = new GlideDateTime(gr.getValue('sys_created_on'))
        var updatedGdt = new GlideDateTime(gr.getValue('sys_updated_on'))
        var deltaMs = updatedGdt.getNumericValue() - createdGdt.getNumericValue()
        if (deltaMs <= ONE_DAY_MS) continue

        modifiedCount++
        if (sampleNames.length < MAX_LIST) {
            var aclName = gr.getValue('name') || gr.getValue('sys_id')
            var operation = gr.getValue('operation') || ''
            sampleNames.push(aclName + ' (' + operation + ')')
        }
    }

    if (modifiedCount === 0) return

    var sampleStr = sampleNames.join('; ')
    var overflow = modifiedCount > MAX_LIST ? ' (+' + (modifiedCount - MAX_LIST) + ' more)' : ''

    var metadata = {
        nowisor_check_id: 'nowisor-oob-acl-modifications',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a'],
            iso27001: ['A.8.3'],
        },
        evidence: {
            modified_oob_acl_count: modifiedCount,
            sample_count: sampleNames.length,
            sample_acls: sampleNames,
            modification_threshold_ms: ONE_DAY_MS,
        },
        severity: 2,
        remediation_id: 'acl-003',
        attack_path_refs: [],
    }

    var details =
        'OOB ACLs modified post-install: ' +
        modifiedCount +
        ' rows in sys_security_acl with sys_package empty and sys_updated_on >1 day after sys_created_on. Sample: ' +
        sampleStr +
        overflow +
        '. Review each against baseline; move intentional changes into an application scope to avoid silent upgrade revert.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
