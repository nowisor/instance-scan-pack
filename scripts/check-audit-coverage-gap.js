// nowisor v1.0.0 — audit coverage gap detector (check #27)
// Detects whether sys_dictionary.audit = true on the table-level (collection)
// row for security-critical tables: sys_user_has_role, sys_security_acl,
// sys_properties. Missing audit on these tables means every other security
// control becomes unverifiable post-incident — you cannot answer "who changed
// the ACL on 2026-05-18?" if the table itself isn't being audited.
//
// ServiceNow auditing model: sys_dictionary stores one row per (table,column)
// plus one COLLECTION row per table (name=<table>, element=''). The collection
// row's `audit` field is the canonical table-level audit flag — when true,
// changes to the table emit sys_audit rows; when false/empty, they do not.
//
// Cross-scope read of sys_dictionary from x_nowisor_isp requires the
// CrossScopePrivilege shipped with the pack (read on sys_dictionary).
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function auditCoverageGap(finding) {
    var CRITICAL_TABLES = ['sys_user_has_role', 'sys_security_acl', 'sys_properties']

    var unaudited = []
    var missingFromDictionary = []
    var inspected = 0

    for (var i = 0; i < CRITICAL_TABLES.length; i++) {
        var tableName = CRITICAL_TABLES[i]
        inspected++

        try {
            var gr = new GlideRecord('sys_dictionary')
            gr.addQuery('name', tableName)
            // Collection row carries element='' (the table-level dictionary entry,
            // not a field row). Without this filter we'd inspect every column.
            var elemQuery = gr.addQuery('element', '')
            elemQuery.addOrCondition('element', 'NULL')
            gr.setLimit(1)
            gr.query()
            if (!gr.next()) {
                missingFromDictionary.push(tableName)
                continue
            }
            var auditFlag = gr.getValue('audit')
            // sys_dictionary.audit is boolean — stored as '1' (true) or '0'/'' (false)
            if (auditFlag !== '1' && auditFlag !== 'true') {
                unaudited.push(tableName)
            }
        } catch (e) {
            // sys_dictionary may be unreadable from x_nowisor_isp if cross-scope
            // privileges weren't committed. Surface as a finding rather than silent-pass.
            missingFromDictionary.push(tableName + ' (read failed: ' + (e && e.message) + ')')
        }
    }

    if (unaudited.length === 0 && missingFromDictionary.length === 0) return

    var description
    if (unaudited.length > 0 && missingFromDictionary.length === 0) {
        description =
            'Audit logging is NOT enabled on ' +
            unaudited.length +
            ' security-critical table(s): ' +
            unaudited.join(', ') +
            '. Changes to these tables will not appear in sys_audit, leaving role grants, ACL modifications, and system property toggles invisible to post-incident review. Every other security control on these tables becomes unverifiable.'
    } else if (unaudited.length === 0 && missingFromDictionary.length > 0) {
        description =
            'Could not verify audit coverage for ' +
            missingFromDictionary.length +
            ' security-critical table(s) — sys_dictionary collection row missing or unreadable: ' +
            missingFromDictionary.join(', ') +
            '. Confirm cross-scope sys_dictionary read access and re-run.'
    } else {
        description =
            'Audit coverage gap: ' +
            unaudited.length +
            ' security-critical table(s) un-audited (' +
            unaudited.join(', ') +
            ') and ' +
            missingFromDictionary.length +
            ' could not be verified (' +
            missingFromDictionary.join(', ') +
            '). Post-incident review of role/ACL/property changes will be incomplete.'
    }

    var metadata = {
        nowisor_check_id: 'nowisor-audit-coverage-gap',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.b'],
            iso27001: ['A.8.15', 'A.8.16'],
            dora: ['10'],
        },
        evidence: {
            critical_tables_inspected: CRITICAL_TABLES,
            unaudited_tables: unaudited,
            unverifiable_tables: missingFromDictionary,
            inspected_count: inspected,
        },
        severity: 2,
        remediation_id: 'audit-001',
        attack_path_refs: [],
    }

    var remediationHint =
        '\n\nRemediation: open sys_dictionary, filter Table=<each table> AND Column name=<empty>, set Audit=true. ' +
        'Audit propagates immediately for subsequent changes; historical changes pre-toggle cannot be recovered.'

    var details =
        description +
        remediationHint +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
