// nowisor v1.0.0 — Fabricated property references (ScriptOnlyCheck)
// Scans custom Script Includes + Business Rules for gs.getProperty/setProperty
// calls. Validates each referenced property name against sys_properties.
// Reports orphans (referenced but not registered) capped at 20.
//
// Provenance: relies on sys_package field to distinguish custom (non-Global)
// from OOB code. Empty / null sys_package = Global scope (legitimate custom
// code authored directly in Global also lands here; the check accepts that
// as the cost of broad coverage).
//
// Cross-scope read: sys_script_include, sys_script, sys_properties.
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function fabricatedPropertyReferences(finding) {
    var GR_LIMIT = 5000
    var ORPHAN_CAP = 20
    var orphans = []
    var checkedNames = {} // memoize property-existence lookups

    function isOrphan(propName) {
        if (Object.prototype.hasOwnProperty.call(checkedNames, propName)) {
            return checkedNames[propName]
        }
        var propGr = new GlideRecord('sys_properties')
        propGr.addQuery('name', propName)
        propGr.setLimit(1)
        propGr.query()
        var orphan = !propGr.next()
        checkedNames[propName] = orphan
        return orphan
    }

    function scanTable(tableName) {
        if (orphans.length >= ORPHAN_CAP) return
        var gr = new GlideRecord(tableName)
        gr.addQuery('sys_package', '')
        gr.setLimit(GR_LIMIT)
        gr.query()
        while (gr.next() && orphans.length < ORPHAN_CAP) {
            var script = gr.getValue('script') || ''
            if (!script) continue
            var refs = script.match(/gs\.(get|set)Property\(\s*['"]([^'"]+)['"]/g) || []
            for (var i = 0; i < refs.length && orphans.length < ORPHAN_CAP; i++) {
                var nameMatch = refs[i].match(/['"]([^'"]+)['"]/)
                if (!nameMatch) continue
                var propName = nameMatch[1]
                if (isOrphan(propName)) {
                    orphans.push({
                        property: propName,
                        referencing_script: gr.getValue('name'),
                        table: tableName,
                        sys_id: gr.getValue('sys_id'),
                    })
                }
            }
        }
    }

    scanTable('sys_script_include')
    scanTable('sys_script')

    if (orphans.length === 0) return

    var metadata = {
        nowisor_check_id: 'nowisor-fabricated-property-references',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a'],
            iso27001: ['A.8.9'],
        },
        evidence: {
            orphan_count: orphans.length,
            orphans_capped_at: ORPHAN_CAP,
            orphans: orphans,
        },
        severity: 3,
        remediation_id: 'prop-ref-001',
        attack_path_refs: [],
    }

    var details =
        'Fabricated property references detected: ' +
        orphans.length +
        ' custom-scope script(s) reference sys_properties names that do not exist on this instance. Such references silently return null at runtime, producing false sense of hardening.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
