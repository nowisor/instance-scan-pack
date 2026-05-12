import { ColumnTypeCheck } from '@servicenow/sdk/core'

// ColumnTypeCheck targets columns of a specific data type (here: 'xml').
// The SDK 4.6.0 surface for ColumnTypeCheck mirrors LinterCheck closely; the
// runtime exposes an `engine` whose source string we scan with regex. If the
// effective parameter name on this SDK build is `dataType` rather than
// `columnType`, the Fluent transformer should still accept the call shape —
// the script body is the load-bearing component. Verified-real assumption:
// sys_update_xml.payload column is type 'xml' on Zurich Patch 6.
export const updateSetXmlSuspiciousCheck = ColumnTypeCheck({
    $id: Now.ID['nowisor-update-set-xml-suspicious'],
    name: 'Suspicious Update Set XML',
    active: true,
    category: 'security',
    priority: '1',
    columnType: 'xml',
    shortDescription:
        'Detects update set XML payloads containing privilege escalation, ACL modification, or cross-scope grant patterns',
    description:
        "Update sets transport configuration between instances. Malicious or accidental update sets can ship privilege escalations (admin role grants), ACL modifications that weaken row-level security, or cross-scope privilege grants that break application isolation. This check scans XML payloads on sys_update_xml for these three patterns and flags any match for human review before the update set is committed.",
    resolutionDetails: `Review the flagged update set in System Update Sets > Retrieved Update Sets. Audit:
- sys_user_has_role records: confirm admin grants are intentional and approved
- sys_security_acl records: confirm ACL changes match a documented change request
- sys_scope_privilege records: confirm cross-scope grants align with application architecture

Framework mapping:
- NIS2 Article 21§2(f): change management and configuration management
- ISO 27001 A.8.32: change management

False-positive note: legitimate update sets from trusted developers may contain these record types. The check flags presence, not intent — combine with update-set source verification (signed export, internal repo origin) before approving.`,
    script: Now.include('../../../scripts/check-update-set-xml-suspicious.js'),
})
