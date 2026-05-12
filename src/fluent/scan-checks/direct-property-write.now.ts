import { LinterCheck } from '@servicenow/sdk/core'

export const directPropertyWriteCheck = LinterCheck({
    $id: Now.ID['nowisor-direct-property-write'],
    name: 'Direct sys_properties Write Detector',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Identifies scripts that write directly to sys_properties via GlideRecord, bypassing gs.setProperty() audit and cache invalidation',
    description:
        'Writing to sys_properties via new GlideRecord("sys_properties").insert()/update() bypasses the property-write code path used by gs.setProperty(): change audit, cache invalidation, and property-write listeners may not fire as expected. It also obscures the property name from static review.',
    resolutionDetails: `Replace direct GlideRecord writes against sys_properties with gs.setProperty(name, value):
- gs.setProperty triggers cache invalidation and audit consistently
- Property name appears as a literal in the call, aiding static review and KB cross-reference
- For programmatic property management, use the System Properties API (gs.getProperty / gs.setProperty)

Framework mapping:
- NIS2 Article 21§2(a): policies on risk analysis and information system security
- ISO 27001 A.8.9: configuration management

False-positive note: legitimate property-management tooling (admin utilities, migration scripts) may write directly to sys_properties for batch operations. Confirm the bypass is intentional and documented.`,
    script: Now.include('../../../scripts/check-direct-property-write.js'),
})
