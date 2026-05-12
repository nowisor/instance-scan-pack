import { LinterCheck } from '@servicenow/sdk/core'

// DEFERRED TO v1.1 (Tier 2 verification, 2026-05-12):
// Planted-artifact validation on dev265484 produced zero findings against
// `new GlideRecord('sys_properties')`. The predicate looks for a LITERAL
// node with value 'sys_properties' under a NEW/CALL ancestor. Either the
// LITERAL.getValue() API is unavailable / returns a different shape than
// expected, OR the AST representation of GlideRecord constructor argument
// chains differs from the parent-walking assumption.
//
// v1.1 reactivation criteria: investigate the AST shape of
// `new GlideRecord('sys_properties').update()` on dev265484 — possibly via
// a diagnostic LinterCheck that dumps node types around table-name
// literals. The detection model may need to anchor on the CALL of
// .update() / .insert() / .deleteRecord() on a GlideRecord whose first
// constructor arg is 'sys_properties', rather than the literal alone.
// Confirm via planted-artifact verification before re-activation.
export const directPropertyWriteCheck = LinterCheck({
    $id: Now.ID['nowisor-direct-property-write'],
    name: 'Direct sys_properties Write Detector',
    active: false,
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
