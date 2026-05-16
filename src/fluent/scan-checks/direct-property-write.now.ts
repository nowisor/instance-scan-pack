import { LinterCheck } from '@servicenow/sdk/core'

// PREDICATE FIXED 2026-05-16 — pending PDI planted-artifact verification.
//
// Tier 2 verification on dev265484 (2026-05-12) confirmed the original
// LITERAL-anchored predicate (LITERAL 'sys_properties' under NEW/CALL
// ancestor) produced zero findings against
// `new GlideRecord('sys_properties').update()`. Ancestor walk from the
// LITERAL did not reach a NEW or CALL node in the form expected.
//
// 2026-05-16 fix: anchor on NAME 'GlideRecord' under CALL/NEW parent —
// the same shape proven by set-roles-detector — and confirm via same-line
// co-occurrence with a LITERAL whose unquoted value is 'sys_properties'.
// Uses only AST APIs verified by active detectors.
//
// Reactivation gate: deploy this revision to dev265484, plant
// `new GlideRecord('sys_properties').update()` in a Script Include, run a
// scan, confirm finding emitted on the planted line. Then flip
// `active: true` here AND in manifest.json. Held at `active: false` until
// that PDI gate clears.
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
