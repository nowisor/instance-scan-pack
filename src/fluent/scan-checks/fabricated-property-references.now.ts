import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const fabricatedPropertyReferencesCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-fabricated-property-references'],
    name: 'Fabricated Property References',
    active: true,
    category: 'security',
    priority: '3',
    shortDescription:
        'Detects custom code referencing sys_properties names that do not exist on the instance',
    description:
        "When custom Script Includes or Business Rules call gs.getProperty('<name>') for a property name that is not registered in sys_properties, the call silently returns null (or the supplied default). This pattern is a frequent source of post-install security drift: hardening configurations referenced by typo'd names never actually take effect, and adversaries can exploit the false sense of protection. The check extracts property references from custom-scope scripts via regex and validates each against sys_properties.",
    resolutionDetails: `For each fabricated reference reported:
1. Confirm whether the property name is a typo of a real property or a fabrication.
2. If typo: correct the script. Re-run the check to confirm the reference resolves.
3. If fabrication: either register the intended property in sys_properties with the correct security baseline value, or remove the dead reference from the script.

Framework mapping:
- NIS2 Article 21§2(a): risk analysis and information system security policies
- ISO 27001 A.8.9: configuration management

False-positive note: properties registered in scoped applications outside Global may not appear under the unqualified name. The check caps reported orphans at 20 to keep finding size bounded.`,
    script: Now.include('../../../scripts/check-fabricated-property-references.js'),
})
