import { LinterCheck } from '@servicenow/sdk/core'

export const domainSeparationScriptIncludeCheck = LinterCheck({
    $id: Now.ID['nowisor-domain-separation-script-include'],
    name: 'Cross-Domain Script Include Reference',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Identifies Script Includes that mutate auth/session state (setRoles, setSession) without referencing sys_overrides for domain-aware override handling',
    description:
        "On domain-separated instances, Script Includes that mutate auth or session state need to participate in the domain-override model (sys_overrides) so per-domain customizations apply correctly. A Script Include that calls setRoles or setSession without any reference to sys_overrides is a heuristic indicator of code that was written for a non-domain-separated mental model and may produce cross-domain leakage when DS is active.",
    resolutionDetails: `For each finding:
- Confirm whether the Script Include is intended to run in a domain-separated context
- If yes, evaluate whether sys_overrides should be consulted to allow per-domain customization
- For auth/session mutation, ensure the call paths respect the caller's domain and do not promote cross-domain visibility

Framework mapping:
- NIS2 Article 21§2(j): access control policies
- ISO 27001 A.5.31: legal, statutory, regulatory and contractual requirements
- GDPR Article 32: security of processing (tenant isolation in multi-tenant context)

False-positive note: heuristic check — the absence of a 'sys_overrides' substring is a coarse signal. Non-DS instances will produce findings that are not defects. Treat as advisory inventory rather than per-occurrence defect.`,
    script: Now.include('../../../scripts/check-domain-separation-script-include.js'),
})
