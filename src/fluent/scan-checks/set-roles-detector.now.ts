import { LinterCheck } from '@servicenow/sdk/core'

export const setRolesDetectorCheck = LinterCheck({
    $id: Now.ID['nowisor-set-roles-detector'],
    name: 'setRoles() Escalation Detector',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Identifies setRoles() calls in server-side scripts, which mutate session role state and can enable privilege escalation',
    description:
        'setRoles() mutates the active session role set, granting or revoking roles for the duration of the script execution. When invoked from user-reachable code paths (UI Actions, Scripted REST APIs, Business Rules on user-facing tables), it can be turned into a privilege-escalation primitive if the role list is influenced by attacker-controllable input.',
    resolutionDetails: `Audit each setRoles() occurrence:
- Verify the role list is a static literal or derived only from trusted internal state
- Confirm the call is reachable only from authenticated paths with appropriate caller-identity checks
- For impersonation use-cases, prefer GlideImpersonate with explicit audit logging
- Consider gs.hasRole() / gs.getUser().hasRole() for read-only role checks instead of mutation

Framework mapping:
- NIS2 Article 21§2(j): human resources security, access control policies and asset management
- ISO 27001 A.5.18: access rights

False-positive note: legitimate elevation-by-design scripts (system bootstrap, scheduled jobs) may invoke setRoles(). Prioritize occurrences whose reachability includes Service Portal or Scripted REST endpoints.`,
    script: Now.include('../../../scripts/check-set-roles-detector.js'),
})
