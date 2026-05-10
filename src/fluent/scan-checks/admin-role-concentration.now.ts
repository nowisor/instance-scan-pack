import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const adminRoleConcentrationCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-admin-role-concentration'],
    name: 'Admin Role Concentration',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Detects when admin role assignments exceed 5% of active users, indicating potential privilege creep',
    description:
        'Concentration of admin role assignments above 5% of active users indicates inadequate role granularity, privilege creep over time, or insufficient privileged access management. Best-practice threshold is <5% based on principle of least privilege.',
    resolutionDetails: `Review admin role assignments. Replace admin grants with more granular roles where feasible (e.g., user_admin, security_admin, itil_admin). Implement periodic admin access reviews.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management
- ISO 27001 A.5.18: access rights
- ISO 27001 A.8.2: privileged access rights
- DORA Article 9: ICT risk management framework

Threshold rationale: 5% based on principle of least privilege; tune via runCondition or scoreScale for organization-specific baselines.`,
    script: Now.include('../../../scripts/check-admin-role-concentration.js'),
})
