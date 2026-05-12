import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const elevatedRoleAssignmentsCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-elevated-role-assignments'],
    name: 'Elevated Role Co-Assignments',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Counts active users who hold BOTH admin and itil_admin — segregation-of-duties violation',
    description:
        'Holding both admin and itil_admin on the same active user concentrates platform-administration authority and ITIL process-administration authority in one identity, breaking separation-of-duties. An attacker compromising such an account can both modify platform configuration and approve/close incident, change, and problem records covering their own tracks.',
    resolutionDetails: `Open the listed users and split the duties: retain admin only on a small platform-administration cohort, and itil_admin only on the process-administration cohort. Where a user genuinely needs both for an interim period, document the exception with an end date and review cadence.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management — segregation-of-duties as part of access management
- ISO 27001 A.5.18: access rights — periodic review of privileged access

Role names queried by role.name ('admin', 'itil_admin'); no sys_id dependency. Verified-real role names against Zurich Patch 6 baseline (dev265484, 2026-05-10).`,
    script: Now.include('../../../scripts/check-elevated-role-assignments.js'),
})
