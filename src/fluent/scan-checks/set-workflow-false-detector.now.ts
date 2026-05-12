import { LinterCheck } from '@servicenow/sdk/core'

export const setWorkflowFalseDetectorCheck = LinterCheck({
    $id: Now.ID['nowisor-set-workflow-false-detector'],
    name: 'setWorkflow(false) Detector',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Identifies setWorkflow(false) calls in server-side scripts, which bypass Business Rules, audit, and notifications',
    description:
        "setWorkflow(false) on a GlideRecord disables Business Rule execution, audit logging, and notification dispatch for the subsequent write. The AP-007 attack pattern documented in nowisor's KB shows how this combines with eval() in Script Includes to enable privilege escalation outside of audit observation, leaving no forensic trail.",
    resolutionDetails: `Default-deny setWorkflow(false). Audit each occurrence and justify in code comments. Safer alternatives:
- Leave Business Rules on; refactor the BR if it has unintended side effects
- Use setWorkflow(false) only inside narrowly-scoped system-maintenance scripts with explicit comment + change control reference
- For bulk operations, prefer chunked writes with full BR coverage over silent-bulk writes

Framework mapping:
- NIS2 Article 21 paragraph 2(f): policies and procedures to assess the effectiveness of cybersecurity measures
- ISO 27001 A.8.15: logging
- DORA Article 9: ICT risk framework

False-positive note: legitimate maintenance scripts (data migration, batch backfill) may use setWorkflow(false) intentionally. Prioritize occurrences in user-reachable code paths (UI Actions, Business Rules on user-facing tables) over background scripts.`,
    script: Now.include('../../../scripts/check-set-workflow-false-detector.js'),
})
