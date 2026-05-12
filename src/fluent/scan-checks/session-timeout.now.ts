import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const sessionTimeoutCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-session-timeout'],
    name: 'Session Idle Timeout',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Verifies glide.ui.session_timeout is set to 30 minutes or less to limit hijack window on idle sessions',
    description:
        'When glide.ui.session_timeout exceeds 30 minutes, idle authenticated sessions remain valid for longer than the recommended baseline, widening the window for session hijack via stolen cookies, unattended workstations, or replay against persistent credentials. Verified-real property on Zurich Patch 6; default value 30.',
    resolutionDetails: `Set glide.ui.session_timeout to 30 (minutes) or lower via System Properties.

Framework mapping:
- NIS2 Article 21§2(j): identity and access management
- ISO 27001 A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
Property registration confirmed in sys_properties; default value '30'.`,
    script: Now.include('../../../scripts/check-session-timeout.js'),
})
