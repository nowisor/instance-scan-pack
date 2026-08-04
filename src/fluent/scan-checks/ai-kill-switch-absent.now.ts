import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const aiKillSwitchAbsentCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-ai-kill-switch-absent'],
    name: 'No Machine-Checkable Agent Deactivation Path',
    active: true,
    category: 'security',
    priority: '3',
    shortDescription:
        'INVESTIGATE-only: reports agent classes with no technical deactivation lever, and asks for a manual attestation instead of failing',
    description:
        "A documented kill procedure is not scannable. A runbook is invisible to a read-only instance scan, so an organisation with an excellent tested procedure would score identically to one with none - which means failing here would assert the absence of something the scan cannot see. The check therefore reports only observable technical levers and asks the customer to attest to the rest. A technical deactivation path is any one of: a per-class disable property that resolves, a separately deactivatable plugin, a per-entity active flag, or a revocable role on the execution identity. Any one means an operator can stop the agent from the platform. None means the only lever may be a support ticket, which is worth knowing before an incident.",
    resolutionDetails: `For each class with no technical lever:
1. Confirm an operational procedure exists to stop that agent class, and that it has been tested - record the answer against the manual_attestation field in the finding evidence
2. Prefer adding a technical lever so the control becomes verifiable rather than attested: a per-entity active flag, or a dedicated revocable role that gates execution
3. Rehearse the procedure. An untested kill switch is an assumption, and the moment you need it is the worst time to discover it does not work

Framework mapping:
- NIS2 Article 21(2)(b): incident handling
- NIS2 Article 21(2)(c): business continuity and crisis management
- ISO 27001 A.5.24: information security incident management planning and preparation - the control that covers developing technical containment capability in advance, which is what a kill switch is
- ISO 27001 A.5.26: response to information security incidents per documented procedures - the half this check can only obtain by attestation
- DORA Article 9(4)(c): limit logical access to ICT assets to approved functions only
- OWASP LLM06:2025 Excessive Agency
- MITRE ATLAS AML.T0053 AI Agent Tool Invocation
- EU AI Act Article 4: AI literacy

Detection is configuration-based and read-only. Property names in the probe list are candidates under test, never asserted as platform identifiers.`,
    script: Now.include('../../../scripts/check-ai-kill-switch-absent.js'),
})
