import { LinterCheck } from '@servicenow/sdk/core'

export const evalUsageDetectorCheck = LinterCheck({
    $id: Now.ID['nowisor-eval-usage-detector'],
    name: 'eval() Usage Detector',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Identifies eval() calls in server-side scripts, which enable arbitrary code execution and bypass static analysis',
    description:
        "eval() executes arbitrary string-based JavaScript at runtime, bypassing static security analysis and enabling injection attacks if the input is user-controlled. The AP-007 attack pattern documented in nowisor's KB shows how eval() in Script Includes enables privilege escalation when combined with setWorkflow(false).",
    resolutionDetails: `Replace eval() with safer alternatives:
- JSON.parse() for parsing JSON strings
- Function constructor for controlled dynamic code (still risky; refactor where possible)
- Refactor to direct method calls or lookup tables

Framework mapping:
- NIS2 Article 21§2(d): supply chain security including security-related aspects of relationships between entities and direct suppliers (covers code-level secure development)
- ISO 27001 A.8.28: secure coding
- DORA Article 9: ICT risk management framework

False-positive note: legitimate JSON parsing fallback patterns may use eval() in older code; prioritize remediation by impact (Script Includes > Background Scripts > UI Scripts).`,
    script: Now.include('../../../scripts/check-eval-usage-detector.js'),
})
