import { LinterCheck } from '@servicenow/sdk/core'

export const glideEvaluatorDetectorCheck = LinterCheck({
    $id: Now.ID['nowisor-glide-evaluator-detector'],
    name: 'GlideEvaluator Dynamic Evaluation Detector',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Identifies GlideEvaluator usage in server-side scripts, which executes arbitrary strings as JavaScript and bypasses static analysis',
    description:
        "GlideEvaluator.evaluateString(...) and new GlideEvaluator() execute arbitrary string-based JavaScript at runtime, mirroring eval()'s risk profile but on a ServiceNow-specific API surface. Any user-controlled or table-stored input passed to GlideEvaluator is a code-injection sink that bypasses static security analysis.",
    resolutionDetails: `Replace GlideEvaluator with:
- Direct method calls or lookup tables for known dispatch patterns
- JSON.parse() for structured input
- Refactor template-style string assembly to GlideRecord field projection

Framework mapping:
- NIS2 Article 21§2(d): supply chain and code-level secure development
- ISO 27001 A.8.28: secure coding

False-positive note: GlideEvaluator appears in legacy workflow and condition-evaluation code; prioritize remediation by reachability from user-controlled input (REST endpoints, Service Portal widgets) over background utility scripts.`,
    script: Now.include('../../../scripts/check-glide-evaluator-detector.js'),
})
