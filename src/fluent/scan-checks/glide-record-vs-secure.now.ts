import { LinterCheck } from '@servicenow/sdk/core'

export const glideRecordVsSecureCheck = LinterCheck({
    $id: Now.ID['nowisor-glide-record-vs-secure'],
    name: 'GlideRecord vs GlideRecordSecure',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Identifies new GlideRecord() usage where GlideRecordSecure would enforce ACL evaluation on read',
    description:
        "GlideRecord bypasses ACL evaluation on read by default — only the developer's discretion enforces row-level security. GlideRecordSecure runs the same query under the caller's ACL context, preventing data exposure when scripts are invoked with elevated privileges or from contexts where the caller identity differs from the script author's mental model.",
    resolutionDetails: `Audit each new GlideRecord occurrence:
- For data the caller is entitled to read under their own ACLs, switch to new GlideRecordSecure(table)
- For administrative tooling that legitimately bypasses ACLs, add an explanatory comment and ensure caller authentication is enforced upstream
- For scripted REST APIs, prefer GlideRecordSecure unless the API contract documents elevation

Framework mapping:
- NIS2 Article 21§2(h): policies and procedures regarding the use of cryptography and, where appropriate, encryption (covers access-control discipline as a complementary control)
- ISO 27001 A.8.3: information access restriction

False-positive note: this check fires on every new GlideRecord regardless of whether GlideRecordSecure would change behaviour. Treat as an inventory signal rather than a per-occurrence defect; pair with reachability analysis.`,
    script: Now.include('../../../scripts/check-glide-record-vs-secure.js'),
})
