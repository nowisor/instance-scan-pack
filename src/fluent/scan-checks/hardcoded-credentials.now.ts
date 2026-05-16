import { LinterCheck } from '@servicenow/sdk/core'

// PREDICATE FIXED 2026-05-16 — pending PDI planted-artifact verification.
//
// Tier 2 verification on dev265484 (2026-05-12) confirmed the original
// labelled-assignment regex against LITERAL.getValue() never matched: the
// Rhino AST splits `var password = '…'` into NAME('password') + OP('=') +
// LITERAL('…'), and LITERAL.getValue() returns the bare password string.
//
// 2026-05-16 fix: anchor on NAME nodes whose identifier matches the
// credential-name pattern, and confirm via line co-occurrence with a
// LITERAL of plausible credential length. Uses only AST APIs already
// verified by the active eval-usage-detector (NAME.getNameIdentifier) and
// set-roles-detector (NAME-anchored predicate); LITERAL.getValue() was
// verified empirically during the Tier 2 round-trip.
//
// Reactivation gate: deploy this revision to dev265484, plant
// `var password = 'Pa$$w0rd123!'` in a Script Include, run a scan, confirm
// finding emitted on the planted line. Then flip `active: true` here AND
// in manifest.json. Held at `active: false` until that PDI gate clears.
export const hardcodedCredentialsCheck = LinterCheck({
    $id: Now.ID['nowisor-hardcoded-credentials'],
    name: 'Hardcoded Credentials Detector',
    active: false,
    category: 'security',
    priority: '1',
    shortDescription:
        'Identifies hardcoded credential patterns (password, api_key, secret, token) in server-side scripts',
    description:
        'Credentials embedded as string literals in Script Includes, Business Rules, and similar surfaces are extractable by anyone with read access to the script table. Update sets carry them across instances; export artifacts leak them to downstream systems. This detector matches common labelled-assignment patterns for password / api_key / secret / token.',
    resolutionDetails: `Move credentials out of script source:
- Use sys_properties for non-secret config; restrict read access via property-level ACLs
- Use Credential records (discovery_credentials, jdbc_credentials, basic_auth_credentials, etc.) for integrations
- Use the Credential Vault Provider API for high-sensitivity tokens
- For OAuth, store refresh tokens in the OAuth credential store, never in script

Framework mapping:
- NIS2 Article 21§2(i): cyber hygiene practices and cybersecurity training
- ISO 27001 A.8.5: secure authentication
- DORA Article 9: ICT risk management framework

False-positive note: the pattern set matches labelled assignments; literal credential-shaped strings without a labelled assignment may not be flagged, and unrelated strings such as "password reset request" may match the password regex. Treat findings as audit candidates, not confirmed defects.`,
    script: Now.include('../../../scripts/check-hardcoded-credentials.js'),
})
