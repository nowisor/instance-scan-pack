import { LinterCheck } from '@servicenow/sdk/core'

export const hardcodedCredentialsCheck = LinterCheck({
    $id: Now.ID['nowisor-hardcoded-credentials'],
    name: 'Hardcoded Credentials Detector',
    active: true,
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
