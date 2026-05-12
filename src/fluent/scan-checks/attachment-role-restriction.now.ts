import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const attachmentRoleRestrictionCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-attachment-role-restriction'],
    name: 'Attachment Role Restriction',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Verifies glide.attachment.role is set to a non-public role to restrict attachment upload/download surface',
    description:
        "The glide.attachment.role property controls which role is required to upload and read attachments via the standard attachment API. When empty or set to 'public', any authenticated session can attach files to records they can read, expanding the malware ingress surface and creating an exfiltration channel from sensitive records. Verified-real property in all_properties_zurich_patch6.json.",
    resolutionDetails: `Set glide.attachment.role to a non-public role appropriate to the instance (commonly 'attachment_writer' or a custom restricted role). Pair with glide.attachment.extensions allowlist and antivirus integration. Audit existing attachments via sys_attachment for files uploaded under the unrestricted regime.

Framework mapping:
- NIS2 Article 21§2(h): policies and procedures regarding the use of cryptography and, where appropriate, encryption — covers data-at-rest controls including attachments
- ISO 27001 A.5.34: privacy and protection of PII
- DORA Article 9: ICT risk management framework

Verified-real property against ServiceNow Zurich Patch 6 (dev265484). Empty string and 'public' are both treated as unrestricted by the platform attachment handler.`,
    script: Now.include('../../../scripts/check-attachment-role-restriction.js'),
})
