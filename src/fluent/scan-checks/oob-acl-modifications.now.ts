import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const oobAclModificationsCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-oob-acl-modifications'],
    name: 'OOB ACL Modifications',
    active: true,
    category: 'security',
    priority: '2',
    shortDescription:
        'Detects out-of-box ACLs (sys_package empty) modified more than one day after creation — local tampering of baseline access controls',
    description:
        'ServiceNow ships baseline ACLs with sys_package empty (Global scope). When such ACLs have sys_updated_on >1 day after sys_created_on, the row has been edited post-install — either intentional hardening, drift from an upgrade reapplying defaults, or an attacker weakening the baseline grant. The check enumerates affected ACLs so a reviewer can compare against the upgrade-skipped-changes list and ServiceNow baseline.',
    resolutionDetails: `For each flagged ACL: open the record, review the Updates related list for the modifying user and timestamp, and compare the operation/script/condition to the baseline. If modification is intentional and required, move the ACL into an application scope so future upgrades do not silently revert it. If unintentional, revert via Upgrade History or by restoring the OOB definition from a sibling instance.

Framework mapping:
- NIS2 Article 21§2(a): risk analysis and information system security policies — baseline control integrity
- ISO 27001 A.8.3: information access restriction — change control on access policy

ACL platform contract: sys_security_acl.sys_package='' identifies Global-scope baseline ACLs (OOB rows do not carry a sys_package reference). Modified-after-install is approximated by sys_updated_on > sys_created_on + 1 day.`,
    script: Now.include('../../../scripts/check-oob-acl-modifications.js'),
})
