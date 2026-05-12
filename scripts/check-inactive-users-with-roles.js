// nowisor v1.0.0 — Inactive users retaining roles check
// TableCheck (advanced mode) — runs once per sys_user row matching
// the encoded query active=false^rolesISNOTEMPTY.
//
// Runtime contract (per now-sdk explain tablecheck-api, Zurich Patch 6):
//   - `current` is the matched sys_user GlideRecord row (IIFE arg)
//   - `finding` is provided in outer scope by the scan runtime; calling
//     finding.setValue('finding_details', …) + finding.increment() emits a
//     finding tied to the current record.
//
// If `finding` is not in scope on a given runtime version, the SDK contract
// is to fall back to a ScriptOnlyCheck doing its own GlideRecord loop; that
// substitution is not exercised here because the SDK example for advanced
// TableCheck references `finding` from outer scope without IIFE binding.
//
// Schema: v1 (---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function inactiveUsersWithRoles(current) {
    var userName = current.getValue('user_name') || current.getValue('sys_id')
    var sysId = current.getValue('sys_id')
    var rolesField = current.getValue('roles')
    var lastLogin = current.getValue('last_login') || ''

    var metadata = {
        nowisor_check_id: 'nowisor-inactive-users-with-roles',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.5.18'],
        },
        evidence: {
            user_name: userName,
            sys_id: sysId,
            roles_field: rolesField,
            last_login: lastLogin,
        },
        severity: 2,
        remediation_id: 'role-002',
        attack_path_refs: [],
    }

    var details =
        'Inactive user "' +
        userName +
        '" retains role assignments (sys_user.roles populated). Privilege residue from incomplete deprovisioning — reactivation of this account would restore the listed roles without a fresh grant audit event. Sys_id: ' +
        sysId +
        '.' +
        '\n\n---NOWISOR_METADATA---\n' +
        JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(current)
