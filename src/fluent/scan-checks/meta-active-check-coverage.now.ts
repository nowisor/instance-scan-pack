import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const metaActiveCheckCoverageCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-meta-active-check-coverage'],
    name: 'Meta — Active Check Coverage',
    active: true,
    category: 'manageability',
    priority: '3',
    shortDescription:
        'Confirms all 26 nowisor v1.0.0 checks are installed and active in the x_nowisor_isp scope',
    description:
        "Self-meta check. Queries scan_script_only_check, scan_table_check, scan_linter_check, and scan_column_type_check filtered to sys_scope.scope='x_nowisor_isp' and active=true. If the active count is below the expected 26 (v1.0.0 inventory), emits a finding listing what is present so the operator can diagnose the install. A clean install produces no finding.",
    resolutionDetails: `If this check fires, the pack install is incomplete or partially deactivated:
1. Re-run the pack installer to restore missing checks.
2. Audit the Instance Scan check tables under x_nowisor_isp scope for inactive entries; reactivate as needed.
3. If a check was intentionally deactivated for the environment, document the exception and tune the EXPECTED_COUNT in the check script after explicit operator review.

No framework mapping — this is operational telemetry, not a security control.`,
    script: Now.include('../../../scripts/check-meta-active-check-coverage.js'),
})
