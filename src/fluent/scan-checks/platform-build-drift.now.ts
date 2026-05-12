import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const platformBuildDriftCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-platform-build-drift'],
    name: 'Platform Build Drift',
    active: true,
    category: 'security',
    priority: '3',
    shortDescription:
        "Confirms the instance build tag matches a baseline the nowisor pack was verified against (Zurich Patch 6 or Australia)",
    description:
        "The nowisor v1.0.0 verified-schema baselines are pinned to Zurich Patch 6 and Australia releases. When the instance runs an unverified build (older or newer), property names, default values, and table shapes may differ from the baseline, leading to false-positive or false-negative findings. This check reads glide.buildtag.last and matches against supported baselines, emitting an operational signal when the version is unrecognized.",
    resolutionDetails: `If this check fires:
1. Verify the instance release in System Definition > Plugins or via the build-tag in System Diagnostics.
2. If on a release older than Zurich Patch 6 or newer than the latest verified Australia patch, expect potential drift in the verified-schema findings.
3. Either upgrade the instance to a supported release, or wait for the next nowisor pack release that adds your build to the supported list.

Framework mapping:
- NIS2 Article 21§2(a): risk analysis and information system security policies (baseline integrity)
- ISO 27001 A.8.32: change management

Verified-real property: glide.buildtag.last (registered in sys_properties on Zurich Patch 6 dev265484).`,
    script: Now.include('../../../scripts/check-platform-build-drift.js'),
})
