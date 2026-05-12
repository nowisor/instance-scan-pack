// nowisor v1.0.0 — Platform build drift (ScriptOnlyCheck)
// Reads glide.buildtag.last and matches against supported baselines.
//
// Verified-real property: glide.buildtag.last on Zurich Patch 6 dev265484
// (recorded in nowisor/verified_schema/releases/zurich/properties).
// Supported baselines for v1.0.0:
//   - Zurich Patch 6 (substring match: zurich.*patch6)
//   - Australia GA + patches (substring match: glide-australia / australia.*patch[0-9]+)
//
// Schema: v1 (finding emits ---NOWISOR_METADATA--- block parsed by advisor)
// ES5-only (Instance Scan runtime constraint)
;(function platformBuildDrift(finding) {
    var SENTINEL = '__NOT_SET__'
    var PROP = 'glide.buildtag.last'
    var buildtag = gs.getProperty(PROP, SENTINEL)

    var supportedPatterns = [
        { label: 'Zurich Patch 6', regex: /zurich.*patch6/i },
        { label: 'Australia GA', regex: /^glide-australia/i },
        { label: 'Australia patch', regex: /australia.*patch[0-9]+/i },
    ]

    var notSetCase = buildtag === SENTINEL
    var matched = false
    var matchedLabel = ''

    if (!notSetCase) {
        for (var i = 0; i < supportedPatterns.length; i++) {
            if (supportedPatterns[i].regex.test(buildtag)) {
                matched = true
                matchedLabel = supportedPatterns[i].label
                break
            }
        }
    }

    if (matched) return

    var description
    if (notSetCase) {
        description =
            'glide.buildtag.last is not registered on this instance — cannot determine platform release. The nowisor verified-schema baselines may not match this build.'
    } else {
        description =
            'Platform build tag (' +
            buildtag +
            ') does not match any nowisor v1.0.0 supported baseline (Zurich Patch 6 or Australia). Findings from verified-schema checks may include false positives or negatives until the pack is re-verified against this release.'
    }

    var supportedLabels = []
    for (var j = 0; j < supportedPatterns.length; j++) {
        supportedLabels.push(supportedPatterns[j].label)
    }

    var metadata = {
        nowisor_check_id: 'nowisor-platform-build-drift',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.a'],
            iso27001: ['A.8.32'],
        },
        evidence: {
            property_name: PROP,
            actual_value: notSetCase ? 'NOT_REGISTERED' : buildtag,
            supported_baselines: supportedLabels,
            matched: matched,
            matched_baseline: matchedLabel || null,
        },
        severity: 3,
        remediation_id: 'build-drift-001',
        attack_path_refs: [],
    }

    var details =
        description + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(metadata)

    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
