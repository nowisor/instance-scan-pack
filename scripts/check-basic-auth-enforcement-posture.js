// nowisor v1.1.0 - Basic Auth enforcement posture check (BASICAUTH-02)
// Reads glide.authenticate.basic_auth.restriction.{enforce,enforcement_date,
//   default_decision}. Verified REAL on Zurich Patch 6 (dev265484), 2026-06-11
//   (enforce=false, enforcement_date populated, default_decision a human label).
// Schema: v1   ES5-only (Instance Scan runtime constraint)
;(function basicAuthEnforcementPosture(finding) {
    var SENTINEL = '__NOT_SET__'
    var P_ENFORCE = 'glide.authenticate.basic_auth.restriction.enforce'
    var P_DATE = 'glide.authenticate.basic_auth.restriction.enforcement_date'
    var P_DEFAULT = 'glide.authenticate.basic_auth.restriction.default_decision'

    var enforce = gs.getProperty(P_ENFORCE, SENTINEL)
    var dateStr = gs.getProperty(P_DATE, SENTINEL)
    var defDecision = gs.getProperty(P_DEFAULT, SENTINEL)

    // Feature not present -> BASICAUTH-01 owns the not_applicable finding.
    if (enforce === SENTINEL) return
    // Enforcement already live -> healthy posture, no finding.
    if (enforce === 'true') return

    var metadata = {
        nowisor_check_id: 'nowisor-basic-auth-enforcement-posture',
        nowisor_check_version: '1.0.0',
        nowisor_finding_schema: 'v1',
        framework_mappings: {
            nis2: ['21.2.j'],
            iso27001: ['A.8.5'],
            dora: ['9'],
        },
        evidence: {
            enforce: enforce,
            enforcement_date: dateStr === SENTINEL ? null : dateStr,
            default_decision: defDecision === SENTINEL ? null : defDecision,
        },
        severity: 3,
        remediation_id: 'basicauth-002',
        attack_path_refs: [],
    }

    var days = null
    if (dateStr !== SENTINEL && dateStr) {
        var ed = new GlideDateTime(dateStr)
        var now = new GlideDateTime()
        days = Math.floor((ed.getNumericValue() - now.getNumericValue()) / 86400000)
        metadata.evidence.days_remaining = days
    }

    var defTxt = defDecision === SENTINEL ? 'not set' : defDecision
    var description
    if (days !== null && days < 0) {
        // Enforcement date passed but enforce still false: deferred / overridden.
        metadata.severity = 2
        description =
            'Basic Auth enforcement is OFF (' +
            P_ENFORCE +
            ' = false) even though the enforcement date (' +
            dateStr +
            ') is ' +
            Math.abs(days) +
            ' day(s) in the past. Enforcement appears deferred or overridden after the vendor date - the MFA-bypass surface persists with no scheduled closure. Default decision: ' +
            defTxt +
            '.'
    } else if (days !== null) {
        // Future date: tracking-mode countdown (the sellable "N days" number).
        metadata.severity = 3
        description =
            'Basic Auth enforcement is in TRACKING mode (' +
            P_ENFORCE +
            ' = false). Enforcement begins in ' +
            days +
            ' day(s), on ' +
            dateStr +
            '. After that, interactive accounts using Basic Auth APIs are blocked unless allow-listed. Use the ' +
            days +
            '-day window to validate integrations (Discovery, Service Graph Connectors, Intune/JAMF/SCCM, IntegrationHub REST, custom). Default decision: ' +
            defTxt +
            '.'
    } else {
        // enforce=false, no usable enforcement date.
        metadata.severity = 3
        description =
            'Basic Auth enforcement is OFF (' +
            P_ENFORCE +
            ' = false) with no enforcement date set. The feature is tracking only, with no scheduled enforcement - the hybrid-account MFA-bypass surface has no closure date. Default decision: ' +
            defTxt +
            '.'
    }

    var details =
        description + '\n\n---NOWISOR_METADATA---\n' + JSON.stringify(metadata)
    finding.setValue('finding_details', details)
    finding.increment()
})(finding)
