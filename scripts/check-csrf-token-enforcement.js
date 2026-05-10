// nowisor pilot v0.1 — CSRF token enforcement check
// Verifies glide.security.use_csrf_token = 'true'
// Property baseline: nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json
// sys_id of property registration: f9f03ca50a0a0bb5658db64889d967cb
// ES5-only (Instance Scan runtime constraint)
;(function csrfTokenEnforcement(finding) {
    var SENTINEL = '__NOT_SET__'
    var value = gs.getProperty('glide.security.use_csrf_token', SENTINEL)

    if (value === SENTINEL) {
        finding.setValue(
            'finding_details',
            'glide.security.use_csrf_token is not registered in sys_properties on this instance'
        )
        finding.increment()
        return
    }

    if (value !== 'true') {
        finding.setValue(
            'finding_details',
            'CSRF token enforcement disabled. Current value: ' + value
        )
        finding.increment()
    }
})(finding)
