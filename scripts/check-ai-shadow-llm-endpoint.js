// nowisor v1.2.0 - Shadow AI: unsanctioned external LLM endpoint check (AIA-003)
// Flags outbound integrations pointing at external model providers that do NOT
// go through the Generative AI Controller / a sanctioned connection alias.
//
// WHY THIS IS THE CONVERSION TRIGGER
// A REST message or connection alias posting instance data to an external model
// endpoint is an undeclared data-export path: it bypasses the Gen AI
// Controller's logging, its data-handling configuration, and any DPA the
// organisation signed. It is the one agentic finding a customer can neither
// dispute nor see in native tooling, which is why the count (not the detail)
// is exposed on the free tier.
//
// DETECTION IS HOST-MATCH ONLY, AND SAYS SO
// The check matches configured endpoint URLs against a list of known model-provider
// hosts. It reports what is configured, never what was transmitted: a read-only
// scan cannot observe traffic. Sanctioned-vs-shadow is decided by whether the
// Gen AI Controller surface exists and whether the integration routes through it;
// where that cannot be established the finding says so rather than assuming
// the worst.
//
// The endpoint FIELD is discovered from sys_dictionary, not assumed - endpoint
// column names differ across sys_rest_message / sys_connection / alias tables
// and across releases.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object  - name
//   sys_dictionary - name, element
//   sys_rest_message - verified table (REST outbound definitions)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiShadowLlmEndpoint(finding) {
    var CHECK_ID = 'nowisor-ai-shadow-llm-endpoint'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    // Outbound-integration tables UNDER TEST, not verified identifiers.
    var SOURCES = ['sys_rest_message', 'sys_rest_message_fn']
    SOURCES.push('sys_connection')
    SOURCES.push('sys_connection_alias')

    var ENDPOINT_HINTS = ['rest_endpoint', 'endpoint', 'url']
    ENDPOINT_HINTS.push('host')

    var NAME_HINTS = ['name', 'label', 'title']

    // Known external model-provider hosts. A hit means "this integration is
    // configured to reach a model provider", nothing more.
    var HOSTS = ['openai.com', 'openai.azure.com']
    HOSTS.push('anthropic.com')
    HOSTS.push('generativelanguage.googleapis.com')
    HOSTS.push('mistral.ai')
    HOSTS.push('cohere.ai')
    HOSTS.push('huggingface.co')
    HOSTS.push('api.together.xyz')
    HOSTS.push('api.groq.com')

    // Presence of a Gen AI Controller surface = a sanctioned route exists.
    var CONTROLLER_TABLES = ['sn_gen_ai_provider_config']
    CONTROLLER_TABLES.push('sys_generative_ai_definition')
    CONTROLLER_TABLES.push('sn_gen_ai_capability')

    var MAPPINGS = {
        nis2: ['21.2.a', '21.2.d'],
        iso27001: ['A.5.15', 'A.8.16'],
        dora: ['9.3.a', '9.4.c'],
        owasp_llm: ['LLM02:2025', 'LLM03:2025'],
        mitre_atlas: ['AML.T0025', 'AML.T0096'],
        eu_ai_act: [{ article: '50', conditional: true }]
    }

    function tableExists(t) {
        try {
            var d = new GlideRecord('sys_db_object')
            d.addQuery('name', t)
            d.setLimit(1)
            d.query()
            return d.next() ? true : false
        } catch (e) {
            return false
        }
    }

    function pickField(t, hints) {
        var have = {}
        try {
            var d = new GlideRecord('sys_dictionary')
            d.addQuery('name', t)
            d.addQuery('element', '!=', '')
            d.setLimit(ROW_CAP)
            d.query()
            while (d.next()) {
                have[d.getValue('element')] = true
            }
        } catch (e) {
            return null
        }
        for (var i = 0; i < hints.length; i++) {
            if (have[hints[i]]) return hints[i]
        }
        return null
    }

    function matchHost(url) {
        var lower = String(url).toLowerCase()
        for (var i = 0; i < HOSTS.length; i++) {
            if (lower.indexOf(HOSTS[i]) !== -1) return HOSTS[i]
        }
        return null
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- gate ------------------------------------------------------------
    var scannable = []
    for (var i = 0; i < SOURCES.length; i++) {
        if (tableExists(SOURCES[i])) scannable.push(SOURCES[i])
    }

    if (scannable.length === 0) {
        emit(
            'No outbound integration tables are readable on this instance, so ' +
            'external model endpoints cannot be enumerated. This is a coverage ' +
            'gap, NOT a passing result.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_outbound_tables',
                    tables_probed: SOURCES
                },
                severity: 4,
                remediation_id: 'ai-003-na',
                attack_path_refs: []
            }
        )
        return
    }

    // Is there a sanctioned route at all on this instance?
    var controllerPresent = false
    var controllerTable = null
    for (var c = 0; c < CONTROLLER_TABLES.length; c++) {
        if (tableExists(CONTROLLER_TABLES[c])) {
            controllerPresent = true
            controllerTable = CONTROLLER_TABLES[c]
            break
        }
    }

    // ---- scan ------------------------------------------------------------
    var hits = []
    var scanned = 0
    var unresolved = []

    for (var s = 0; s < scannable.length; s++) {
        var tbl = scannable[s]
        var epF = pickField(tbl, ENDPOINT_HINTS)
        if (!epF) {
            unresolved.push(tbl)
            continue
        }
        var nameF = pickField(tbl, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.addQuery(epF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scanned = scanned + 1
                var ep = gr.getValue(epF)
                if (!ep) continue
                var host = matchHost(ep)
                if (!host) continue
                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.endpoint_field = epF
                row.endpoint = ep
                row.matched_host = host
                row.name = nameF ? gr.getValue(nameF) : null
                hits.push(row)
            }
        } catch (e) {
            unresolved.push(tbl)
        }
    }

    if (hits.length === 0) return

    var hostSet = {}
    var hostList = []
    for (var h = 0; h < hits.length; h++) {
        var mh = hits[h].matched_host
        if (!hostSet[mh]) {
            hostSet[mh] = true
            hostList.push(mh)
        }
    }

    // Honest severity: an unsanctioned export path is CRITICAL, but if no
    // controller surface exists at all we cannot claim the integration
    // "bypassed" one - it is still an undeclared export path, reported as
    // INVESTIGATE rather than asserted as a control bypass.
    var sev = controllerPresent ? 1 : 3
    var posture = controllerPresent ? 'bypasses_controller' : 'no_controller_present'

    var lead
    if (controllerPresent) {
        lead =
            hits.length +
            ' outbound integration(s) are configured to reach external model ' +
            'providers (' +
            hostList.join(', ') +
            ') while a Generative AI Controller surface exists on this ' +
            'instance (' +
            controllerTable +
            '). Instance data leaving through an integration the controller ' +
            'does not mediate is an undeclared export path: it is outside the ' +
            'controller-side logging and data-handling configuration, and ' +
            'outside whatever DPA covers the sanctioned route.'
    } else {
        lead =
            hits.length +
            ' outbound integration(s) are configured to reach external model ' +
            'providers (' +
            hostList.join(', ') +
            '). No Generative AI Controller surface was found on this ' +
            'instance, so these cannot be described as controller bypasses - ' +
            'but they are undeclared model-data export paths and need an ' +
            'owner, a DPA and a logging decision. Verify each one.'
    }

    emit(
        lead +
        ' Detection is configuration-based: this check reports what is ' +
        'configured to be reachable, not what was transmitted.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: controllerPresent ? 'fail' : 'investigate',
                posture: posture,
                shadow_endpoint_count: hits.length,
                matched_hosts: hostList,
                integrations_scanned: scanned,
                controller_present: controllerPresent,
                controller_table: controllerTable,
                tables_unresolved: unresolved,
                row_cap: ROW_CAP,
                detection_basis: 'configured_endpoint_host_match',
                endpoints: hits
            },
            severity: sev,
            remediation_id: controllerPresent ? 'ai-003' : 'ai-003-investigate',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
