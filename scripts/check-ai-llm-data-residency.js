// nowisor v1.2.0 - LLM connection terminating outside the EU (AIG-006)
// Flags model endpoints resolving to non-EU regions on instances flagged as
// EU-regulated.
//
// SCOPE GATE FIRST
// This check only speaks where residency is actually a requirement. It fires
// only when the instance shows an EU-regulated signal: an EU-region instance
// name or an EU data-centre property. On an instance with no such signal the
// check is silent - a US customer using a US model endpoint has no finding here,
// and inventing one would be noise that trains people to ignore the category.
//
// HOW REGION IS DETERMINED, AND ITS LIMIT
// From the endpoint URL only: an explicit region token in the host or path
// (eu-central-1, europe-west4, eu., .eu) or a known-global host with no region
// pin. A URL is not a data-flow proof - a provider may route differently than
// its hostname suggests, and a global endpoint may or may not process in-region.
// So a region-pinned EU endpoint passes, an explicitly non-EU region fails, and
// an unpinned global endpoint is INVESTIGATE rather than assumed non-compliant.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object   - name
//   sys_dictionary  - name, element
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiLlmDataResidency(finding) {
    var CHECK_ID = 'nowisor-ai-llm-data-residency'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var CONN_TABLES = ['sys_rest_message', 'sys_rest_message_fn']
    CONN_TABLES.push('sys_connection')
    CONN_TABLES.push('sys_connection_alias')

    var ENDPOINT_HINTS = ['rest_endpoint', 'endpoint', 'url']
    ENDPOINT_HINTS.push('host')

    var NAME_HINTS = ['name', 'label', 'title']

    // Model-provider hosts (same family as the shadow-AI check).
    var MODEL_HOSTS = ['openai.com', 'openai.azure.com']
    MODEL_HOSTS.push('anthropic.com')
    MODEL_HOSTS.push('generativelanguage.googleapis.com')
    MODEL_HOSTS.push('bedrock')
    MODEL_HOSTS.push('mistral.ai')
    MODEL_HOSTS.push('cohere.ai')

    // Region tokens that indicate EU processing.
    var EU_TOKENS = ['eu-central', 'eu-west', 'eu-north']
    EU_TOKENS.push('eu-south')
    EU_TOKENS.push('europe-west')
    EU_TOKENS.push('europe-north')
    EU_TOKENS.push('.eu/')
    EU_TOKENS.push('eu.')
    EU_TOKENS.push('frankfurt')
    EU_TOKENS.push('amsterdam')
    EU_TOKENS.push('dublin')

    // Region tokens that indicate definitively non-EU processing.
    var NONEU_TOKENS = ['us-east', 'us-west', 'us-central']
    NONEU_TOKENS.push('ap-south')
    NONEU_TOKENS.push('ap-northeast')
    NONEU_TOKENS.push('ap-southeast')
    NONEU_TOKENS.push('sa-east')
    NONEU_TOKENS.push('ca-central')
    NONEU_TOKENS.push('us-gov')

    // Instance-level EU-regulated signals.
    var EU_INSTANCE_TOKENS = ['eu', 'emea', 'de', 'fr', 'nl', 'ie', 'es', 'it']

    var MAPPINGS = {
        nis2: ['21.2.d', '21.2.h'],
        iso27001: ['A.5.15', 'A.8.24'],
        dora: ['9.3.a'],
        owasp_llm: ['LLM02:2025', 'LLM03:2025'],
        mitre_atlas: ['AML.T0025'],
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

    function fieldsOf(t) {
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
        return have
    }

    function pick(have, hints) {
        if (!have) return null
        for (var i = 0; i < hints.length; i++) {
            if (have[hints[i]]) return hints[i]
        }
        return null
    }

    function anyToken(hay, list) {
        var lower = String(hay).toLowerCase()
        for (var i = 0; i < list.length; i++) {
            if (lower.indexOf(list[i]) !== -1) return list[i]
        }
        return null
    }

    function propOrEmpty(name) {
        try {
            var v = gs.getProperty(name, '')
            return v ? String(v) : ''
        } catch (e) {
            return ''
        }
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- scope gate: is this instance EU-regulated? -----------------------
    var instName = propOrEmpty('instance_name')
    if (instName === '') return

    var euSignal = null
    var parts = String(instName).toLowerCase().split(/[^a-z0-9]+/)
    for (var p = 0; p < parts.length; p++) {
        for (var q = 0; q < EU_INSTANCE_TOKENS.length; q++) {
            if (parts[p] === EU_INSTANCE_TOKENS[q]) euSignal = 'instance_name:' + parts[p]
        }
    }
    // Not EU-flagged: residency is not a requirement here. Stay silent.
    if (!euSignal) return

    // ---- collect model endpoints -----------------------------------------
    var nonEu = []
    var unpinned = []
    var euOk = 0
    var scanned = 0

    for (var c = 0; c < CONN_TABLES.length; c++) {
        var tbl = CONN_TABLES[c]
        if (!tableExists(tbl)) continue
        var have = fieldsOf(tbl)
        var epF = pick(have, ENDPOINT_HINTS)
        if (!epF) continue
        var nameF = pick(have, NAME_HINTS)
        try {
            var gr = new GlideRecord(tbl)
            gr.addQuery(epF, '!=', '')
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                var ep = gr.getValue(epF)
                if (!ep) continue
                if (!anyToken(ep, MODEL_HOSTS)) continue
                scanned = scanned + 1

                var row = {}
                row.table = tbl
                row.sys_id = gr.getUniqueValue()
                row.name = nameF ? gr.getValue(nameF) : null
                row.endpoint = ep
                row.endpoint_column = epF

                var euHit = anyToken(ep, EU_TOKENS)
                var nonEuHit = anyToken(ep, NONEU_TOKENS)

                if (nonEuHit) {
                    row.region_token = nonEuHit
                    nonEu.push(row)
                } else if (euHit) {
                    euOk = euOk + 1
                } else {
                    row.region_token = null
                    unpinned.push(row)
                }
            }
        } catch (e) {
            // unreadable table - excluded, not fatal
        }
    }

    if (scanned === 0) return
    if (nonEu.length === 0 && unpinned.length === 0) return

    var lead
    var status
    var sev
    var remId

    if (nonEu.length > 0) {
        var ex = []
        for (var x = 0; x < nonEu.length && x < 5; x++) {
            var nm = nonEu[x].name ? nonEu[x].name : nonEu[x].sys_id
            ex.push(nm + ' [' + nonEu[x].region_token + ']')
        }
        status = 'fail'
        sev = 2
        remId = 'aig-006'
        lead =
            nonEu.length +
            ' model endpoint(s) on this EU-flagged instance are pinned to a ' +
            'non-EU region: ' +
            ex.join('; ') +
            '. Instance data reaching a model in that region leaves the EU, ' +
            'which needs a transfer basis and a supplier assessment the ' +
            'endpoint configuration does not carry.'
    } else {
        var ux = []
        for (var y = 0; y < unpinned.length && y < 5; y++) {
            var un = unpinned[y].name ? unpinned[y].name : unpinned[y].sys_id
            ux.push(un)
        }
        status = 'investigate'
        sev = 3
        remId = 'aig-006-investigate'
        lead =
            'INVESTIGATE: ' +
            unpinned.length +
            ' model endpoint(s) on this EU-flagged instance carry no region ' +
            'pin in their URL: ' +
            ux.join(', ') +
            '. A global endpoint may or may not process in-region, and the ' +
            'hostname does not say which. Confirm the processing region with ' +
            'the provider and pin the endpoint where the provider offers it.'
    }

    emit(
        lead +
        ' Region is inferred from the endpoint URL only - a URL is not a ' +
        'data-flow proof, and this check does not observe traffic. EU-pinned ' +
        'endpoints found: ' +
        euOk +
        '.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: status,
                eu_scope_signal: euSignal,
                instance_name: instName,
                endpoints_scanned: scanned,
                non_eu_count: nonEu.length,
                unpinned_count: unpinned.length,
                eu_pinned_count: euOk,
                detection_basis: 'endpoint_url_region_token_only',
                claim_boundary: 'url_inference_not_traffic_observation',
                row_cap: ROW_CAP,
                non_eu_endpoints: nonEu,
                unpinned_endpoints: unpinned
            },
            severity: sev,
            remediation_id: remId,
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
