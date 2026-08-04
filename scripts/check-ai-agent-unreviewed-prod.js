// nowisor v1.2.0 - Active agent with no review/approval trail (AIA-002)
// Flags agentic entities active on a production-looking instance whose records
// carry no evidence of review or approval.
//
// WHAT "NO REVIEW TRAIL" MEANS HERE, PRECISELY
// The check looks for a review/approval signal on the entity itself: a resolved
// review field with a value, or an approval record. It does NOT infer review
// from sys_updated_on - an agent edited yesterday by the person who built it is
// not a reviewed agent, and treating "recently touched" as "approved" would
// make the check pass exactly where governance is weakest.
//
// Where no review FIELD exists on the release, the answer is N/A: the platform
// is not recording review state, so its absence is not evidence of a gap. That
// keeps the finding count honest on releases whose agent tables are thin.
//
// PROD DETECTION IS A HEURISTIC AND IS LABELLED AS ONE
// A connected scan cannot know an instance's role for certain. instance_name
// containing dev/test/qa/sandbox/uat/train is treated as non-prod; anything else
// is treated as prod-looking. When the signal is ambiguous the finding drops to
// INVESTIGATE rather than asserting a production control failure.
//
// Verified identifiers used directly (verified_schema, Zurich Patch 6):
//   sys_db_object  - name
//   sys_dictionary - name, element
//   sysapproval_approver - verified table (approval records)
//
// Schema: v1. ES5-only. ASCII-only, short lines.
;(function aiAgentUnreviewedProd(finding) {
    var CHECK_ID = 'nowisor-ai-agent-unreviewed-prod'
    var CHECK_VERSION = '1.0.0'
    var ROW_CAP = 200

    var SOURCES = ['sn_aia_use_case', 'sys_cb_ai_agent', 'sys_cs_topic']

    var REVIEW_HINTS = ['last_review', 'last_reviewed']
    REVIEW_HINTS.push('last_review_date')
    REVIEW_HINTS.push('reviewed_by')
    REVIEW_HINTS.push('approved_by')
    REVIEW_HINTS.push('approval')

    var ACTIVE_HINTS = ['active', 'state', 'status']
    var NAME_HINTS = ['name', 'label', 'title']

    var NONPROD_TOKENS = ['dev', 'test', 'qa']
    NONPROD_TOKENS.push('sandbox')
    NONPROD_TOKENS.push('uat')
    NONPROD_TOKENS.push('train')
    NONPROD_TOKENS.push('demo')

    var MAPPINGS = {
        nis2: ['21.2.e', '21.2.f'],
        iso27001: ['A.5.16', 'A.8.25'],
        dora: ['9.4.a'],
        owasp_llm: ['LLM06:2025'],
        mitre_atlas: ['AML.T0081', 'AML.T0103'],
        eu_ai_act: [{ article: '26', conditional: true }]
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

    function hasApproval(recordId) {
        try {
            var gr = new GlideRecord('sysapproval_approver')
            gr.addQuery('document_id', recordId)
            gr.setLimit(1)
            gr.query()
            return gr.next() ? true : false
        } catch (e) {
            return false
        }
    }

    function emit(details, metadata) {
        var out = details
        out = out + '\n\n---NOWISOR_METADATA---\n'
        out = out + JSON.stringify(metadata)
        finding.setValue('finding_details', out)
        finding.increment()
    }

    // ---- instance posture (heuristic) ------------------------------------
    var instName = ''
    try {
        instName = String(gs.getProperty('instance_name', '') || '')
    } catch (e) {
        instName = ''
    }
    var lowerName = instName.toLowerCase()
    var looksNonProd = false
    for (var n = 0; n < NONPROD_TOKENS.length; n++) {
        if (lowerName.indexOf(NONPROD_TOKENS[n]) !== -1) looksNonProd = true
    }
    var nameKnown = instName !== ''

    // ---- gate ------------------------------------------------------------
    var present = []
    for (var i = 0; i < SOURCES.length; i++) {
        if (tableExists(SOURCES[i])) present.push(SOURCES[i])
    }

    if (present.length === 0) {
        emit(
            'No agentic entity tables are present on this instance, so agent ' +
            'review state cannot be assessed. Out of scope, NOT a pass.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'no_agentic_tables',
                    tables_probed: SOURCES
                },
                severity: 4,
                remediation_id: 'ai-002-na',
                attack_path_refs: []
            }
        )
        return
    }

    // Non-prod instance: an unreviewed agent here is not a production control
    // failure. Stay silent rather than inflate the finding count.
    if (looksNonProd) return

    // ---- scan ------------------------------------------------------------
    var unreviewed = []
    var scanned = 0
    var reviewFieldTables = []
    var noReviewFieldTables = []

    for (var s = 0; s < present.length; s++) {
        var tbl = present[s]
        var revF = pickField(tbl, REVIEW_HINTS)
        var actF = pickField(tbl, ACTIVE_HINTS)
        var nameF = pickField(tbl, NAME_HINTS)
        if (!revF) {
            noReviewFieldTables.push(tbl)
            continue
        }
        reviewFieldTables.push(tbl)
        try {
            var gr = new GlideRecord(tbl)
            if (actF === 'active') gr.addQuery('active', true)
            gr.setLimit(ROW_CAP)
            gr.query()
            while (gr.next()) {
                scanned = scanned + 1
                var rv = gr.getValue(revF)
                if (rv !== null && String(rv) !== '') continue
                var rid = gr.getUniqueValue()
                if (hasApproval(rid)) continue
                var row = {}
                row.table = tbl
                row.sys_id = rid
                row.name = nameF ? gr.getValue(nameF) : null
                row.review_field = revF
                row.created_by = gr.getValue('sys_created_by')
                row.created_on = gr.getValue('sys_created_on')
                unreviewed.push(row)
            }
        } catch (e) {
            noReviewFieldTables.push(tbl)
        }
    }

    // No release-level review field anywhere -> cannot judge.
    if (scanned === 0) {
        emit(
            'Agentic entities are present, but no review / approval field ' +
            'could be resolved on this release (' +
            noReviewFieldTables.join(', ') +
            '). The platform is not recording agent review state here, so its ' +
            'absence is not evidence of an unreviewed estate. Track agent ' +
            'approval outside the agent record. No posture failure is asserted.',
            {
                nowisor_check_id: CHECK_ID,
                nowisor_check_version: CHECK_VERSION,
                nowisor_finding_schema: 'v1',
                framework_mappings: MAPPINGS,
                evidence: {
                    status: 'not_applicable',
                    reason: 'review_field_unresolved',
                    tables_present: present,
                    tables_without_review_field: noReviewFieldTables
                },
                severity: 4,
                remediation_id: 'ai-002-na',
                attack_path_refs: []
            }
        )
        return
    }

    if (unreviewed.length === 0) return

    var examples = []
    for (var x = 0; x < unreviewed.length && x < 10; x++) {
        var label = unreviewed[x].name ? unreviewed[x].name : unreviewed[x].sys_id
        var by = unreviewed[x].created_by ? unreviewed[x].created_by : 'unknown'
        examples.push(label + ' (created by ' + by + ')')
    }

    // Ambiguous instance identity -> INVESTIGATE, not an asserted prod failure.
    var ambiguous = !nameKnown
    var lead =
        unreviewed.length +
        ' of ' +
        scanned +
        ' active agentic entities carry no review or approval record. An agent ' +
        'in production without an approval trail has no point at which anyone ' +
        'accepted its permissions, its prompt, or its autonomy level - and ' +
        'nothing to re-check when any of those change. ' +
        examples.join('; ') +
        '.'

    if (ambiguous) {
        lead =
            lead +
            ' INVESTIGATE: this instance did not report an instance_name, so ' +
            'its production status could not be established - confirm the ' +
            'environment before treating this as a production gap.'
    }

    emit(
        lead +
        ' Review state is read from the resolved review field and approval ' +
        'records only; a recent sys_updated_on is deliberately NOT treated as ' +
        'evidence of review.',
        {
            nowisor_check_id: CHECK_ID,
            nowisor_check_version: CHECK_VERSION,
            nowisor_finding_schema: 'v1',
            framework_mappings: MAPPINGS,
            evidence: {
                status: ambiguous ? 'investigate' : 'fail',
                unreviewed_count: unreviewed.length,
                agents_scanned: scanned,
                instance_name: instName,
                instance_posture: ambiguous ? 'unknown' : 'prod_looking',
                prod_detection_basis: 'instance_name_token_heuristic',
                tables_with_review_field: reviewFieldTables,
                tables_without_review_field: noReviewFieldTables,
                review_evidence_sources: ['resolved_review_field', 'sysapproval_approver'],
                row_cap: ROW_CAP,
                unreviewed: unreviewed
            },
            severity: ambiguous ? 3 : 2,
            remediation_id: ambiguous ? 'ai-002-investigate' : 'ai-002',
            attack_path_refs: ['AP-013']
        }
    )
})(finding)
