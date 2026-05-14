// nowisor v1.0.0 — Compliance Rollup
//
// What it does: parses every nowisor finding's embedded NOWISOR_METADATA
// JSON block and prints a per-framework rollup (NIS2, DORA, ISO 27001, GDPR)
// showing which articles are cited, how many findings hit each article, the
// severity breakdown, and which checks fired.
//
// Why this exists: ServiceNow's standard Instance Scan UI renders
// scan_finding.finding_details as a single text field. The framework mapping
// is encoded inside finding_details as JSON below a ---NOWISOR_METADATA---
// separator (chosen at design time because scan_finding has no structured
// metadata columns and modifying it would add install friction). The
// trade-off is that compliance grouping is invisible in the OOB UI unless
// you parse the JSON. This script does that parsing.
//
// How to use: paste into System Definition -> Scripts - Background, click
// Run script. Read-only, safe for production. Will print to script output;
// nothing is written to any table.
//
// ES5-only (Background Script runtime constraint).
;(function complianceRollup() {
    var SEPARATOR = '---NOWISOR_METADATA---';
    var SCOPE = 'x_nowisor_isp';
    var FRAMEWORKS = ['nis2', 'dora', 'iso27001', 'gdpr'];
    var SEVERITY_LABEL = { 1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW' };

    var rollup = {};
    FRAMEWORKS.forEach(function (f) { rollup[f] = {}; });

    var totalFindings = 0;
    var parseErrors = 0;
    var noMetadata = 0;
    var noMappings = 0;

    var gr = new GlideRecord('scan_finding');
    gr.addQuery('check.sys_scope.scope', SCOPE);
    gr.query();

    while (gr.next()) {
        totalFindings++;
        var details = gr.getValue('finding_details') || '';
        var idx = details.indexOf(SEPARATOR);
        if (idx < 0) { noMetadata++; continue; }
        var jsonText = details.substring(idx + SEPARATOR.length).trim();
        var meta;
        try {
            meta = JSON.parse(jsonText);
        } catch (e) {
            parseErrors++;
            continue;
        }
        var sev = parseInt(meta.severity, 10) || 0;
        var checkId = meta.nowisor_check_id || 'unknown';
        var mappings = meta.framework_mappings || {};

        var anyMapping = false;
        FRAMEWORKS.forEach(function (f) {
            var articles = mappings[f] || [];
            if (!articles.length) return;
            anyMapping = true;
            articles.forEach(function (art) {
                if (!rollup[f][art]) {
                    rollup[f][art] = { count: 0, severities: {1:0,2:0,3:0,4:0}, checks: {} };
                }
                rollup[f][art].count++;
                if (rollup[f][art].severities[sev] === undefined) {
                    rollup[f][art].severities[sev] = 0;
                }
                rollup[f][art].severities[sev]++;
                rollup[f][art].checks[checkId] = true;
            });
        });
        if (!anyMapping) noMappings++;
    }

    gs.print('================================================================');
    gs.print('nowisor Compliance Rollup');
    gs.print('================================================================');
    gs.print('Total nowisor findings:        ' + totalFindings);
    gs.print('Findings without metadata:     ' + noMetadata);
    gs.print('Findings with parse errors:    ' + parseErrors);
    gs.print('Findings without any mapping:  ' + noMappings);
    gs.print('');

    if (totalFindings === 0) {
        gs.print('No findings in scope ' + SCOPE + '. Has the suite scan been executed?');
        gs.print('Try: Instance Scan -> Suite Scans -> nowisor Instance Scan Pack -> Execute Suite Scan');
        return;
    }

    FRAMEWORKS.forEach(function (f) {
        var articles = Object.keys(rollup[f]).sort();
        gs.print('----------------------------------------------------------------');
        if (!articles.length) {
            gs.print(f.toUpperCase() + ': no findings mapped to this framework');
            return;
        }
        gs.print(f.toUpperCase() + ' (' + articles.length + ' article(s) cited)');
        gs.print('----------------------------------------------------------------');
        articles.forEach(function (art) {
            var data = rollup[f][art];
            var sevBreakdown = [];
            [1,2,3,4].forEach(function (s) {
                if (data.severities[s]) {
                    sevBreakdown.push(SEVERITY_LABEL[s] + '=' + data.severities[s]);
                }
            });
            var checkIds = Object.keys(data.checks).sort();
            gs.print('  ' + art + ': ' + data.count + ' finding(s) [' + sevBreakdown.join(', ') + ']');
            gs.print('    checks: ' + checkIds.join(', '));
        });
        gs.print('');
    });

    gs.print('================================================================');
    gs.print('End of rollup. For CISO-language explanation of each article and');
    gs.print('finding-by-finding remediation, connect the instance to the');
    gs.print('nowisor advisor at https://nowisor.com');
    gs.print('================================================================');
})();
