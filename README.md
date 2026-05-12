# nowisor Instance Scan Agent

Open-source ServiceNow security check pack that runs inside your instance and produces structured findings consumed by the [nowisor](https://nowisor.com) AI security advisor.

- **Pack version:** 1.0.0
- **Finding schema:** v1 (stable; backwards-compat policy in §Schema and versioning)
- **License:** Apache-2.0
- **Verified against:** ServiceNow Zurich Patch 6 (dev265484), Australia GA (forthcoming dev377226 verification — see Compatibility)
- **SDK requirement:** `@servicenow/sdk` ≥ 4.6.0 (only required if you build from source; the pre-built update set has no runtime SDK dependency)

## What this is

The nowisor agent is the open-source sensor surface of the nowisor product. It runs as a scoped application (`x_nowisor_isp`) inside your ServiceNow instance. Each scan execution produces `scan_finding` records, each finding carrying both a human-readable description and a structured `---NOWISOR_METADATA---` JSON block parseable by external tooling — primarily the nowisor advisor at nowisor.com, but the schema is open and any consumer can parse it.

The agent ships with 26 checks across four categories:

| Category | Count | What it audits |
|---|---|---|
| Platform property hardening | 8 | Security-relevant `glide.*` properties: CSRF, cookies, session timeout, MFA, REST anonymous access, external auth policy |
| ACL and role configuration | 6 | Admin role concentration, inactive users retaining roles, attachment role restrictions, OOB ACL modifications, cross-scope privilege grants, elevated role co-assignments |
| Code analysis (AST-based) | 8 | `eval()`, `setWorkflow(false)`, `GlideEvaluator`, `GlideRecord` vs `GlideRecordSecure`, `setRoles()`, hardcoded credentials, direct `sys_properties` writes, cross-domain Script Includes |
| Cross-cutting | 4 | Update-set XML privilege-escalation patterns, fabricated property references, meta check coverage, platform build drift |

The full machine-readable inventory is in [`manifest.json`](./manifest.json).

## What this is not

This pack is **not** a replacement for ServiceNow Security Center or the platform's built-in scan checks. It runs alongside them. The differences:

- **Framework alignment.** nowisor checks map to NIS2, DORA, ISO 27001, and GDPR — the CISO-facing regulatory frameworks. Security Center's checks align primarily to OWASP ASVS, which targets the developer audience. The two complement each other; deploy both.
- **Detection model.** nowisor includes AST-based linting (Code analysis category) and finding-level metadata for downstream automation. Security Center provides broader platform telemetry.
- **Coordination layer.** nowisor findings are designed to be consumed by the nowisor advisor (paid tier) for AI-assisted triage. The findings remain in your instance regardless — you can read them directly in the `scan_finding` table or via the standard Instance Scan UI.

## Installation

### Option A: Pre-built application bundle (recommended for non-developers)

The pack distributes as a tarball of per-record ServiceNow XMLs (the modern source-driven SDK format), not a single legacy update set XML.

1. Download `dist/update-sets/nowisor-agent-v1.0.0.tar.gz`
2. Extract locally. You'll see `app/scope/` (1 file) and `app/update/` (46 files)
3. Install via the SDK on a workstation that has the credentials configured:
   ```bash
   npm install -g @servicenow/sdk@4.6.0
   npx now-sdk auth --add https://yourinstance.service-now.com --type basic --alias your-alias
   # extract the tarball into a workspace, then:
   npx now-sdk install --source <extracted-dir> --auth your-alias
   ```
4. Run the suite bootstrap (next section)
5. Verify by navigating to **System Definition → Scan → Scan Checks** — you should see 26 active nowisor checks

If you cannot install the ServiceNow SDK locally, contact your ServiceNow administrator — they can install on your behalf. A pure-XML single-file distribution is on the v1.1 roadmap.

### Option B: Build from source (developers / pinning to a fork)

```bash
git clone https://github.com/nowisor-com/instance-scan-agent
cd instance-scan-agent
npm install
npx now-sdk auth --add https://yourinstance.service-now.com --type basic --alias your-alias
npx now-sdk build
npx now-sdk install --auth your-alias
```

Then run the suite bootstrap (next section).

### Required post-install step: suite bootstrap

ServiceNow's Fluent SDK 4.6.0 does not expose a `ScanCheckSuite` API. The suite that aggregates the 26 checks must be provisioned via Background Script after the update set installs.

1. Navigate to **System Definition → Scripts - Background**
2. Open [`bootstrap/install-suite.js`](./bootstrap/install-suite.js)
3. Paste the entire script into the Background Script editor
4. Click **Run script**
5. Read the output — it should confirm "Suite … is ready" and list the number of checks linked

The script is **idempotent**. Safe to re-run. If you upgrade the pack later (`now-sdk install --reinstall`), the m2m rows are cascade-deleted — re-run the bootstrap to re-link them. `scan_finding` records persist across reinstalls.

## Running scans

### Ad-hoc via REST

```bash
curl -u admin:$SN_PASS -H 'Accept: application/json' \
  -X POST 'https://yourinstance.service-now.com/api/sn_cicd/instance_scan/full_scan'
```

Returns a progress URL. Poll until status is `Successful`. Findings appear in the `scan_finding` table filtered by `check.sys_scope.name=x_nowisor_isp`.

### Ad-hoc via UI

Navigate to **Instance Scan → Suite Scans**, open the **nowisor Instance Scan Pack** suite, click **Execute Suite Scan**.

### Scheduled

Navigate to **Instance Scan → Scheduled Scans**, create a new scheduled scan, set the suite to **nowisor Instance Scan Pack**, set the cadence (weekly is a reasonable default for production instances).

## Reading findings

Findings appear as records in the `scan_finding` table. Each finding has two layers:

1. **Human-readable description** at the top of `finding_details`
2. **Structured metadata** below a `---NOWISOR_METADATA---` separator

Example finding text:

```
CSRF token enforcement is disabled. The platform does not validate CSRF tokens on
state-changing requests, exposing authenticated sessions to cross-site request forgery.

Current value: false. Expected: true.

---NOWISOR_METADATA---
{
  "nowisor_check_id": "nowisor-csrf-token-enforcement",
  "nowisor_check_version": "1.0.0",
  "nowisor_finding_schema": "v1",
  "framework_mappings": {
    "nis2": ["21.2.a"],
    "iso27001": ["A.5.15"],
    "dora": ["9"]
  },
  "evidence": {
    "property_name": "glide.security.use_csrf_token",
    "expected_value": "true",
    "actual_value": "false"
  },
  "severity": 1,
  "remediation_id": "csrf-001",
  "attack_path_refs": ["AP-002"]
}
```

To parse all nowisor findings programmatically:

```javascript
// In a Background Script — pulls all current nowisor findings as structured data
var gr = new GlideRecord('scan_finding');
gr.addQuery('check.sys_scope.name', 'x_nowisor_isp');
gr.query();
while (gr.next()) {
    var details = gr.getValue('finding_details') || '';
    var idx = details.indexOf('---NOWISOR_METADATA---');
    if (idx < 0) continue;
    var jsonText = details.substring(idx + '---NOWISOR_METADATA---'.length).trim();
    try {
        var meta = JSON.parse(jsonText);
        gs.print(meta.nowisor_check_id + ' severity=' + meta.severity);
    } catch (e) {
        gs.print('Malformed metadata in finding ' + gr.getValue('sys_id'));
    }
}
```

## Schema and versioning

### Finding schema v1

```
nowisor_check_id          string — full kebab id (e.g., "nowisor-csrf-token-enforcement")
nowisor_check_version     string — semver of the check at finding-emission time
nowisor_finding_schema    "v1" (literal; bumped only for breaking schema changes)
framework_mappings        object — lowercase keys (nis2, iso27001, dora, gdpr), array values
evidence                  object — check-specific; always present, may be {}
severity                  integer 1–4 (1=Critical, 4=Low; mirrors check priority)
remediation_id            string — short kebab id for remediation tracking
attack_path_refs          array of strings — AP-XXX nowisor KB identifiers; may be empty
```

The `---NOWISOR_METADATA---` separator is exact. Consumers parse by splitting on this string.

### Check IDs and versioning

Check IDs are **immutable**. If a check's logic changes incompatibly, the pack ships a NEW $id and the old $id is deprecated (kept as `active: false`) for one minor-version cycle, then removed.

Pack versions follow semver:
- Patch (1.0.x): bug fixes in check scripts; no schema changes
- Minor (1.x.0): new checks, evidence-schema additions; no breaking changes to schema fields
- Major (x.0.0): finding schema breaking change (bumps `nowisor_finding_schema`); backwards-compat window: current + previous, 12 months

## Upgrading

```bash
npx now-sdk install --auth your-alias --reinstall
# m2m rows are cascade-deleted on --reinstall; re-run the bootstrap:
# Background Script → paste bootstrap/install-suite.js → Run
```

Or via update set: download the new XML from `dist/update-sets/`, import, preview, commit, re-run bootstrap.

Existing `scan_finding` records persist (FK is preserved against deterministic check sys_ids).

## Connecting to the nowisor advisor

The advisor at [nowisor.com](https://nowisor.com) consumes your findings to produce AI-assisted triage, remediation playbooks, and compliance reports. Connection is optional — your findings stay in your instance regardless.

To connect:

1. Sign in to nowisor.com
2. Navigate to **Connect → ServiceNow Instance**
3. Follow the OAuth 2.0 Authorization Code flow (the advisor never receives your admin credentials; it operates under a dedicated `nowisor_advisor` user with read-only `scan_finding` access)
4. The advisor pulls findings on a schedule you set (default: hourly)

Free tier (Community): pack-only, no advisor.
Paid tiers (Pro / Enterprise): advisor enabled.

## Troubleshooting

### "No findings produced after scan"

- **Suite not bootstrapped.** Run `bootstrap/install-suite.js`. Without it, the platform's full-scan engine never executes the checks.
- **Checks inactive.** Navigate to Scan Checks list filtered by scope `x_nowisor_isp` — confirm all 26 are `active=true`.
- **Cross-scope read denied.** If scan_check_execution records show "permission denied" on Global tables, your instance enforces strict scope isolation. The pack ships 17 `CrossScopePrivilege` records — verify they were committed in the update set.

### "Build fails with TypeScript errors in keys.ts"

`keys.ts` is auto-generated by `now-sdk build`. If it's out of date, delete it (`rm src/fluent/generated/keys.ts`) and re-run `npx now-sdk build`. The SDK regenerates deterministic sys_ids from `$id` references.

### "Bootstrap script reports 0 active nowisor checks"

Either:
1. Update set was imported but not committed
2. Scope name mismatch — confirm `x_nowisor_isp` matches your installed scope (rare; would indicate the pack was forked and renamed)

### "Findings have garbled JSON in finding_details"

The JSON should be valid JSON-parseable text after the `---NOWISOR_METADATA---` separator. If it's not, you may be looking at an old finding from a pre-v1 pilot. Re-run the suite after updating to v1.0.0; new findings will use the v1 schema.

## Compatibility

| Release | Verified | Status |
|---|---|---|
| Zurich Patch 6 | dev265484 | Fully verified (property baseline complete) |
| Australia (GA) | (forthcoming dev377226) | Pack expected to install cleanly; some property baselines pending |
| Older releases (Yokohama, Xanadu, Washington DC) | not verified | Likely works but unverified; file an issue if you test |

The 17 `CrossScopePrivilege` records ship with the pack so it functions correctly even in instances with strict scope isolation. The pack does not require admin elevation; the executing user needs read on `scan_finding`, `scan_check_*`, and the in-scope tables the audit checks touch (audit of sys_user, sys_security_acl, sys_script_include, etc.).

## Contributing

- **Issues / proposed checks:** [github.com/nowisor-com/instance-scan-agent/issues](https://github.com/nowisor-com/instance-scan-agent/issues) (replace with your fork URL if not from upstream)
- **Property-name verification rule:** every `glide.*` property referenced must exist on a verified PDI. The pack ships with a verified baseline at `nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json` (3,585 properties). Pull requests that reference unverified property names will not be merged.
- **AST predicate verification:** every LinterCheck predicate must be verified against a planted test artifact before the check is enabled. Pilot procedure documented in `V0_2_RETROSPECTIVE.md`.

## License

Apache-2.0. See `LICENSE` for the full text.

## Project context

This pack is the open-source sensor surface of nowisor — the paid advisor at nowisor.com is a separate product. The agent itself is fully open-source under Apache-2.0 and produces findings that anyone can consume. The Datadog Agent/SaaS pattern, not the GitLab CE/EE pattern: the agent is permissive, the advisor is the commercial offering.

Strategic context (architecture decisions, framework alignment rationale, advisor product scope) is documented in `/nowisor/SCOPING_v1.md` in the parent repository.
