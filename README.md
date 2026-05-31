# nowisor Instance Scan Agent

> **This pack now lives at [github.com/nowisor/instance-scan-pack](https://github.com/nowisor/instance-scan-pack) as a public Apache-2.0 open-source repository.**
>
> The contents in this monorepo subdirectory are retained for build-time artifacts and historical reference. For installation, contribution, issue reporting, or release notes, please use the public repository.

Open-source ServiceNow security check pack that runs inside your instance and produces structured findings consumed by the [nowisor](https://nowisor.com) AI security advisor.

- **Pack version:** 1.0.0
- **Finding schema:** v1 (stable; backwards-compat policy in §Schema and versioning)
- **Log-export schema:** v1 (stable; companion schema for the twin-sensor log export)
- **License:** Apache-2.0
- **Verified against:** ServiceNow Zurich Patch 6 (dev265484) and Australia Patch 2 (dev194572). On Australia the instance rejects the app as third-party until the pack's vendor key is trusted — one Background Script; see [Compatibility](#compatibility) / [Troubleshooting](#troubleshooting).
- **SDK requirement:** `@servicenow/sdk` ≥ 4.6.0 to build and install from source (current 4.7.0; 4.4.0+ supports the Australia release). The installed app has no *runtime* SDK dependency, but every install path — including the pre-built package under `dist/` — uploads through the instance's app-client processor, which has its own server-side prerequisites (see [Troubleshooting → "Install fails — application was null"](#troubleshooting)).

## What this is

The nowisor agent is the open-source **twin-sensor** surface of the nowisor product. It runs as a scoped application (`x_nowisor_isp`) inside your ServiceNow instance and emits two complementary streams, both consumed by the nowisor advisor's correlation engine:

1. **Sensor surface #1 — config findings.** 27 scan checks emit `scan_finding` records carrying a human-readable description plus a structured `---NOWISOR_METADATA---` JSON block. These capture static security posture (properties, ACLs, code patterns).
2. **Sensor surface #2 — log export.** A single Background Script (`tools/security-log-export.js`) emits a `---NOWISOR_LOGEXPORT---` envelope carrying runtime activity over a configurable lookback window (default 7 days): sys_audit on security-critical tables, sysevent discovery, syslog_transaction aggregated by user.

The advisor binds the two streams: findings tell you what's misconfigured; the log export tells you which misconfigurations were actually exercised. This is the active-risk distinction. **No correlation logic ships in this pack** — that work lives in the closed-source advisor at nowisor.com. The pack is a pure sensor; consumers are free to ingest the schemas and run their own correlation.

The 27 config checks span four categories:

| Category | Count | What it audits |
|---|---|---|
| Platform property hardening | 8 | Security-relevant `glide.*` properties: CSRF, cookies, session timeout, MFA, REST anonymous access, external auth policy |
| ACL and role configuration | 6 | Admin role concentration, inactive users retaining roles, attachment role restrictions, OOB ACL modifications, cross-scope privilege grants, elevated role co-assignments |
| Code analysis (AST-based) | 8 | `eval()`, `setWorkflow(false)`, `GlideEvaluator`, `GlideRecord` vs `GlideRecordSecure`, `setRoles()`, hardcoded credentials, direct `sys_properties` writes, cross-domain Script Includes |
| Cross-cutting | 5 | Update-set XML privilege-escalation patterns, fabricated property references, meta check coverage, platform build drift, **audit coverage gap (#27 — new in 1.0.1)** |

The log export ships as `tools/security-log-export.js` — see §Running scans → Running the log export below.

The full machine-readable inventory is in [`manifest.json`](./manifest.json).

## What this is not

This pack is **not** a replacement for ServiceNow Security Center or the platform's built-in scan checks. It runs alongside them. The differences:

- **Framework alignment.** nowisor checks map to NIS2, DORA, ISO 27001, and GDPR — the CISO-facing regulatory frameworks. Security Center's checks align primarily to OWASP ASVS, which targets the developer audience. The two complement each other; deploy both.
- **Detection model.** nowisor includes AST-based linting (Code analysis category) and finding-level metadata for downstream automation. Security Center provides broader platform telemetry.
- **Coordination layer.** nowisor findings are designed to be consumed by the nowisor advisor (paid tier) for AI-assisted triage. The findings remain in your instance regardless — you can read them directly in the `scan_finding` table or via the standard Instance Scan UI.

## Installation

Install the pack via the ServiceNow Fluent SDK. The procedure is single-path: clone the repo, install dependencies, build, install. Both the SDK and Node 20+ are required.

> The artifact at `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` is the build-output bundle (scope and per-record XMLs). It is **not** a standalone installer — it ships alongside the source for transparency and download-verification, not as a separate install path. A pure-UI install path that requires no local toolchain is on the v1.1 roadmap.

### Prerequisites

- Node.js 20 or higher
- `@servicenow/sdk` 4.6.0 or higher
- Admin credentials on the target ServiceNow instance (Zurich Patch 6 verified; other releases see [Compatibility](#compatibility))

### Step 1 — Clone the source

```bash
git clone https://github.com/nowisor-com/instance-scan-agent
cd instance-scan-agent
npm install
```

### Step 2 — Configure auth

```bash
npx now-sdk auth --add https://yourinstance.service-now.com --type basic --alias your-alias
```

The auth alias is stored in your local SDK config (credentials live in your OS keychain). One alias per target instance.

### Step 3 — Build and install

```bash
npx now-sdk build
npx now-sdk install --auth your-alias
```

The install uploads the built package to `sn_appclient_upload_processor.do` on the instance and creates the `x_nowisor_isp` scope. Watch the SDK output for any installation tracker errors.

### Step 4 — Run the suite bootstrap (required post-install step)

The Fluent SDK 4.6.0 does not expose a `ScanCheckSuite` API. The suite that aggregates the 26 checks must be provisioned via Background Script after the install.

1. Navigate to **System Definition → Scripts - Background**
2. Open [`bootstrap/install-suite.js`](./bootstrap/install-suite.js)
3. Paste the entire script into the Background Script editor
4. Click **Run script**
5. Read the output — it should confirm "Suite … is ready" and list the number of checks linked

The script is **idempotent**. Safe to re-run. If you upgrade the pack later (`now-sdk install --reinstall`), the m2m rows are cascade-deleted — re-run the bootstrap to re-link them. `scan_finding` records persist across reinstalls.

### Step 5 — Verify

Navigate to **System Definition → Scan → Scan Checks**. You should see 27 nowisor checks under the `x_nowisor_isp` scope — 25 active and 2 deferred (`nowisor-hardcoded-credentials` and `nowisor-direct-property-write`, deferred to v1.1 per `V1_RETROSPECTIVE_TIER2.md`).

## Running scans

### Ad-hoc via REST

```bash
curl -u admin:$SN_PASS -H 'Accept: application/json' \
  -X POST 'https://yourinstance.service-now.com/api/sn_cicd/instance_scan/full_scan'
```

Returns a progress URL. Poll until status is `Successful`. Findings appear in the `scan_finding` table filtered by `check.sys_scope.scope=x_nowisor_isp`.

### Ad-hoc via UI

Navigate to **Instance Scan → Suite Scans**, open the **nowisor Instance Scan Pack** suite, click **Execute Suite Scan**.

### Scheduled

Navigate to **Instance Scan → Scheduled Scans**, create a new scheduled scan, set the suite to **nowisor Instance Scan Pack**, set the cadence (weekly is a reasonable default for production instances).

### Running the log export

`tools/security-log-export.js` is a Background Script (NOT part of the suite — it does not emit `scan_finding` records). Run it separately:

1. Navigate to **System Definition → Scripts - Background**
2. Open [`tools/security-log-export.js`](./tools/security-log-export.js)
3. Paste the entire script into the editor
4. Click **Run script**
5. The script prints a JSON envelope under the `---NOWISOR_LOGEXPORT---` separator. Copy the full output for ingestion by the nowisor advisor.

The script is **read-only and safe for production** — it queries audit / event / transaction tables only and does not write anywhere. The lookback window (`LOOKBACK_DAYS = 7`) and per-category row cap (`ROW_CAP = 300`) are configurable at the top of the script. Connect the log export to the advisor by pasting both the scan output and the log export into the **Active Risk Report** on nowisor.com.

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
gr.addQuery('check.sys_scope.scope', 'x_nowisor_isp');
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

### LinterCheck-required evidence keys (A1-DEP, added in 1.0.1)

LinterCheck findings (check IDs `nowisor-eval-usage-detector`, `nowisor-set-workflow-false-detector`, `nowisor-glide-evaluator-detector`, `nowisor-glide-record-vs-secure`, `nowisor-set-roles-detector`, `nowisor-hardcoded-credentials`, `nowisor-direct-property-write`, `nowisor-domain-separation-script-include`) emit two additional keys inside `evidence`:

```
artifact_scope            string — sys_scope of the flagged record (e.g., 'global', 'sn_*', 'x_*')
artifact_table            string — table the flagged record lives on (e.g., 'sys_script_include')
```

These are mandatory for downstream correlation: without them, a correlation engine cannot distinguish OOB/system-scope findings (deferrable) from customer-modifiable findings (live risk). The fields may be empty strings on instances where the framework does not pre-populate `scan_finding.table` and `scan_finding.record` at script-execution time — consumers should treat empty values as "scope unknown" and route those findings to `INVESTIGATE` rather than `NOISE`. Property-based and ACL/role checks do NOT carry these keys (their `evidence` is property- or ACL-shaped).

### Log-export schema v1

The companion log-export envelope (emitted by `tools/security-log-export.js`) follows the same `---NOWISOR_<KIND>---` separator pattern as findings. Single envelope per script execution:

```jsonc
{
  "nowisor_logexport_schema": "v1",
  "pack_version": "1.0.0",
  "generated_at": "<ISO UTC>",

  "window": {
    "lookback_days": 7,
    "start": "<ISO>", "end": "<ISO>",
    "per_category_cap": 300
  },

  "coverage": {
    "sources_expected":  ["sys_audit", "sysevent", "syslog_transaction"],
    "sources_available": [],
    "sources_missing":   [],
    "coverage_note":     "<human-readable; correlation engines render this verbatim>"
  },

  "build_drift": {
    "buildtag_last": "<gs.getProperty('glide.buildtag.last')>",  // may be null on instances where the property is unset
    "lastplugin":    "<gs.getProperty('glide.lastplugin')>",
    "recent_property_changes_30d": 0
  },

  "sources": {
    "sys_audit":          { "schema_note": "...", "row_count": N, "cap_hit": false, "filter": "...", "rows": [...] },
    "sysevent":           { "discovery": { "method": "...", "tables_present": [...] }, "row_count": N, "rows": [...] },
    "syslog_transaction": { "schema_note": "...", "aggregation": "group_by_user_top_25", "row_count": N, "rows": [...] }
  }
}
```

**L2-reserved keys** (NOT emitted in v1; parsers must ignore unknown keys for forward-compat). When v1.1 lands after PDI verification, these will appear inside rows[]:
- `source_ip` — verified on `syslog_transaction.remote_ip`; pending corpus update
- `user_agent` — verified on `syslog_transaction.user_agent`; pending corpus update
- `owning_job` — derived from sys_audit join when property toggles trace to a scheduled job
- `anonymous_principal_volume` — aggregate signal for guest/anonymous transactions

**L1.1-reserved key** (NOT emitted in v1; needed for runtime-non-execution claims on linter findings):
- `script_exec_history` — per-script execution counts. Without it, linter-finding deferral rationale rests on artifact_scope (static), never on runtime non-execution.

Same backwards-compat policy as the finding schema (current + previous, 12 months). Parsers must split on the exact `---NOWISOR_LOGEXPORT---` string and `JSON.parse` the tail.

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

### "Install fails — `sn_appclient_upload_processor.do` returns 'application was null'"

The package uploads but the instance's app-client handler deserializes it to a null application:

```
java.lang.IllegalStateException at
com.sn_appclient_bootstrap.ScopedAppUploadProcessor.uploadAndInstallApp(ScopedAppUploadProcessor.java:251)
```

This is an **instance-side install policy, not a defect in the build** — the same v1.0.0 package installs on Zurich Patch 6 (`dev265484`) and failed on Australia Patch 2. **Verified root cause and fix** (reproduced + resolved on Australia Patch 2 `dev194572`, 2026-05-31):

The instance rejects the app as **third party**. The real signal is the `syslog` line *immediately before* the null-application error:

```
ServletErrorListener: Not allowing install of third party application: no thrown error
ServletErrorListener: Unable to install application as application was null ... ScopedAppUploadProcessor:251
```

The upload processor trusts only company keys listed in the **`sn_appauthor.all_company_keys`** property. On a fresh PDI that contains only the instance's own key (e.g. `2064919`). The pack's vendor key — the company segment of its scope `x_nowisor_isp`, i.e. **`nowisor`** — isn't trusted, so the app deserializes to null.

**Fix:** add the pack's vendor key to the trust list via a Background Script (REST writes to `sys_properties` are ACL-blocked on most PDIs — this must run server-side):

```javascript
// System Definition → Scripts - Background
var cur = gs.getProperty('sn_appauthor.all_company_keys', '');
if (cur.split(',').indexOf('nowisor') === -1) {
    gs.setProperty('sn_appauthor.all_company_keys', (cur ? cur + ',' : '') + 'nowisor');
}
gs.print('all_company_keys = ' + gs.getProperty('sn_appauthor.all_company_keys'));
```

Re-run `npx now-sdk install --auth <alias>` — it now completes and creates the `x_nowisor_isp` scope with all 27 checks. Revert anytime by removing `nowisor` from the property. **Do not rename the scope** to dodge this — `x_nowisor_isp` is hardcoded in `bootstrap/install-suite.js` and every `check.sys_scope.scope=x_nowisor_isp` query.

If the `syslog` shows a *different* line instead of the third-party block, two other prerequisites can produce the same null-application surface error: (a) **ServiceNow IDE < 4.1.1 or `sn_appclient` < 29.0.4** — entitle/upgrade from the Store, sync Application Manager; (b) a **`glide.appcreator.company.code`** scope-prefix mismatch. Always read the line above the `ScopedAppUploadProcessor` error first. Note: `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` is a now-sdk package, **not** a plain Update-Set XML — it routes through the same processor and fails identically; there is no SDK-free import path today.

## Compatibility

| Release | Verified | Status |
|---|---|---|
| Zurich Patch 6 | dev265484 | Fully verified — property baseline complete; 24/24 verification Background Scripts pass on a live instance |
| Australia Patch 2 | dev194572 | **Verified end-to-end** — v1.0.0 installs cleanly (scope + 27 checks, 25 active / 2 deferred) after trusting the pack's vendor key in `sn_appauthor.all_company_keys`; see [Troubleshooting → "application was null"](#troubleshooting). Suite bootstrap + a live suite scan validated: 144 findings emitted under `x_nowisor_isp` with the intact `---NOWISOR_METADATA---` v1 schema (advisor-integration contract holds). The third-party rejection is a per-instance policy, not a build issue. Verified 2026-05-31. |
| Older releases (Yokohama, Xanadu, Washington DC) | not verified | Likely works but unverified; file an issue if you test |

### Pending PDI verification (gates v1.1)

| Identifier | Source | Status | Blocks |
|---|---|---|---|
| `syslog_transaction.remote_ip` | log-export L2 column | Present on Zurich manifest, missing from per-table verified corpus | TEST verdict in correlation engine |
| `syslog_transaction.user_agent` | log-export L2 column | Present on Zurich manifest, missing from per-table verified corpus | TEST verdict in correlation engine |
| `sys_audit.{tablename,documentkey,fieldname,oldvalue,newvalue,sys_created_by,sys_created_on}` | log-export L1 column set | Empty `fields: []` stub in `verified_schema/releases/zurich/tables/sys_audit.json` | Full-confidence sys_audit join in correlation engine |
| `glide.buildtag.last` | build_drift block | Unverified | When unverified, the tool emits `null` for this field — drift signal degraded but non-fatal |
| `sysevent` (canonical event log table) | log-export L1 source | Not present in verified schema (`sysevent_register` + `sysevent_email_action` only) | EXERCISED verdict for auth-failure findings |

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
