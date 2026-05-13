# nowisor Instance Scan Agent

Open-source ServiceNow security check pack that runs inside your instance and produces structured findings consumed by the [nowisor](https://nowisor.com) AI security advisor.

- **Pack version:** 1.0.0
- **Finding schema:** v1 (stable; backwards-compat policy in §Schema and versioning)
- **License:** Apache-2.0
- **Verified against:** ServiceNow Zurich Patch 6 (dev265484). Australia Patch 2 install fails — see [Compatibility](#compatibility); v1.1 reactivation work.
- **SDK requirement:** `@servicenow/sdk` ≥ 4.6.0 (only required if you build from source; the pre-built update set has no runtime SDK dependency)

## Quickstart

If you have a Zurich Patch 6 PDI with Node 20+ and ~15 minutes:

```bash
git clone https://github.com/nowisor/instance-scan-pack
cd instance-scan-pack
npm install
npx @servicenow/sdk auth --add https://your-instance.service-now.com --type basic --alias your-alias
npx @servicenow/sdk build
npx @servicenow/sdk install --auth your-alias
```

Then in your instance:

1. **System Definition → Scripts - Background** — paste [`bootstrap/install-suite.js`](./bootstrap/install-suite.js), click Run.
2. **Instance Scan → Suite Scans** — open "nowisor Instance Scan Pack", click Execute Suite Scan.
3. **scan_finding.list** filtered by `check.sys_scope.scope = x_nowisor_isp` — your findings.

> ⚠ **Password caveat (F-005):** if your PDI's auto-generated admin password contains `/` or `%`, `npx @servicenow/sdk auth --add` will fail with "username or password invalid" even though the credentials are correct. Reset the password via the developer portal to one within `[A-Za-z0-9!=._-]` before configuring the alias. See [`docs/qa/pdi-install-verification.md`](docs/qa/pdi-install-verification.md) for the full diagnosis.

Detailed installation with explanations is in [Installation](#installation) below.

## What it finds

26 checks across four categories. Examples ordered by differentiation — LinterChecks and drift detection have no direct Security Center equivalent; property checks complement ISC's OWASP-aligned audits with NIS2 / DORA / ISO mapping:

| Example finding | Type | Property / pattern | Frameworks | Severity |
|---|---|---|---|---|
| `eval()` in custom code | LinterCheck (AST) | AST-detected `eval()` call in Script Includes, Business Rules, etc. | NIS2 21.2.d · ISO 27001 A.8.28 | HIGH |
| OOB ACL modified in last 24h | Drift detection | Recently-modified out-of-the-box ACL (pre-attack signal) | NIS2 21.2.a · ISO 27001 A.8.3 | MEDIUM |
| CSRF token enforcement disabled | Property | `glide.security.use_csrf_token = false` | NIS2 21.2.a · ISO 27001 A.5.15 · DORA 9 | CRITICAL |
| Attachment role unrestricted | Property | `glide.attachment.role = public` (Zurich OOB default) | NIS2 21.2.h · ISO 27001 A.5.34 | HIGH |
| Session idle timeout exceeds baseline | Property | `glide.ui.session_timeout > 30` (Zurich OOB default is 90) | NIS2 21.2.j · ISO 27001 A.8.5 · DORA 9 | HIGH |

The full check inventory is in [`manifest.json`](./manifest.json). Every check has a customer-facing documentation page at `nowisor.com/kb/checks/<check-id>` covering the attack-path narrative, regulatory mapping, remediation steps, and a verification Background Script.

## What runs where, what's sent where

- **The pack runs inside your ServiceNow instance.** It installs as a scoped application (`x_nowisor_isp`) and writes findings to your `scan_finding` table.
- **No outbound traffic.** The pack does not phone home, does not send findings anywhere, and does not require outbound network access from your instance to function. Findings live in your instance and are visible to users with read access to `scan_finding`.
- **Optional advisor integration is opt-in.** If you choose to connect your instance to the [nowisor advisor](https://nowisor.com) (the paid SaaS at the higher tiers of that product), the advisor reads your `scan_finding` records via an authenticated OAuth grant you authorize. That data flow is opt-in, scoped to the OAuth grant, documented in the advisor's terms of service. The agent itself remains independent of it.
- **The agent is standalone-useful.** You can install this pack, run scans, and read findings without ever connecting to nowisor.com. The advisor is the value-add; the detection is the floor.

See [`SECURITY.md`](./SECURITY.md) for the responsible-disclosure policy and the full scope of what this project commits to.

## Sample finding output

Every finding has a human-readable summary followed by a structured `---NOWISOR_METADATA---` JSON block. Here's what a typical CSRF finding looks like in the `scan_finding` table:

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

The metadata block is the open schema any consumer can parse — the nowisor advisor at nowisor.com is one consumer, but you can build your own (export to SIEM, automate ticket creation, feed into a custom dashboard). See [Reading findings](#reading-findings) for the GlideRecord-based parsing pattern.

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

Navigate to **System Definition → Scan → Scan Checks**. You should see 26 nowisor checks under the `x_nowisor_isp` scope — 24 active and 2 deferred (`nowisor-hardcoded-credentials` and `nowisor-direct-property-write`, deferred to v1.1 per [`docs/retrospectives/V1_RETROSPECTIVE_TIER2.md`](docs/retrospectives/V1_RETROSPECTIVE_TIER2.md)).

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

## Reading findings

Findings appear as records in the `scan_finding` table. Each finding has two layers:

1. **Human-readable description** at the top of `finding_details`
2. **Structured metadata** below a `---NOWISOR_METADATA---` separator

A complete sample finding is shown in [Sample finding output](#sample-finding-output) above. The metadata block is stable schema v1; the parsing pattern below extracts it programmatically.

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
| Zurich Patch 6 | dev265484 | Fully verified — property baseline complete; 24/24 verification Background Scripts pass on a live instance |
| Australia Patch 2 | dev377226 | **Install fails** — `sn_appclient_upload_processor.do` returns `application was null` on the v1.0.0 build. Root cause not yet investigated. Tracked as v1.1 reactivation work. |
| Older releases (Yokohama, Xanadu, Washington DC) | not verified | Likely works but unverified; file an issue if you test |

The 17 `CrossScopePrivilege` records ship with the pack so it functions correctly even in instances with strict scope isolation. The pack does not require admin elevation; the executing user needs read on `scan_finding`, `scan_check_*`, and the in-scope tables the audit checks touch (audit of sys_user, sys_security_acl, sys_script_include, etc.).

## Contributing

- **Issues / proposed checks:** [github.com/nowisor-com/instance-scan-agent/issues](https://github.com/nowisor-com/instance-scan-agent/issues) (replace with your fork URL if not from upstream)
- **Property-name verification rule:** every `glide.*` property referenced must exist on a verified PDI. The pack ships with a verified baseline at `nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json` (3,585 properties). Pull requests that reference unverified property names will not be merged.
- **AST predicate verification:** every LinterCheck predicate must be verified against a planted test artifact before the check is enabled. Pilot procedure documented in [`docs/retrospectives/V0_2_RETROSPECTIVE.md`](docs/retrospectives/V0_2_RETROSPECTIVE.md).

## License

Apache-2.0. See `LICENSE` for the full text.

## Project context

This pack is the open-source sensor surface of nowisor — the paid advisor at nowisor.com is a separate product. The agent itself is fully open-source under Apache-2.0 and produces findings that anyone can consume. The Datadog Agent/SaaS pattern, not the GitLab CE/EE pattern: the agent is permissive, the advisor is the commercial offering.

Strategic context (architecture decisions, framework alignment rationale, advisor product scope) is documented in `/nowisor/SCOPING_v1.md` in the parent repository.
