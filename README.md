# nowisor Instance Scan Agent

> **This pack now lives at [github.com/nowisor/instance-scan-pack](https://github.com/nowisor/instance-scan-pack) as a public Apache-2.0 open-source repository.**
>
> The contents in this monorepo subdirectory are retained for build-time artifacts and historical reference. For installation, contribution, issue reporting, or release notes, please use the public repository.

Open-source ServiceNow security check pack that runs inside your instance and produces structured findings consumed by the [nowisor](https://nowisor.com) AI security advisor.

- **Pack version:** 1.3.13
- **Finding schema:** v1 (stable; backwards-compat policy in §Schema and versioning)
- **Log-export schema:** v1 (stable; companion schema for the twin-sensor log export)
- **License:** Apache-2.0
- **Verified against:** ServiceNow Zurich Patch 6 (dev265484) and Australia Patch 2 (dev194572). On Australia the instance rejects the app as third-party until the pack's vendor key is trusted — one Background Script; see [Compatibility](#compatibility) / [Troubleshooting](#troubleshooting).
- **SDK requirement:** `@servicenow/sdk` ≥ 4.6.0 to build and install from source (pinned 4.14.0 since 1.3.13; 4.4.0+ supports the Australia release). The installed app has no *runtime* SDK dependency, but every install path — including the pre-built package under `dist/` — uploads through the instance's app-client processor, which has its own server-side prerequisites (see [Troubleshooting → "Install fails — application was null"](#troubleshooting)).

## What this is

The nowisor agent is the open-source **twin-sensor** surface of the nowisor product. It runs as a scoped application (`x_nowisor_isp`) inside your ServiceNow instance and emits two complementary streams, both consumed by the nowisor advisor's correlation engine:

1. **Sensor surface #1 — config findings.** 49 scan checks emit `scan_finding` records carrying a human-readable description plus a structured `---NOWISOR_METADATA---` JSON block. These capture static security posture (properties, ACLs, code patterns).
2. **Sensor surface #2 — log export.** A single Background Script (`tools/security-log-export.js`) emits a `---NOWISOR_LOGEXPORT---` envelope carrying runtime activity over a configurable lookback window (default 7 days): sys_audit on security-critical tables, sysevent discovery, syslog_transaction aggregated by user.

The advisor binds the two streams: findings tell you what's misconfigured; the log export tells you which misconfigurations were actually exercised. This is the active-risk distinction. **No correlation logic ships in this pack** — that work lives in the closed-source advisor at nowisor.com. The pack is a pure sensor; consumers are free to ingest the schemas and run their own correlation.

The 49 config checks span six categories:

| Category | Count | What it audits |
|---|---|---|
| Platform property hardening | 8 | Security-relevant `glide.*` properties: CSRF, cookies, session timeout, MFA, REST anonymous access, external auth policy |
| ACL and role configuration | 6 | Admin role concentration, inactive users retaining roles, attachment role restrictions, OOB ACL modifications, cross-scope privilege grants, elevated role co-assignments |
| Code analysis (AST-based) | 8 | `eval()`, `setWorkflow(false)`, `GlideEvaluator`, `GlideRecord` vs `GlideRecordSecure`, `setRoles()`, hardcoded credentials, direct `sys_properties` writes, cross-domain Script Includes |
| Cross-cutting | 5 | Update-set XML privilege-escalation patterns, fabricated property references, meta check coverage, platform build drift, **audit coverage gap (#27 — new in 1.0.1)** |
| AI and agent security | 17 | **New in 1.2.0.** Agentic inventory (AI-BOM), ownership, shadow-AI endpoints, inbound MCP / Action Fabric agents, governance coverage, and static guardrail posture. See the [category overview](./docs/ai-agent-security.md) |
| Basic Auth API restriction | 5 | **New in 1.1.0.** Readiness for the ServiceNow Basic Auth API restriction rollout (KB3025707/KB3055080): tracking active, enforcement posture + days-remaining countdown, untriaged hybrid accounts (`sys_user_basic_auth_exception`), allow-list role granted without WSAO (MFA bypass), and dormant Basic Auth API accounts |

Five Background-Script sensors ship in `tools/`: `security-log-export.js` (runtime activity),
three added in 1.2.0 for the AI module — `ai-discovery-export.js` (agentic surface
enumeration), `ai-bom-export.js` (agentic inventory), and `ai-usage-export.js` (permission
envelope + invocation evidence) — and `bundle.js`, added in 1.3.0 for offline mode (the reads a
connected scan makes, printed as one file to upload). All five are pure sensors: no correlation
logic, no verdicts, and they run as Background Scripts without installation. The 49 configuration
checks run as the scoped application `x_nowisor_isp`. See §Running scans → Running the log export
and §Offline mode (upload) below.

The full machine-readable inventory is in [`manifest.json`](./manifest.json).

## What this is not

This pack is **not** a replacement for ServiceNow Security Center or the platform's built-in scan checks. It runs alongside them. The differences:

- **Framework alignment.** nowisor checks map to NIS2, DORA, ISO 27001, and GDPR — the CISO-facing regulatory frameworks. The `ai-agent-security` group additionally carries OWASP LLM Top 10, MITRE ATLAS, and (conservatively) EU AI Act mappings. Security Center's checks align primarily to OWASP ASVS, which targets the developer audience. The two complement each other; deploy both.
- **Detection model.** nowisor includes AST-based linting (Code analysis category) and finding-level metadata for downstream automation. Security Center provides broader platform telemetry.
- **Coordination layer.** nowisor findings are designed to be consumed by the nowisor advisor for AI-assisted triage (which plans include what: [nowisor.com/#pricing](https://nowisor.com/#pricing)). The findings remain in your instance regardless — you can read them directly in the `scan_finding` table or via the standard Instance Scan UI.

## Installation

Install the pack via the ServiceNow Fluent SDK. The procedure is single-path: clone the repo, install dependencies, build, install. Both the SDK and Node 20+ are required.

> The artifact at `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` is the build-output bundle (scope and per-record XMLs). It is **not** a standalone installer — it ships alongside the source for transparency and download-verification, not as a separate install path. A pure-UI install path that requires no local toolchain is on the v1.1 roadmap.

### Prerequisites

- Node.js 20 or higher
- `@servicenow/sdk` 4.6.0 or higher
- Admin credentials on the target ServiceNow instance (Zurich Patch 6 verified; other releases see [Compatibility](#compatibility))
- For passwordless **OAuth** auth (Step 2), the instance needs ServiceNow IDE 1.1+ (default on Zurich). On older releases, use basic auth or import the ServiceNow IDE XML.

### Step 1 — Clone the source

```bash
git clone https://github.com/nowisor-com/instance-scan-agent
cd instance-scan-agent
npm install
```

### Step 2 — Configure auth

Authenticate with **OAuth** (recommended). A browser opens, you log in to your existing instance
session, click **Accept**, and paste the one-time authorization code — **no password is typed into the
terminal**, and no long-lived password is stored:

```bash
npx now-sdk auth --add https://yourinstance.service-now.com --type oauth --alias your-alias
```

OAuth needs ServiceNow IDE 1.1+ on the instance (default on Zurich — see [Prerequisites](#prerequisites)).
The alias is stored in your OS keychain and reused by `build`/`install`. One alias per target instance;
`now-sdk auth --list` shows aliases (never passwords or codes).

<details><summary>Basic auth (fallback) and non-interactive CI/CD</summary>

Basic auth prompts for the admin username and password:

```bash
npx now-sdk auth --add https://yourinstance.service-now.com --type basic --alias your-alias
```

For **non-interactive CI/CD**, skip `auth` and let `install` read these environment variables (store the
password as a CI secret — it is never typed at a prompt):

```bash
export SN_SDK_INSTANCE_URL=https://yourinstance.service-now.com
export SN_SDK_USER=svc.nowisor_deploy
export SN_SDK_USER_PWD=********            # CI secret
export SN_SDK_NODE_ENV=SN_SDK_CI_INSTALL
npx now-sdk build && npx now-sdk install
```

</details>

### Step 3 — Build and install

```bash
npx now-sdk build
npx now-sdk install --auth your-alias
```

The install uploads the built package to `sn_appclient_upload_processor.do` on the instance and creates the `x_nowisor_isp` scope. Watch the SDK output for any installation tracker errors.

### Step 4 — Run the suite bootstrap (required post-install step)

The Fluent SDK 4.6.0 does not expose a `ScanCheckSuite` API. The suite that aggregates the pack's checks (every entry in `manifest.json`) must be provisioned via Background Script after the install.

1. Navigate to **System Definition → Scripts - Background**
2. Open [`bootstrap/install-suite.js`](./bootstrap/install-suite.js)
3. Paste the entire script into the Background Script editor
4. Click **Run script**
5. Read the output — it should confirm "Suite … is ready" and list the number of checks linked

The script is **idempotent**. Safe to re-run. If you upgrade the pack later (`now-sdk install --reinstall`), the m2m rows are cascade-deleted — re-run the bootstrap to re-link them. `scan_finding` records persist across reinstalls.

> **Passwordless note:** with OAuth (Step 2), auth + `build`/`install` and triggering scans (below) need no terminal password. This bootstrap is the one remaining step that needs a logged-in admin **browser session** to run the Background Script — Fluent SDK 4.6.0 exposes no `ScanCheckSuite` API (suite-on-install is on the v1.1 roadmap).

### Step 5 — Verify

Navigate to **System Definition → Scan → Scan Checks**. You should see one nowisor check per `manifest.json` entry (49 checks in 1.3.13) under the `x_nowisor_isp` scope — all active except the 2 the manifest marks `active: false` (`nowisor-hardcoded-credentials` and `nowisor-direct-property-write`, deferred to v1.1 per `V1_RETROSPECTIVE_TIER2.md`).

## Running scans

### Ad-hoc via REST

With an **OAuth bearer token** (no password) — recommended; use a token for a dedicated scan user or OAuth client:

```bash
curl -H "Authorization: Bearer $SN_TOKEN" -H 'Accept: application/json' \
  -X POST 'https://yourinstance.service-now.com/api/sn_cicd/instance_scan/full_scan'
```

Or with basic auth:

```bash
curl -u admin:$SN_PASS -H 'Accept: application/json' \
  -X POST 'https://yourinstance.service-now.com/api/sn_cicd/instance_scan/full_scan'
```

Returns a progress URL. Poll until status is `Successful`. Findings appear in the `scan_finding` table filtered by `check.sys_scope.scope=x_nowisor_isp`. The **UI**, **Scheduled Scans**, and the **nowisor advisor** paths below need no password at all.

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

## Offline mode (upload)

Offline mode — run the scan yourself, upload the results

Use this if your instance is self-hosted, on-prem, or you prefer not to grant API access.
Nothing connects to your instance from outside. No credentials leave your organisation.

1. Get the script — [`tools/bundle.js`](./tools/bundle.js) (in the app, **Instances → Upload results**
   has Copy script and Download bundle.js, with the file's sha256 to compare against this one).
2. In your instance: System Definition → Scripts - Background. Paste. Run script. (Sub-production
   first, then production. Admin role required. Takes 2–3 min; output appears only at the end. The
   script starts no read after 240 s: a read it did not reach is recorded as not read, and the checks
   that rest on it are reported UNKNOWN — never passed. The output says whether the cap was reached
   and where the time went, section by section.)
   The script's largest reads — every empty ACL and its role rows — are off as shipped; to include
   them, change `var READ_EMPTY_ACLS = false` to `true` at the top before you run. The output line
   `empty ACL reads ON` or `OFF` says which ran.
3. Copy everything between ---NOWISOR_BUNDLE--- and ---NOWISOR_BUNDLE_END--- into a file named
   nowisor-scan-bundle.json (pasting the whole output page also works).
4. Review the file —
   <details>
   <summary>what it contains</summary>
   It contains configuration property values (password-type and secret-shaped values redacted
   in-instance before the file is written), ACL script and condition text, the list of users holding
   admin and security_admin roles (username, full name, last login), scheduled-job run-as accounts,
   OAuth application names, knowledge base titles and MID Server hostnames, script include and
   credential record names (no bodies, no secrets), plugin and application inventory, and table and
   field metadata. It does not contain platform passwords, tickets, CMDB records or end-user records.
   Script text is copied as-is: anything a developer wrote into an ACL script — including a hardcoded
   secret — will be in the file, so review it. Bundle processing is covered by the Nowisor DPA; the
   bundle is processed and stored in the EU and deleted 30 days after upload.
   </details>
5. Upload it below. Pick the instance or create it from the bundle's URL.

What differs from a connected instance

- No check requires a live call to your instance. If one is ever added, it will show as
  'Not assessable from upload' — never guessed.
- Posture is a point-in-time capture. Re-run and re-upload on your own cadence; quarterly is
  what Self-Hosted Assurance assumes.
- Uploads older than 30 days show findings as conditional and withhold CVE answers until you
  re-upload; older than 90 days are refused.
- Bundle files are processed and stored in the EU and deleted 30 days after upload.

The SHA-256 the script prints appears in every report as the integrity reference: it proves the
file was not changed after the script wrote it; the printed run-by account and instance ID are the
attribution. `bundle.js` needs no installation — the 49 configuration checks of the scan pack's
scoped application `x_nowisor_isp` are not required for upload.

The file is printed one section per line (bundle schema 2, pack 1.3.12): a `header` line, a
`timings` line, one `read` line per read (a long read continues on `rows` lines), and an `end` line —
so no line, and no single string inside the instance, has to hold the whole bundle. Each line is
`<section> <json>`; the JSON escapes spaces, `<`, `>`, `&` and non-ASCII characters as `\uXXXX` so
that a browser copy cannot alter it. Within a read, rows are printed column by column, a reference
is printed as its value (the advisor rebuilds the Table API link), and a record's package is printed
once per read. The SHA-256 is taken over each line's canonical JSON (keys sorted, no whitespace),
chained in order; the advisor recomputes it and refuses a file that was changed, and refuses a
malformed line by its line number and section. `bundle.js` is read-only: plain `GlideRecord`
queries for the check reads added in 1.3.9 and 1.3.10, `GlideRecordSecure` queries for every other read, and
`GlideAggregate` counts; nothing written.

<!-- BEGIN bundle-read-plan: generated from the advisor's read inventory; do not edit by hand -->

### What the script reads

Every read `tools/bundle.js` records — 79 distinct reads — listed from the advisor's own read inventory, the same list a connected scan is held to. A value known only at run time (an ACL's sys_id, a knowledge base's sys_id, a date) is shown as a placeholder. The check reads added in pack 1.3.9 (on `sys_ws_operation`, `sys_upgrade_history` and the typed `sys_dictionary` read, with their counts) and in pack 1.3.10 (the ACL, script-include, job, table-origin and knowledge-base check reads, with their counts) run as plain GlideRecord queries; every other read runs as a GlideRecordSecure query; a read that asks for a row count is counted with GlideAggregate; nothing is written. This section is generated from the inventory and the script; it is not typed.

| Part | Table | Query | Fields | Rows per request | When |
|---|---|---|---|---|---|
| posture | `sys_properties` | `name=glide.script.use.sandbox^ORname=glide.security.use_csrf_token^ORname=glide.basicauth.required.scriptedprocessor^ORname=glide.ui.session_timeout^ORname=glide.security.strict_elevate_privilege^ORname=glide.ui.secure_cookies^ORname=glide.security.file.mime_type.validation^ORname=glide.attachment.role` | `name,value` | 50 | every run |
| posture | `sys_security_acl` | `active=true^conditionISEMPTY^scriptISEMPTY` | `sys_id,name,type,operation,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 500 | every run |
| posture | `sys_script_include` | `client_callable=true^active=true` | `name,api_name,access` | 200 | every run |
| posture | `sys_script` | `active=true` | `sys_id` | 1 | every run |
| posture | `discovery_credentials` | — | `name,type,target_type` | 100 | every run |
| posture | `sn_vsc_instance_hardening_settings` | — | `harc_name,risk_score,score_impact,compliance_status` | 500 | every run |
| posture | `sys_security_acl` | `active=true^scriptISNOTEMPTY^scriptCONTAINSreturn true` | `name,operation,script` | 200 | every run |
| posture | `sys_user_has_role` | `role.name=admin^state=active^user.active=true` | `user.user_name,user.last_login_time,user.name` | 500 | every run |
| posture | `sys_user_has_role` | `role.name=security_admin^state=active^user.active=true` | `sys_id` | 1 | every run |
| posture | `ecc_agent` | `status=Up` | `name,status,version,host_name,validated` | 50 | every run |
| posture | `sys_db_object` | `super_class.name=sys_import_set_row` | `name,label` | 200 | every run |
| posture | `sys_ws_definition` | `active=true` | `name,api_id,enforced,version,active,sys_scope.name` | 1000 | every run |
| posture | `sys_ws_operation` | `active=true^requires_acl_authorization=false^ORDERBYsys_id` | `sys_id,name,http_method,operation_uri,relative_path,requires_acl_authorization,requires_authentication,enforce_acl,sys_policy,sys_created_on,sys_package,sys_package.name,sys_package.sys_class_name,web_service_definition,web_service_definition.name,web_service_definition.namespace,web_service_definition.active` | 1000, paged | every run |
| posture | `sys_ws_operation` | — | `sys_id` | 1 | every run |
| posture | `sys_ws_operation` | `active=true^requires_acl_authorization=false^sys_package.ref_sys_scope.private=true^ORDERBYsys_id` | `sys_id` | 1000, paged | every run |
| posture | `sys_ws_operation` | `active=true^requires_acl_authorization=false^sys_package.ref_sys_scope.private=false` | `sys_id` | 1 | every run |
| posture | `sys_upgrade_history` | `upgrade_startedISNOTEMPTY^ORDERBYsys_id` | `upgrade_started,upgrade_finished` | 1000, paged | every run |
| posture | `sys_upgrade_history` | — | `sys_id` | 1 | every run |
| posture | `sys_plugins` | `active=active` | `name,source` | 500 | every run |
| posture | `sys_properties` | `name=glide.ui.session_timeout^ORname=glide.authenticate.multifactor^ORname=glide.authenticate.external^ORname=glide.authenticate.multisso.enabled` | `name,value` | 10 | every run |
| posture | `sys_properties` | `name=glide.basicauth.required.api^ORname=glide.basicauth.required.soap^ORname=glide.basicauth.required.scriptedprocessor^ORname=glide.basicauth.required.jsonv2^ORname=glide.basicauth.required.csv^ORname=glide.basicauth.required.excel^ORname=glide.basicauth.required.importprocessor^ORname=glide.basicauth.required.pdf^ORname=glide.basicauth.required.rss^ORname=glide.basicauth.required.schema^ORname=glide.basicauth.required.unl^ORname=glide.basicauth.required.wsdl^ORname=glide.basicauth.required.xml^ORname=glide.basicauth.required.xsd^ORname=glide.basicauth.required.xmloutputprocessor^ORname=glide.basicauth.required.databrokerrestapiprocessor` | `name,value` | 50 | every run |
| posture | `sys_dictionary` | `elementLIKEpassword^ORelementLIKEsecret^ORelementLIKEtoken^ORelementLIKEkey^ORelementLIKEcredential^ORcolumn_labelLIKEpassword^ORcolumn_labelLIKEsecret^ORcolumn_labelLIKEtoken^internal_typeINstring,string_full_utf8,html,translated_text^ORDERBYsys_id` | `name,element,column_label,internal_type,sys_scope` | 1000, paged | every run |
| posture | `sys_plugins` | `sourceINcom.glide.encryption.core,com.snc.db_encryption,com.glide.column_encryption` | `sys_id,name,source,active` | 20 | every run |
| posture | `sys_user_has_role` | `role.name=admin^state=active^user.active=true` | `user.user_name,user.name` | 1000 | every run |
| posture | `sys_user_has_role` | `role.name=security_admin^state=active^user.active=true` | `user.user_name,user.name,user.last_login_time` | 1000 | every run |
| posture | `oauth_entity` | `active=true` | `sys_id,name,type,access_token_lifespan,refresh_token_lifespan` | 500 | every run |
| posture | `sys_rate_limit_rules` | `active=true` | `name,sys_id` | 25 | every run |
| posture | `sys_properties` | `nameLIKEpassword^ORnameLIKEcredential^ORnameLIKEsecret^ORnameLIKEapi_key` | `name` | 1 | every run |
| posture | `sys_security_acl_role` | `sys_security_aclIN<ACL sys_ids, chunks of 100>` | `sys_security_acl` | 5000 | the ACL reads returned rows (one read per 100 sys_ids) |
| posture | `sys_dictionary` | `internal_type=encrypted_text^ORinternal_type=password2` | `sys_id` | 1 | the sys_plugins encryption-plugin read succeeded |
| posture | `oauth_credential` | `type=access_token^sys_created_on>=<now − 90 days>` | `peer` | 10000 | every run |
| posture | `sys_security_acl` | `active=true^conditionISEMPTY^scriptISEMPTY^ORDERBYsys_id` | `sys_id,name,operation,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | only when `READ_EMPTY_ACLS` is set to `true` (ACL-001's paged reads; off as shipped) |
| posture | `sys_security_acl_role` | `sys_security_acl.active=true^sys_security_acl.conditionISEMPTY^sys_security_acl.scriptISEMPTY^ORDERBYsys_id` | `sys_security_acl` | 1000, paged | only when `READ_EMPTY_ACLS` is set to `true` (ACL-001's paged reads; off as shipped) |
| posture | `sys_security_acl` | `active=true^scriptISNOTEMPTY^ORDERBYsys_id` | `sys_id,name,operation,script` | 1000, paged | every run |
| posture | `sys_security_acl` | `active=true^nameLIKE*^ORoperation=*^ORDERBYsys_id` | `name,operation,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_security_acl` | `active=true^operation=read^nameINsys_user,sn_hr_core_profile^ORnameSTARTSWITHsys_user.^ORnameSTARTSWITHsn_hr_core_profile.^ORDERBYsys_id` | `sys_id,name,operation,condition,script` | 1000, paged | every run |
| posture | `sys_dictionary` | `nameINsys_user,sys_user_has_role,sys_user_grmember,discovery_credentials^element=NULL^ORDERBYsys_id` | `name,audit` | 1000, paged | every run |
| posture | `sysauto_script` | `run_asISNOTEMPTY^ORDERBYsys_id` | `name,run_as,run_as.user_name,active,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_security_acl` | — | `sys_id` | 1 | every run |
| posture | `sys_security_acl_role` | — | `sys_id` | 1 | only when `READ_EMPTY_ACLS` is set to `true` (ACL-001's paged reads; off as shipped) |
| posture | `sys_dictionary` | — | `sys_id` | 1 | every run |
| posture | `sysauto_script` | — | `sys_id` | 1 | every run |
| posture | `oauth_entity` | `active=true` | `name,type,default_grant_type,inbound_grant_type,access_token_lifespan,refresh_token_lifespan` | 100 | every run |
| posture | `kb_knowledge_base` | — | `sys_id` | 1 | every run |
| posture | `kb_uc_can_read_mtom` | — | `sys_id` | 1 | every run |
| posture | `user_criteria` | — | `sys_id` | 1 | every run |
| posture | `sys_user_role` | — | `sys_id` | 1 | every run |
| posture | `sp_page` | — | `sys_id` | 1 | every run |
| posture | `sys_script_include` | — | `sys_id` | 1 | every run |
| posture | `sys_db_object` | — | `sys_id` | 1 | every run |
| posture | `kb_knowledge_base` | `active=true^ORDERBYsys_id` | `sys_id,title,active` | 1000, paged | every run |
| posture | `kb_uc_can_read_mtom` | `kb_knowledge_baseISNOTEMPTY^ORDERBYsys_id` | `kb_knowledge_base,user_criteria` | 1000, paged | every run |
| posture | `user_criteria` | `roleISNOTEMPTY^ORDERBYsys_id` | `sys_id,role` | 1000, paged | every run |
| posture | `sys_user_role` | `name=public^ORDERBYsys_id` | `sys_id,name` | 1000, paged | every run |
| posture | `sp_page` | `idINkb_home,kb_article_view,kb_search^ORDERBYsys_id` | `id,public` | 1000, paged | every run |
| posture | `sys_properties` | `nameINglide.appcreator.company.code,glide.knowman.block_access_with_no_user_criteria` | `name,value` | 4 | every run |
| posture | `sys_db_object` | `nameIN<tables the typed secret-name rows name, chunks of 100>^ORDERBYsys_id` | `name,sys_scope,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000 | the typed secret-name read completed (one read per 100 table names) |
| posture | `sys_script_include` | `client_callable=true^active=true^scriptLIKEeval(^ORDERBYsys_id` | `sys_id,name,api_name,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_script_include` | `client_callable=true^active=true^scriptLIKEnew Function(^ORDERBYsys_id` | `sys_id,name,api_name,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_script_include` | `client_callable=true^active=true^scriptLIKEGlideEvaluator^ORDERBYsys_id` | `sys_id,name,api_name,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_script_include` | `client_callable=true^active=true^scriptLIKEGlideScopedEvaluator^ORDERBYsys_id` | `sys_id,name,api_name,sys_package,sys_package.name,sys_package.sys_class_name,sys_policy,sys_created_on` | 1000, paged | every run |
| posture | `sys_db_object` | `name=x_nowisor_vsme_health^ORDERBYsys_id` | `name,sys_package` | 1000, paged | every run |
| posture | `sys_user_has_role` | `role.name=admin^state=active^user.active=true` | `user.user_name,user.web_service_access_only` | 500 | every run |
| AI surface | `sys_db_object` | `nameINsn_aia_agent,sn_mcp_server,sys_mcp_server` | `name` | 10 | every run |
| AI surface | `sys_store_app` | `nameLIKENow Assist^ORnameLIKEGenerative AI^ORnameLIKEAI Agent^ORnameLIKEControl Tower^ORnameLIKEBuild Agent` | `name,active,version` | 50 | every run |
| AI surface | `sys_scope` | `nameLIKENow Assist^ORnameLIKEGenerative AI^ORnameLIKEAI Agent^ORnameLIKEControl Tower^ORnameLIKEBuild Agent` | `name,active` | 50 | every run |
| AI surface | `sys_plugins` | `nameLIKENow Assist^ORnameLIKEGenerative AI^ORnameLIKEAI Agent^ORnameLIKEControl Tower^ORnameLIKEBuild Agent` | `name,active` | 50 | every run |
| AI surface | `sys_properties` | `nameLIKEnowassist^ORnameLIKEgenerative_ai^ORnameLIKEsn_aia` | `name` | 1 | every run |
| release reading | `sys_properties` | `name=glide.buildtag.last^ORname=glide.buildtag^ORname=instance_id^ORname=instance_name` | `name,value` | 10 | every run |
| release reading | `/stats.do` (page) | — | — | — | never requested in an instance — recorded as unanswered when build tag or instance id missing after the sys_properties read |
| release reading | `sys_db_object` | `nameIN<SECURITY_CORE_TABLES + control YAML tables, chunks of 80>` | `name,label,super_class,sys_scope` | 500 | every run |
| release reading | `sys_dictionary` | `nameIN<tables found, chunks of 40>^element!=NULL` | `name,element,column_label,internal_type,max_length,mandatory,read_only,reference` | 10000 | every run |
| release reading | `sys_properties` | `type!=password^type!=password2` | `name,value,type` | 5000, paged | every run |
| release reading | `sys_store_app` (row count) | — | — | — | every run |
| release reading | `sys_store_app` | — | `name,version,active,scope,sys_id` | 2000, paged | every run |
| release reading | `sys_scope` (row count) | — | — | — | every run |
| release reading | `sys_plugins` | — | `sys_id,name,source,active,description,version` | 2000 | every run |
| release reading | `sys_scope` | — | `name,version,active,scope,sys_id,private,vendor` | 2000, paged | every run |
| access diagnosis | `sys_user` | — | `sys_id` | 1 | sys_properties and sys_security_acl both refused (403) |

<!-- END bundle-read-plan -->

### Sizing probe (`tools/probe.js`)

A read-only script that prints row counts only, for sizing the bundle before it is run. Paste it into
Scripts - Background and run it as an admin. For each table that carries most of the bundle's size it prints the table's row total, the total of each query `bundle.js` reads that table with, and how
many milliseconds each count took, plus the pack version and the instance's build string. Every number
is a `GlideAggregate` count. `v_plugin` is not counted (probe 1.1.0, pack 1.3.12): the bundle no longer reads it, and a cold read of that view makes the platform rebuild it — 166 s, and platform writes to `v_plugin` and `sys_cache_flush`, in the 1.3.11 probe's run on dev433526; `sys_plugins`, which the bundle reads instead, is counted. It
prints no row content, no names and no sys_ids, and writes nothing. A count that cannot be taken prints
`unread`, never 0, and so does a table total of 0 for a table every instance populates (a count that failed silently).

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

### Changelog

**1.3.13 (2026-10-24)** — dependency updates, no rule or engine changes. Build toolchain `@servicenow/sdk` 4.13.3 → 4.14.0, which carries patched `handlebars` (4.7.10), `fastify` (5.12.7), `@fastify/static` (10.1.3) and `joi` (17.13.8); the lockfile refresh also brings `source-map-js` 1.2.2. The `js-yaml@3` and `joi@17` pins are removed — the toolchain no longer carries a 3.x `js-yaml` and pins the patched `joi` itself. `undici@7` stays pinned, now to 7.30.1: the CLI pins 7.29.1, and three advisories published 2026-10-23, among them a denial of service, are fixed in 7.30.1, and `zod@4` is pinned to 4.6.6 (memory exhaustion validating oversized collections, fixed in 4.6.6; the toolchain pins 4.6.5). All dev-only: none of them is part of the installed app. `npm audit`: 0 vulnerabilities. Built with 4.14.0, the installed app differs from 1.3.12 in the version it carries and in two build records only: the SBOM names the 4.14.0 toolchain (and no longer carries a serial number or timestamp), and the packaged `package.json` carries the new toolchain and pins. No change to any check, script, manifest entry or bundle format. Check count unchanged (49).

**1.3.12 (2026-10-19)** — offline bundle (`tools/bundle.js` 2.0.0, **bundle schema 2**): a customer instance's bundle stopped in Rhino ("String object would exceed maximum permitted size of 33554432") — schema 1 built the whole document as one string. Schema 2 prints one section per line, so no string holds the bundle. It is smaller: rows are printed column by column, a reference as its value, a record's package once per read; the two reads nothing used (the 5,000-row active REST operation read and the untyped 1,000-row secret-name dictionary read) are no longer made, and `sys_plugins.description` and the empty-ACL summary's `type` are asked for and not read. `sys_db_object` is read only for the tables the typed secret-name rows name, not every table (the advisor answers its own table-origin read with those rows; nothing reads another). Replayed over dev433526's run 6 (pack 1.3.10, 2026-10-18), the printed bundle is 3.3 M characters in 135 lines instead of 11.3 M in one document, with the same findings. The script starts no read after 240 s: a read not reached is recorded as not read, and its checks are UNKNOWN, never passed; the output prints the time per section, and whether and where the cap was reached, before the bundle. **Both plugin reads — the plugin list and DATA-003's encryption plugins — are made on `sys_plugins`; `v_plugin` is never read** — a view the platform rebuilds on a cold read (207 s on dev433526, which used the whole time budget), so the advisor answers its plugin reads from `sys_plugins` on an upload (and an upload's fingerprint is compared only with other uploads'). The advisor reads schema 1 and schema 2, from engine 1.53.0. Sizing probe 1.1.0: `sys_plugins` is counted in place of `v_plugin`. No change to any check or manifest check entry. Check count unchanged (49).

**1.3.11 (2026-10-19)** — sizing probe (`tools/probe.js` 1.0.0, new): prints, for each table `tools/bundle.js` reads at size, the row total and the total of each query the bundle reads it with, the milliseconds each count took, the pack version and the build string. `v_plugin` is counted by row count (a remote table, filled by its own script). Counts only — no row content, no names, no sys_ids; nothing written. `tools/bundle.js` is unchanged apart from the pack version it prints (tool 1.3.0, same reads). No change to any check, manifest check entry or bundle schema (still 1). Check count unchanged (49).

**1.3.10 (2026-10-16)** — offline bundle (`tools/bundle.js` 1.3.0): the bundle carries the reads an uploaded scan needs to tell customer-authored records from ServiceNow-shipped and third-party ones on INJ-001, ACL-001, ACL-003, JOB-001 and DATA-006, to count INJ-001 by pattern, and to decide ACL-009 on what was read. The reads added, each made the way the advisor's connected scan makes it (the table's row count, then 1,000-row pages ordered by `sys_id`, each carrying the total):
- the origin fields (`sys_package`, its name and class, `sys_policy`, `sys_created_on`) on the permit-all ACL read and its role rows (those two reads — every empty ACL and its role rows — are the largest, and are made only when `READ_EMPTY_ACLS` is set to `true` at the top of the script; off as shipped), the wildcard ACL read, the job run-as read, and four client-callable script-include reads, one per evaluation pattern (`eval(`, `new Function(`, `GlideEvaluator`, `GlideScopedEvaluator`), each with its count;
- `sys_dictionary.sys_scope` on the typed secret-name read, and `sys_db_object` with the origin fields of every table;
- the API definition's namespace and active flag on the exposure read;
- every active knowledge base, every Can Read row, the user criteria that name roles, the `public` role and the knowledge portal pages' Public flag;
- `glide.appcreator.company.code` and `glide.knowman.block_access_with_no_user_criteria` by name, with the count;
- `sys_db_object` for the connection reader app's health table (its package);
- each admin holder's `web_service_access_only` flag, and for every web-service-only admin the count of its `syslog_transaction` rows over 90 days, with the one row that proves the filter applied (PRIV-002: for such an account the last login is never evidence of inactivity);
- `sys_scope` with its private flag and vendor.

The `oauth_entity` read now asks for the grant-type columns the instance has (`default_grant_type`, `inbound_grant_type`; there is no `grant_type`), so an upload assesses AUTH-001/002. The five uncounted dynamic-code reads (`setWorkflow(false)` among them) and the per-base knowledge criteria reads are gone: the advisor no longer sends them. These reads are plain `GlideRecord` queries, like 1.3.9's. A bundle from 1.3.9 or earlier is still accepted; the rules it lacks reads for say "bundle lacks …". No change to any check, manifest check entry or bundle schema (still 1). Check count unchanged (49).

**1.3.9 (2026-10-14)** — offline bundle (`tools/bundle.js` 1.2.0 — 1.1.0 was the tool of the withdrawn 1.3.7, and a withdrawn version number is never reused): the bundle carries the reads an uploaded scan needs for the exposure rules (EXP-001, EXP-002, EXP-005), the origin of each exposed operation, and DATA-006, so an upload no longer reports them as "bundle lacks …". Each read is made the way the advisor's connected scan makes it: the table's row count, then 1,000-row pages ordered by `sys_id`, each carrying the total; page 0 always, further pages only when the total says there are more rows (at most 50), every one of them recorded even if an earlier one fails. The reads added:
- `sys_ws_operation`, active operations with "Requires ACL authorization" cleared (`active=true^requires_acl_authorization=false`), with their package, policy and creation date — the rows EXP-001/002/005 judge and the origin each one is given.
- `sys_ws_operation`, the same operations restricted to private platform scopes (`sys_package.ref_sys_scope.private=true`), `sys_id` only, with their count — the attribution of operations the instance counted but did not return.
- `sys_ws_operation`, a count of the same operations with `sys_package.ref_sys_scope.private=false` — the proof that the private-scope filter was applied.
- `sys_upgrade_history`, `upgrade_started` and `upgrade_finished` of every upgrade, with the count — the windows that place a global-scope operation as shipped or customer-authored.
- `sys_dictionary`, the secret-name fields typed to the clear-text types (`internal_typeINstring,string_full_utf8,html,translated_text`), with the count — DATA-006.
- The row count of `sys_ws_operation`, `sys_upgrade_history` and `sys_dictionary` (one each).

These reads are plain `GlideRecord` queries: an admin's `GlideRecordSecure` query drops rows (measured on dev433526, 990–993 of 1,000 per page), so the read comes back short of its total. Every read the bundle already made is unchanged and still a `GlideRecordSecure` query; the mixed state is deliberate until the in-instance read plan is redesigned. A bundle from 1.3.8 or earlier is still accepted; it reports the exposure rules and DATA-006 as "bundle lacks …", as before. No change to any check, manifest check entry or bundle schema (still 1). Check count unchanged (49).

**1.3.8 (2026-10-10)** — offline bundle: **1.3.7 is withdrawn.** `tools/bundle.js` returns to the 1.3.6 read plan (bundle tool 1.0.0); only the pack version it prints changes. The 1.3.7 bundle paged every empty ACL, every role row on the empty ACLs and every wildcard and scripted ACL to completion — about 90,000 rows on a stock instance (dev433526, Zurich Patch 10: 39,536 empty ACLs, 37,946 role rows on them). At 2.5–7.7 s per 1,000 rows in-instance it cannot finish inside the roughly 300-second limit of the Scripts - Background page, which answered HTTP 504 and printed no bundle. The 1.3.8 bundle was run on dev433526 before release: 219.7 s, 81 reads — about 80 s inside the page limit. A bundle from 1.3.8 (or 1.3.6) is replayed by the advisor through the older reads it carries, as before. The read plan of the uploaded path is redesigned before it changes again. No change to any check, manifest check entry or bundle schema (still 1). Check count unchanged (49).

**1.3.7 (2026-10-10, withdrawn — see 1.3.8)** — offline bundle (`tools/bundle.js` 1.1.0): the bundle makes the reads the advisor's connected scan now makes. The ACL, audit and scheduled-job checks read the rows they judge selected in the query and paged to the end — 1,000-row pages by offset, at most 50 — with the row count recorded on every page, in place of capped samples of whole tables (ACL-001/002/003/005/008, AUDIT-001, JOB-001). The properties a rule measures and the build identity are read by name in one request, with a per-name count only where that read came back short. The property walk asks for empty-typed properties explicitly (`typeNOT INpassword,password2^ORtypeISEMPTY`): `type!=password` does not match an empty type, so the 1.3.6 filter left out every empty-typed property, `glide.war` among them; password-typed properties are still never read. The OAuth read asks for `default_grant_type` and `inbound_grant_type` (the table has no `grant_type` column). The return-true ACL script read is dropped from the bundle: no rule scored it. Bundles from 1.3.6 and earlier are still accepted and replayed through the older reads they carry. The README now lists every read the script makes, generated from the advisor's read inventory. No change to any check, manifest check entry or bundle schema (still 1). Check count unchanged (49).

**1.3.6 (2026-10-02)** — offline bundle: the release-fingerprint property read (`tools/bundle.js`) now skips password-typed properties (`type!=password^type!=password2`), matching the nowisor app's own read (WI-CONN-1). Their values were already redacted in-instance; now they are never read at all, so a bundle carries no password-typed property, redacted or otherwise. No change to any check, manifest entry or bundle schema (still 1). Check count unchanged (49).

**1.3.5 (2026-09-30)** — dependency updates, no rule or engine changes. Dev-only transitives of the `@servicenow/sdk` 4.13.3 toolchain pinned to patched releases: `undici@7` → 7.30.0 (it pins 7.29.0; nine advisories, among them a WebSocket denial of service, are fixed in 7.29.1) and `joi@17` → 17.13.8 (isoDate regular-expression backtracking, fixed in 17.13.7). The pack still builds clean. No change to any check, script, manifest entry or bundle format. Check count unchanged (49).

**1.3.4 (2026-09-29)** — dependency updates, no rule or engine changes. Build toolchain `@servicenow/sdk` 4.6.0 → 4.13.3 (the pack still builds clean); dev-only transitives refreshed and `js-yaml@3` pinned to the patched 3.15.2. No change to any check, script, manifest entry or bundle format. Check count unchanged (49).

**1.3.3 (2026-09-28)** — `tools/bundle.js`: the capabilities probe also reads `sys_scope` (name matches only, `name,active`), between Store apps and plugins — the same read the advisor's connected scan now makes (probe version 2), so an uploaded bundle and a connected scan assess the AI surface from the same sources. A bundle from 1.3.2 or earlier is still accepted: the AI surface then says the scopes read was not in that bundle. Check count unchanged (49).

**1.3.2 (2026-09-28)** — docs: "Connecting to the nowisor advisor" uses the current plan names (Recon, Practitioner, Practice, Connected, Managed) and the real Connect Instance path; the OAuth account sentence says what the token carries.

**1.3.1 (2026-09-27)** — docs: offline-mode section aligned with the in-app panel.

**1.3.0 (2026-09-25)** — New sensor `tools/bundle.js` (offline mode, bundle schema 1): performs in-instance the Table API reads the advisor's connected scan makes and prints them as one `nowisor-scan-bundle.json` with its SHA-256, for upload by customers who do not grant API access. Raw reads only; password-type and secret-shaped property values are redacted before printing. Registered in `manifest.json` `tools[]`. Check count unchanged (49). Every tool's `PACK_VERSION` moves to 1.3.0; no other tool changed.

**1.2.1 (2026-09-10)** — `nowisor-external-auth-policy` 1.0.1: removed a sentinel-guarded read of a per-SSO enable property that does not exist on any release (adjudicated fabricated 2026-04-28), which could never fire and read like a signal. SSO detection is the `sso_properties` active-row count alone — where the Multi-Provider SSO plugin is inactive the table is absent and the check exits as no-SSO (measured on Australia P3 `dev371429`). The real `glide.authenticate.multissov2_feature.enabled` (verified on the Zurich P6 capture + ServiceNow docs) is now reported as finding evidence `multisso_v2_feature_enabled`; it says the plugin is at v2, not that an IdP is configured, so it never decides the finding. Check count unchanged (49).

**1.2.0 (2026-08-01)** — Added the **AI and agent security** check group (17 checks, `nowisor-ai-*`): 9 inventory checks (AIA-001..009) covering agent ownership, review trail, shadow-AI endpoints, sub-production posture, dormant grants, shared execution identities, elevated run-as, ungoverned inbound MCP / Action Fabric agents, and AI Control Tower registry coverage; plus 8 static guardrail and governance-posture checks (AIG-001..008). Three new sensors: `ai-discovery-export.js`, `ai-bom-export.js`, `ai-usage-export.js`.

Notable in this release:

- **`log_sources[]` gained per-source completeness** (`truncated`, `effective_lookback_days`). Both fields are optional and additive — the envelope schema stays `v1`, and a consumer that ignores them behaves exactly as before. They exist because the run-level `budget.exhausted` flag cannot say *which* log table was cut short, and an advisor that cannot tell the difference has to treat a complete source as truncated. A budget that ran out harvesting the fourth candidate says nothing about the first three, whose rows are already in hand.
- **A truncated run can no longer read as "never used".** When the sensor stops early, `invocations` is empty *because it stopped* — which over a window the log table happens to cover is indistinguishable from a permission that was genuinely never exercised. The advisor now caps the evidence window at what the sensor reports it achieved, so a truncated run resolves to `UNKNOWN-USAGE` with "evidence collection incomplete (query budget)" rather than a revocation instruction. Sensor output is unchanged in shape apart from the two fields above; the guarantee is in how it is read.

- **Enumeration-driven detection.** Table and field names are resolved from `sys_db_object` / `sys_dictionary` at runtime, never hardcoded. The `sn_aia` namespace is paid-SKU gated and cannot be verified against a developer instance, so asserting its identifiers from documentation alone was not defensible.
- **Absent plugin ⇒ `N/A`, never PASS.** The absence of Now Assist is out of scope, not a security win.
- **The CONDITIONAL cap became code.** Delegation-aware severity was previously prose in `lib/delegation-severity.md` consumed by LLM surfaces. For agent permissions it is now a deterministic function with its own tests: a grant whose lineage was never observed caps at CONDITIONAL and names the artifact that would settle it, and only a *complete* delegation-chain walk can lift the cap. Presentation is separate from semantics — an unconfirmed sensitive write still renders in its floor band rather than sinking below confirmed lower severities.
- **Framework mapping additions.** `owasp_llm`, `mitre_atlas` and `eu_ai_act` join the existing `nis2` / `iso27001` / `dora` keys (additive; finding schema stays `v1`). OWASP Agentic threat IDs are deliberately omitted until they can be cited version-pinned.
- **DORA sub-article precision.** The new group emits ASCII sub-article ids (`9.4.c`) which the advisor renders as `9§4(c)`; Rhino ES0 cannot emit the section sign. The 18 legacy checks still emit whole-article `['9']` — tracked separately.

Total checks 32 → 49.

*Adversarial review.* This release was reviewed in **ten adversarial passes** that asserted invariants and then tried to falsify them. **67 invariants were falsified and repaired**, each with a committed test that fails if the repair is reverted. Rounds 1-2 found 16, the most serious being the truncated-run case above. **Round 3 was the first genuinely independent reviewer and found 13**, including one that no unit suite could have seen: every module was correct and green and the whole feature was wired to nothing — 605 tests passed over a deliverable that could not be reached. Rounds 4-10 found the remaining 38, and the pattern that emerged is worth stating plainly: most of them were re-openings of a previous round's repair, one field or one file outside where the fix stopped applying.

The point of recording this in a changelog: a scanner that recommends revoking production access is only as trustworthy as its willingness to be wrong in public. Several of these findings were cases where the tool would have told a customer they were clear when it had no basis to — a nonsense retention floor believed instead of refused, a truncated run read as "never used", an envelope allowed to declare itself already validated. The rules that came out of it are enforced in code, not documented as intentions: a validation that cannot run must refuse rather than pass; every sensor-emitted flag declares which way it fails when unreadable; supplying LESS information must never produce a softer verdict. What has still not run is an end-to-end pass against an instance with Now Assist actually activated — `sn_aia` is paid-SKU on every developer instance, so the populated path is exercised by fixtures and the `N/A` path by real instances.

**1.1.0 (2026-06-11)** — Added the **Basic Auth API restriction** check group (5 checks, `nowisor-basic-auth-*`) for the ServiceNow Basic Auth restriction rollout (KB3025707/KB3055080): restriction-tracking-active, enforcement-posture (with days-remaining countdown), hybrid-accounts-undecided (`sys_user_basic_auth_exception`), role-without-WSAO (MFA-bypass), and dormant-API-accounts. All identifiers (4 `glide.authenticate.basic_auth.restriction.*` properties, the allow-list properties, the `snc_basic_auth_api_access` role, and the `sys_user_basic_auth_exception` table + fields + `decision` choices) verified read-only on Zurich Patch 6 `dev265147`, 2026-06-11. Ships a cross-scope read privilege for `sys_user_basic_auth_exception`. Total checks 27 → 32.

**1.0.1** — Added the audit-coverage-gap check (#27) and LinterCheck A1-DEP evidence keys.

**1.0.0** — Initial public release: 26 checks + the log-export twin sensor.

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

Connecting an instance is included from the **Connected** plan. To connect:

1. Sign in to nowisor.com
2. Click **Connect Instance** in the header
3. Choose **OAuth** (register an OAuth API endpoint under **System OAuth > Application Registry** with the Redirect URL the panel shows, then enter its Client ID and Client Secret) or **Basic Auth** with a service account. With OAuth nowisor stores an OAuth token and the client credentials you registered — never a user password; the token carries the roles of the user who authorises it, so authorise with a dedicated read-only account.

The tables a connected scan reads are listed at [nowisor.com/access](https://nowisor.com/access). If the instance cannot be reached from outside, run `tools/bundle.js` and upload its output instead (**Instances → Upload results**, same plans).

Plans, by what they do with this pack:

- **Recon** (free): the advisor, 25 queries lifetime. You run the pack and paste its output into chat.
- **Practitioner**: the advisor without a query limit, 5 seats. You run the pack and paste its output into chat. No scan-pack import, no instance connection.
- **Practice**: adds scan-pack import — Active Risk correlation (scan findings bound to runtime log signals) and the CycloneDX AI-BOM, which is where named AI agents and endpoints appear. No instance connection.
- **Connected**: one live instance — OAuth, Basic Auth or an uploaded bundle — with scheduled scans, compliance posture, the Instance Security Report PDF, and the automated push below. Signed evidence packs are delivered under the Assured engagement.
- **Managed**: operator-provisioned, several instances, remediation tickets written back to the instance.

Current prices and the full comparison: [nowisor.com/#pricing](https://nowisor.com/#pricing).

### Automated push (recommended)

Instead of copy-pasting scan output into the advisor, the pack can push its
findings automatically from a Scheduled Job in your instance to the advisor's
machine API:

1. In nowisor.com go to **Settings → API Keys**, create a key with the
   `scanpack:push` scope, and store it in your instance as a connection
   credential or an `x_nowisor_isp` system property (encrypted `password2`
   recommended — never hardcode it in the script).
2. Create a **Scheduled Script Execution** (hourly is a reasonable default,
   scheduled AFTER your Scheduled Scan cadence) with a script that:
   - collects the latest `scan_finding` records exactly like
     `tools/security-log-export.js` formats them (`---NOWISOR_METADATA---`
     envelope, plus the optional `---NOWISOR_LOGEXPORT---` block), and
   - POSTs them via `sn_ws.RESTMessageV2` to
     `https://nowisor.com/api/v1/scan-pack/import` with headers
     `Authorization: Bearer <your key>` and `Content-Type: application/json`,
     body `{"rawInput": "<the envelope text>", "instanceLabel": "<instance name>"}`.
3. The advisor correlates each push with its signature set and stores the
   verdicts — same result as the paste flow, without the human in the loop.
   Rate limit: 12 pushes/hour per key; the response is JSON with the verdicts.

The outbound REST call is one-way: the key can only push findings and cannot
read anything from the advisor account.

## Troubleshooting

### "No findings produced after scan"

- **Suite not bootstrapped.** Run `bootstrap/install-suite.js`. Without it, the platform's full-scan engine never executes the checks.
- **Checks inactive.** Navigate to Scan Checks list filtered by scope `x_nowisor_isp` — confirm every check `manifest.json` marks `active: true` is `active=true` (47 of the 49 in 1.3.13; `nowisor-hardcoded-credentials` and `nowisor-direct-property-write` ship deferred and are expected to be inactive).
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

Re-run `npx now-sdk install --auth <alias>` — it now completes and creates the `x_nowisor_isp` scope with every check in `manifest.json` (49 checks in 1.3.13). Revert anytime by removing `nowisor` from the property. **Do not rename the scope** to dodge this — `x_nowisor_isp` is hardcoded in `bootstrap/install-suite.js` and every `check.sys_scope.scope=x_nowisor_isp` query.

If the `syslog` shows a *different* line instead of the third-party block, two other prerequisites can produce the same null-application surface error: (a) **ServiceNow IDE < 4.1.1 or `sn_appclient` < 29.0.4** — entitle/upgrade from the Store, sync Application Manager; (b) a **`glide.appcreator.company.code`** scope-prefix mismatch. Always read the line above the `ScopedAppUploadProcessor` error first. Note: `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` is a now-sdk package, **not** a plain Update-Set XML — it routes through the same processor and fails identically; there is no SDK-free import path today.

## Compatibility

| Release | Verified | Status |
|---|---|---|
| Zurich Patch 6 | dev265484 | Fully verified — property baseline complete; 24/24 verification Background Scripts pass on a live instance |
| Australia Patch 2 | dev194572 | **Verified end-to-end** (v1.0.0, then 25 active / 2 deferred checks; the count has since grown — see the changelog) — installs cleanly after trusting the pack's vendor key in `sn_appauthor.all_company_keys`; see [Troubleshooting → "application was null"](#troubleshooting). Suite bootstrap + a live suite scan validated: 144 findings emitted under `x_nowisor_isp` with the intact `---NOWISOR_METADATA---` v1 schema (advisor-integration contract holds). The third-party rejection is a per-instance policy, not a build issue. Verified 2026-05-31. <!-- doc-count:historical: this row records the v1.0.0 end-to-end run; its numbers are that era's, not today's --> |
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
