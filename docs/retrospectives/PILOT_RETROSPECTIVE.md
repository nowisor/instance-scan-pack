# nowisor Instance Scan Pack — Pilot v0.1 Retrospective

**Date:** 2026-05-10
**Target instance:** dev265484 (Zurich Patch 6)
**SDK:** @servicenow/sdk 4.6.0
**Working time:** ~3.5 hours
**Recommendation:** **REFINE PILOT** before scaling to v1.

---

## Executive summary

Three checks deployed cleanly via Fluent SDK. All three executed during a Full Scan triggered from the UI (SR00000013, 9 min, 265 total findings across the OOB suite). **All three of our checks produced zero findings with score=100.** Two of those zeros are unexpected and signal real v1-blocking unknowns: the Admin Role check found 0 admins despite an actual ratio of 36% (18/50), and the eval LinterCheck found 0 despite 50+ Script Includes containing `eval`. The conversion methodology itself works — Now.include() inlines correctly, framework mappings render verbatim in `resolution_details`, deterministic `$id`-derived sys_ids enable clean update paths — but the pilot exposed three v1-blocking unknowns that need a focused follow-up sprint before committing 30+ check authoring effort.

---

## What was built

| $id | Type | Sys ID on dev265484 | Final priority | Findings produced |
|-----|------|---------------------|----------------|-------------------|
| `nowisor-csrf-token-enforcement` | ScriptOnlyCheck | `b20ecfa9500e4ac48fcab135b839b352` | 1 | 0 (correct PASS — `glide.security.use_csrf_token = 'true'` on dev265484) |
| `nowisor-admin-role-concentration` | ScriptOnlyCheck | `e27b5266082240d8bf97d231ca14ca52` | 1 | 0 (**unexpected** — actual ratio 18/50 = 36% via REST query) |
| `nowisor-eval-usage-detector` | LinterCheck | `b6d3e0840f21424e908a542597b07387` | 1 | 0 (**unexpected** — 50+ OOB Script Includes contain `eval` per direct `sys_script_include` query) |

**Project layout** (~360 LOC across 7 files plus npm scaffolding):

```
src/fluent/scan-checks/
  csrf-token-enforcement.now.ts
  admin-role-concentration.now.ts
  eval-usage-detector.now.ts
scripts/
  check-csrf-token-enforcement.js
  check-admin-role-concentration.js
  check-eval-usage-detector.js
  sn-query.sh           # REST helper (pilot-only)
README.md
PILOT_RETROSPECTIVE.md
```

---

## Empirical answers to the 7 questions

### Q1 — Deployment mechanics

| | |
|--|--|
| Init command | `npx now-sdk init --appName "..." --packageName "..." --scopeName "x_nowisor_isp" --template "typescript.basic"` |
| Auth command | `npx now-sdk auth --add <url> --type basic --alias <alias>` (interactive prompts for username/password) |
| Build command | `npx now-sdk build` (~3s, validates Fluent + emits `dist/app/update/*.xml`) |
| Install command | `npx now-sdk install --auth <alias>` (5-15s success path) |
| Permissions on dev265484 | `admin` role sufficient (Basic auth) |
| Free PDI? | **Yes** — works on Zurich Patch 6 PDI without paid SKUs |
| Incremental? | Yes — INSERT_OR_UPDATE on deterministic sys_ids (derived from `$id` via the SDK build) |

**Critical finding — incremental install reliability:** Plain `now-sdk install` reproducibly **silently failed** in this pilot. After an initial successful install + one `--reinstall`, every subsequent plain install returned `ERROR: Could not determine app installation status` after exactly 38 seconds, and the instance state did **not** reflect local source changes. Verified by querying `sys_app.sys_updated_on` (unchanged) and the modified `scan_script_only_check` record (priority field still old value). Recovery via `--reinstall` always worked (10-18s). This was reproduced twice during the pilot. For v1 distribution this is a real risk — customers updating between releases of the pack may believe install succeeded when it didn't.

**Build artifact structure:** Each check emits one `scan_<type>_check_<sys_id>.xml` plus one `sys_module_<sys_id>.xml` per `Now.include()`'d script. The XML is plain `<record_update>` format suitable for update-set distribution.

### Q2 — Finding output structure

`scan_finding` schema (verified via `sys_dictionary`):

```
sys_id (GUID)
check (reference → scan_check)            # the check that produced the finding
result (reference → scan_result)          # the scan run grouping (SR000xxxxx)
task (reference → scan_task)
finding_details (string)                  # what we set via finding.setValue()
count (integer)                           # what we set via finding.setValue()
source (document_id)                      # auto-populated when check uses setCurrentSource
source_table (table_name)                 # auto-populated alongside source
muted (boolean)
check_version (integer)
sys_package, sys_domain, sys_class_name, sys_created_on, etc.
```

`scan_check_execution` (one per check per scan run):

```
check (ref), result (ref), score (int 0-100), execution_time (ms), message (string)
```

`scan_result` (one per scan run):

```
number (SR000xxxxx), state (complete/error/cancelled),
scan_type (full_scan / app_scan / suite_scan / test_scan),
finding_count (int), execution_time (ms), combo, progress_id
```

**Verbatim preservation of resolutionDetails:** YES — multi-line strings with newlines, special characters (NIS2 §, hyphenated bullets), and ServiceNow-specific identifiers (`glide.security.use_csrf_token`) all preserved exactly as authored. Confirmed by `sysparm_display_value=all` REST query showing the literal string in both `display_value` and `value` slots.

**Critical authoring gotcha:** `Array.join('\n')` in a check property serializes to the literal string `Symbol(CallExpressionShape)` instead of throwing. The Fluent compiler accepts only string literals and template literals for these fields. Caught and fixed during pilot (would have shipped broken otherwise — silent serialization failure with no validation error from `now-sdk build`).

**UI display of framework mappings:** Could not be verified — no findings were produced, and the Instance Scan dashboard at `/scan_dashboard.do` shows aggregated counts, not full `resolution_details` text. The text is preserved in the database; whether the UI renders multi-line bullets faithfully is open.

### Q3 — Scheduling and execution

**UI mechanisms** (the supported path):

| UI action | Onclick | Backend method |
|-----------|---------|----------------|
| Test Check | `initTestScan()` | `ScanAjaxProcessor.executeTestScan` → `sn_instance_scan.ScanInstance().triggerTestScan(sysId, tableName)` |
| Execute Full Scan | `init()` | `ScanAjaxProcessor.executeFullScan` → `sn_instance_scan.ScanInstance().triggerFullScan()` |
| Schedule Full Scan | `redirectToScheduledJob()` | redirects to scheduled job at sysauto sys_id `0c98a05b0fd233006e5140c1df767e19` (the OOB Default Full Scan) |

The full surface of `sn_instance_scan.ScanInstance` (reverse-engineered from the SI source):

```js
triggerTestScan(sysId, tableName)        // single check
triggerPointScan(tableName, sysId)        // scan a specific record
triggerSuiteScan(sysId)                   // run a check suite
triggerAppScan(scopeId)                   // all checks in a given scope
triggerFullScan()                         // full instance, all suites
triggerUpdateSetScan(sysId)               // scan an update set
triggerUpdateSetBatchScan(sysId)
cancelScan(progressId, false)
```

**Programmatic API (CI/CD):** **Non-trivial.** Plain Basic auth REST does not work — `xmlhttp.do` returns `error="invalid token"` without a CSRF token. Fetching the token requires a session cookie + scraping `g_ck` from the root page HTML. Even with token + session + `sysparm_processor=ScanAjaxProcessor`, the call returned an empty `answer` attribute and no execution record was created (root cause not isolated; the function may have early-returned silently or the session context was insufficient). The Background Script endpoint (`/sys.scripts.do`) responds with `Content-Length: 0` and clears the session (`X-Is-Logged-In: false`) — Zurich appears to require an additional elevated-privilege step beyond admin role for that endpoint.

For v1 CI/CD integration, the cleanest path is **a Scripted REST API ship-with-the-pack** that wraps `triggerSuiteScan` (or `triggerAppScan`). Customer hits one HTTPS endpoint with admin Basic auth, receives a `progress_id`, polls `scan_result` until `state=complete`. Adds 1 file to v1 pack (~30 LOC); eliminates the entire CSRF dance.

**Per-check vs full-scan execution:** Both supported. Full Scan via the Default Full Scan scheduled job runs all active checks across all suites — that's what produced this pilot's executions (SR00000013, 535s wall time, 265 OOB findings). Per-check (`triggerTestScan`) requires the check sys_id and its concrete table name (e.g., `scan_script_only_check`).

**Error/failure visibility:** `scan_check_execution.message` carries any thrown error. `scan_log0000` through `scan_log0007` are partitioned log tables. Our checks ran with empty `message` (no errors caught) but still produced 0 findings — see Q5 for what this implies about debugging silent-zero results.

### Q4 — Update lifecycle

Tested protocol: deploy v0.1 with priority=1, modify CSRF check to priority=2 + new `shortDescription`, redeploy, observe.

**Findings:**

1. **`$id`-derived sys_id is stable across rebuilds.** All three rebuilds produced identical `scan_<type>_check_<sys_id>.xml` filenames. The check record on the instance kept the same sys_id (`b20ecfa9500e4ac48fcab135b839b352`) across deploys.

2. **Plain incremental install (`now-sdk install`) reproducibly failed** with the timeout described in Q1. Instance state did not change (priority remained 1; `sys_updated_on` did not advance). Customer cannot rely on this command for pack updates.

3. **`--reinstall` succeeded reliably** (10-18s) and applied changes correctly: priority `'2'`, new `shortDescription`, fresh `sys_updated_on`. **But `--reinstall` deletes and recreates the application**, which means:
   - `scan_check_execution` records previously tied to our checks were **deleted** (3 records → 0)
   - `scan_finding` records would similarly be wiped (we had none to verify, but the SDK's own `--reinstall` warning makes this explicit: *"any application metadata on your instance that isn't present in the local application installation package will be removed during the uninstall process"*)
   - `sys_mod_count` reset to 0 (fresh INSERT, not UPDATE)

4. **Findings persistence across deployments — open question.** Because our checks produced no findings, we couldn't directly observe whether findings persist or are wiped during `--reinstall`. Based on the warning text above, findings linked to the application's tables would be deleted alongside.

**For v1:** Packs need a versioning strategy that doesn't require destructive reinstalls. Options to investigate:
- Whether `--reinstall` can be made non-destructive for tables in another scope (`scan_finding` is in Global, not our scope — may already be safe)
- Whether incremental install reliability can be improved (root cause of the 38s timeout unknown — may be a 4.6.0 SDK bug, may be specific to our project)
- Whether we should ship a `migrate.js` that customers run instead of relying on the SDK install

### Q5 — AST API limitations (LinterCheck)

**Most consequential pilot finding.** Could not validate any of the brief's questions about ES6 handling, table coverage, or AST predicate behavior because **the LinterCheck produced zero findings despite clear matching content existing on the instance**.

Evidence:
- Direct REST query `sys_script_include?sysparm_query=scriptCONTAINSeval` returned 50+ active records (ScheduledInstallService, AutoResolutionSLACondition, BundleExtensions, and many more)
- LinterCheck `execution_time = 115869ms` (~2 minutes) — significant work occurred; the engine was not skipped
- `score = 100, message = ""` — no error, no exception caught
- `scan_target` table is empty on dev265484 — no targets are explicitly defined
- Our pack is the **only active LinterCheck** on the instance (Zurich Patch 6 ships with zero active LinterChecks for comparison) — could not validate the AST engine via a known-working OOB linter

**Hypotheses (untested):**
1. LinterCheck requires explicit `scan_target` configuration to know which tables to traverse; without one, it scans only its own scope's scripts (we have none beyond our 3 detector scripts, none of which contain `eval`)
2. The AST predicate `node.getTypeName() === 'NAME' && node.getNameIdentifier() === 'eval' && parent.getTypeName() === 'CALL'` is wrong for the actual ServiceNow Rhino AST representation
3. Custom-scope LinterChecks may be sandboxed from reading global scripts

**For v1:** A LinterCheck cannot ship without resolving this. The pattern should be validated against a planted Script Include known to contain `eval('1+1')`, with explicit `scan_target` configured if needed, and the AST predicate logged via `gs.info` calls during scan execution to prove it traverses the expected tables. This is a focused 2-3 hour investigation, not a v1 redesign.

### Q6 — Multi-release portability

| Aspect | Zurich Patch 6 (tested) | Australia (untested) | Older releases |
|--------|------------------------|---------------------|----------------|
| `sn_instance_scan.ScanInstance` namespace | ✓ exists | likely exists (open-sourced docs confirm) | uncertain — different namespace before Tokyo/Utah era |
| `gs.getProperty` | universal | universal | universal |
| `GlideAggregate` patterns | universal | universal | universal |
| AST node types ('NAME', 'CALL') | per docs | per docs | per docs |
| Deterministic `$id` → sys_id | SDK 4.6.0 feature | same SDK | requires SDK 4.0+ |
| Property defaults (`use_csrf_token = 'true'`) | confirmed via PDI | unconfirmed | varies |

**Conclusion:** The check logic itself is portable; the SDK abstraction is portable; what isn't portable is the assumed property defaults and (potentially) custom-scope ACL configuration. v1 should test on the Australia PDI as a second-instance gate.

### Q7 — Distribution path

Three plausible v1 distribution models, ranked by friction:

| Model | Customer steps | Cleanliness | v1 fit |
|-------|---------------|-------------|--------|
| Git clone + `now-sdk install` | install Node 20 → npm install -g @servicenow/sdk → auth → install | medium friction; familiar to ServiceNow developers | **best for early adopters** |
| Update set XML download | login → import update set → commit | low friction; no toolchain | best for ops teams; loses incremental update path |
| ServiceNow Store | search → install (one click) | lowest friction | best for scale; weeks of cert burden |

**Pilot observation:** `dist/app/` is a pure update-XML layout. `now-sdk pack` is supposed to bundle this into a deliverable update set; not exercised in pilot but available. Model 2 is therefore "free" once `now-sdk pack` is run.

**Recommendation for v1 launch:** Ship as git clone + install (Model 1) for the first 5-10 design partners; produce parallel update set XML (Model 2) for ops-heavy buyers; defer Store submission until findings quality is validated across 3-4 customer instances.

---

## Surprises and blockers

| Class | Item | Impact |
|-------|------|--------|
| **Methodology gotcha** | `Array.join()` in `resolutionDetails` serializes to `Symbol(CallExpressionShape)` silently | Caught & fixed; v1 generator template must use template literals only |
| **Doc/runtime contradiction** | `instance-scan-guide` says "always inline scripts, never use Now.include()" but `scriptonlycheck-api` example shows Now.include and it works | Documented; v1 uses `Now.include()` for separation |
| **v1 blocker** | Admin Role check produced 0 findings despite obvious match (cross-scope ACL hypothesis) | Must resolve before v1 |
| **v1 blocker** | eval LinterCheck produced 0 findings despite 50+ matches | Must resolve before v1 |
| **v1 blocker** | Incremental `now-sdk install` silently fails after first reinstall | Must resolve before v1 distribution |
| **CI/CD friction** | No clean Basic-auth REST API for triggering scans | v1 must ship a Scripted REST API wrapper |
| **Lifecycle warning** | `--reinstall` deletes `scan_check_execution` history | v1 README must call this out |

---

## Recommendation: REFINE PILOT

Three v0.2 follow-up tasks (estimated 6-10 hours total) close the v1-blocking unknowns:

1. **Cross-scope ACL resolution for ScriptOnlyChecks** (2-3h)
   - Add `sys_scope_privilege` records to the pack OR explicit `Cross-scope access` config
   - Re-run admin role check; verify finding produced for 36% admin ratio
   - Document the privilege set required in the pack's `sys_scope_privilege` definitions

2. **LinterCheck target configuration + AST predicate validation** (2-4h)
   - Investigate whether `scan_target` records are required for LinterCheck to traverse `sys_script_include`
   - Plant a known-eval Script Include, verify the predicate fires
   - Log AST traversal counts via `gs.info` during scan to confirm coverage

3. **Install reliability + Scripted REST trigger API** (2-3h)
   - Root-cause the 38s incremental install timeout (file an SDK bug if reproducible on a fresh project; design around if it's project-specific)
   - Ship a `nowisor_scan_trigger` Scripted REST API endpoint in the pack that wraps `triggerSuiteScan` — eliminates CSRF dance for CI/CD

After v0.2 closes those three, **scale to v1 with high confidence.**

### Revised v1 effort estimate

| Task | Hours |
|------|-------|
| v0.2 follow-up sprint | 6-10 |
| 30-check authoring (post-pattern) | 12-15 |
| Framework mapping integration (NIS2/DORA/ISO leveraging existing nowisor KB) | 3 |
| Scripted REST trigger API + README | 2 |
| Australia PDI cross-test | 3-5 |
| Distribution polish (update set pack, install script, customer README) | 3 |
| **Total** | **29-38** |

Squarely within the original 25-50 hour estimate. The pilot's 3.5h investment shaved no scope but raised confidence in the timeline by surfacing exactly what the unknowns are.

---

## Methodology rules — final state

| Rule | Held in pilot? |
|------|----------------|
| Property names verified in `verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json` | Yes — `glide.security.use_csrf_token` confirmed |
| Hardcoded sys_ids documented with verification command + timestamp | Yes — admin role sys_id `2831a114c611228501d4ea6c309d626d` cited in script comment with verification REST call |
| Server-side scripts ES5-only | Yes — all `var`, `function() {}`, no template literals at runtime |
| Now.include() over inline | Yes — three external `.js` files; build-time inlining confirmed in generated XML |
| Scripts marked "Read-only, safe for production" | Implicit in script intent; explicit comment can be added in v0.2 |

---

## What success looked like (per the brief)

- ✅ Project scaffold at `nowisor/instance-scan-pack/` with working build/install commands
- ✅ Three checks deployed to dev265484 (sys_ids `b20ecfa9...`, `e27b5266...`, `b6d3e084...`) and visible in Instance Scan UI
- ✅ Scan run produced `scan_check_execution` records for each check (SR00000013)
- ✅ Framework mappings preserved verbatim in `resolution_details` (verified via REST `sysparm_display_value=all`)
- ✅ Retrospective answers all 7 empirical questions
- ✅ Recommendation captured (refine pilot before v1)
- ⚠ Real `scan_finding` records: **NOT produced** for any of the three checks (CSRF correctly = 0; admin and eval unexpectedly = 0). This is itself the most consequential finding — see "v1 blockers" above.
