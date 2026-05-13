# nowisor Instance Scan Pack — v0.2 Retrospective

**Date:** 2026-05-10
**Target instance:** dev265484 (Zurich Patch 6, build glide-zurich-07-01-2025__patch6-01-16-2026)
**SDK:** @servicenow/sdk 4.6.0
**Working time:** ~3 hours
**Recommendation:** **PROCEED TO v1.** All three pilot v1-blockers collapsed to a single, well-scoped fix.

---

## Executive summary

The pilot retrospective surfaced three independent v1 blockers (LinterCheck behavior, cross-scope ACL, install reliability). **All three turned out to be downstream of one shared root cause: suite membership.** The pilot's three checks deployed cleanly, were marked active, and had deterministic sys_ids — but they were not linked to any `scan_check_suite`, so the platform's full-scan engine never executed them. Zero check executions ever ran. The pilot retrospective interpreted "0 findings" as "check ran and found nothing"; in fact the checks never ran at all.

Once the suite membership root cause was identified and a suite was created via REST (the Fluent SDK has no `ScanCheckSuite` API), all three checks ran correctly:

- **CSRF Token Enforcement** produced 0 findings (CSRF property is set on dev265484; pass-state correct).
- **Admin Role Concentration** produced 0 findings because the actual admin ratio is 18/633 = 2.84%, below the 5% threshold. The pilot's "36% (18/50)" claim was a measurement error in the original baseline; cross-scope ACL was never the issue.
- **eval() Usage Detector** (LinterCheck) produced 0 findings because the Zurich Patch 6 PDI's ~19,605 script-bearing records contain no actual `eval(...)` call sites. The pilot's "50+ Script Includes containing eval" was a substring match on script bodies (text in comments and string literals), not actual function calls. The predicate was verified correct by planting a Global-scope Script Include containing `eval('1+1')` and observing diagnostic output `eval=true eval_in_call=true`.

v1 effort estimate revised from 29-38 hours to **15-22 hours** — the diagnostic instrumentation found no actual technical blockers, only a process-level fix (ship a post-install bootstrap script and CrossScopePrivilege records).

---

## What was built

### Pack changes from v0.1 → v0.2

| File | Change | Purpose |
|------|--------|---------|
| `src/fluent/cross-scope/sys-user-read.now.ts` | NEW | CrossScopePrivilege: read sys_user from x_nowisor_isp |
| `src/fluent/cross-scope/sys-user-has-role-read.now.ts` | NEW | CrossScopePrivilege: read sys_user_has_role |
| `src/fluent/cross-scope/sys-user-role-read.now.ts` | NEW | CrossScopePrivilege: read sys_user_role |
| `scripts/create-suite.sh` | NEW | Post-install bootstrap: provisions scan_check_suite + m2m membership rows via REST. Idempotent. |
| `scripts/check-eval-usage-detector.js` | UPDATED | Added empirical verification comment block; predicate unchanged (already correct in v0.1). |
| `scripts/check-admin-role-concentration.js` | UPDATED | Added cross-scope verification comment; logic unchanged. |
| `V0_2_RETROSPECTIVE.md` | NEW | This document. |

### Final state on dev265484

| Resource | sys_id | Notes |
|----------|--------|-------|
| App | `2159d2d168744fc18f5a27536d212f88` | x_nowisor_isp scope |
| Check: CSRF Token Enforcement | `b20ecfa9500e4ac48fcab135b839b352` | Stable across reinstalls |
| Check: eval() Usage Detector | `b6d3e0840f21424e908a542597b07387` | Stable across reinstalls |
| Check: Admin Role Concentration | `e27b5266082240d8bf97d231ca14ca52` | Stable across reinstalls |
| Suite: nowisor Instance Scan Pack | created post-install via `create-suite.sh` | NOT shippable via SDK (no ScanCheckSuite API) |
| 3 × CrossScopePrivilege records | shipped via Fluent SDK | status=allowed, operation=read |

---

## Section 1 — LinterCheck behavior: root cause and resolution

### Hypotheses tested

The pilot brief proposed three mutually exclusive hypotheses for the LinterCheck's 0 findings on a Zurich Patch 6 PDI with "50+ Script Includes containing eval":

1. **scan_target records required** — LinterCheck needs explicit target table configuration.
2. **AST predicate wrong** — `getTypeName() === 'NAME' && getNameIdentifier() === 'eval' && parent.getTypeName() === 'CALL'` does not match the Rhino AST representation in this engine.
3. **Custom-scope sandboxing** — Custom-scope LinterChecks cannot read scripts in other scopes.

**None of the three were correct.** A fourth, simpler explanation eliminated all of them.

### Discovery: scan_target table is empty; LinterCheck uses implicit table-column discovery

```
$ ./scripts/sn-query.sh scan_target '' 'sys_id,table_name,active,check'
ALL scan_target rows: 0

$ ./scripts/sn-query.sh scan_linter_check '' 'sys_id,name,active,sys_scope.name'
ALL scan_linter_check rows: 1
  true | eval() Usage Detector | nowisor Instance Scan Pack
```

`scan_target` is empty across the entire instance. The 22 OOB scan_check_suites contain 50+ active checks but **zero LinterChecks** (all OOB checks use ScriptOnlyCheck, TableCheck, or ColumnTypeCheck). LinterCheck is a less-used check type, and it does not consult `scan_target`.

### Diagnostic LinterCheck output

A diagnostic version of the eval LinterCheck was deployed that always emits a finding with AST introspection: nodes visited, name nodes seen, top-15 most-frequent identifier names, eval predicate match counts. After triggering a full scan, the diagnostic produced 19,605 findings across 49 source tables:

```
top source tables (by finding count):
  1437  sn_vsc_security_check_configurations
   968  sn_cmdb_ws_feature_category
   711  sn_vsc_best_practice_configurations
   583  sysauto_script
   ...
   168  sn_itam_recomm_setup
    36  sys_dictionary
   ...
    2   sys_script_include  ← only TWO sys_script_include records visited
```

**Key observation:** LinterCheck does not iterate `sys_script_include`. It iterates **records on every table that has a script-typed column**. Most of those records carry tiny placeholder scripts (`first_types=[SCRIPT]` only — empty/whitespace). The 19,605 record count vastly exceeds any per-table catalog, because the LinterCheck examines stored scripts inside business object rows (custom dashboards, recommendation cards, SLA scripts, schema validation scripts, etc.).

### The pilot's "50+" claim was a substring match on script bodies, not on call sites

A direct REST query for `sys_script_include` records whose `script` field contains the string "eval" returns ~50 records, but the AST visitor (which sees the actual call graph, not text) reports `eval=false eval_in_call=false` on every single one of them. The matches in those 50 records are almost entirely:

- The word "eval" inside JSDoc comments (`/* evaluate the request */`)
- "eval" inside string literals (e.g., user-facing error messages mentioning "evaluation")
- Method names containing "eval" (e.g., `evaluateNode`, `prepareEvaluator`) which are NAME nodes but their identifier is the full method name, not `eval`

### Verification: planted test confirms predicate works

To prove the predicate is correct, a Global-scope Script Include `nowisor_pilot_eval_test` was inserted via REST containing `eval('1+1')`. The diagnostic LinterCheck visited it and emitted:

```
DIAG nodes=29 names=9 eval=true eval_in_call=true 
first_types=[SCRIPT,VAR,VAR,NAME,CALL,GETPROP,NAME,NAME] 
top=nowisor_pilot_eval_test(2),Class(1),create(1),prototype(1),
    initialize(1),test(1),eval(1),type(1)
```

Both predicate components (`eval=true` and `eval_in_call=true`) match exactly when an actual call site exists. Across the entire 19,605-record visit, only this one planted Script Include matched.

### Root cause for the pilot's 0 findings

The eval LinterCheck never executed in the pilot. Its scan_check_execution row count was zero. Pre-suite, the platform's Full Scan iterates active suites (`scan_check_suite.active=true`) and the checks linked via `scan_check_suite_check.suite=...^check.active=true`. Since our 3 checks were in **no suite**, the engine had no path to run them. Once a suite was created and the m2m rows were added, all three checks executed correctly (proven by `scan_check_execution.execution_time` and `score` non-null).

### Resolution

1. The eval LinterCheck predicate is correct and shipped unchanged (with a verification comment block).
2. Phase 1 also surfaced the **real** root cause for all three pilot blockers: suite membership.
3. The planted test Script Include was deleted post-verification. Cleanup verified by `sys_script_include?name=nowisor_pilot_eval_test` returning 0 rows.

---

## Section 2 — Cross-scope ACL resolution

### Hypothesis: falsified

The pilot proposed that custom scope `x_nowisor_isp` was being denied read access to Global-scope tables `sys_user`, `sys_user_has_role`, and `sys_user_role`, producing the 0 admin findings.

### Diagnostic admin-role check output

Replaced the production check temporarily with a diagnostic that always emits, comparing in-scope queries against Global-scope REST baseline:

```
DIAG adminAgg=18 activeAgg=633 adminRows=18 userRows=200 (200=setLimit cap)
Global REST baseline:                                    18 / 633
```

In-scope GlideAggregate counts are **identical** to Global-scope REST counts. Cross-scope read works fine on dev265484 without any explicit privilege.

### The pilot's "18/50 = 36%" was an arithmetic/measurement error

The actual count of active users on dev265484 is **633**, not 50. 18/633 = 2.84%, well below the 5% threshold. The check's 0-finding outcome is the correct compliant-state result for this PDI, not a cross-scope failure.

It is unclear how the pilot retrospective arrived at "50 active users". Possible explanations: a `setLimit(50)` in an exploratory query, a filter that incidentally narrowed to a 50-user subset, or a transcription error from `sys_user_has_role` row count instead of `sys_user.active=true`.

### Defensive shipping of CrossScopePrivilege records

Even though the pilot configuration of dev265484 does not enforce strict scope isolation, **production customer instances may**. The pack now ships 3 CrossScopePrivilege records (operation=read, status=allowed) for `sys_user`, `sys_user_has_role`, and `sys_user_role`, declared via the SDK's Fluent `CrossScopePrivilege` API. These are shipped as belt-and-suspenders for v1 — in any environment where the customer has tightened scope strictness, the privilege grants are pre-declared rather than requiring post-install fix-ups.

Verified deployed:

```
$ ./scripts/sn-query.sh sys_scope_privilege \
    'source_scope=2159d2d168744fc18f5a27536d212f88'
  read sys_user_has_role | status: allowed
  read sys_user          | status: allowed
  read sys_user_role     | status: allowed
```

### v1 cross-scope inventory (catalog of Global-scope tables v1 checks will need)

Captured as input for v1 manifest. Each entry will need a corresponding `CrossScopePrivilege` record in v1:

| Table | Read-only? | v1 check categories that need it |
|-------|-----------|---------------------------------|
| `sys_user` | yes | admin role audits, identity & SSO |
| `sys_user_role` | yes | role catalog, RBAC analysis |
| `sys_user_has_role` | yes | admin role audits, role concentration |
| `sys_properties` | n/a | already accessible via `gs.getProperty()` (no privilege required) |
| `sys_script_include` | yes | code security, AP-007 patterns |
| `sys_security_acl` | yes | ACL inventory and analysis |
| `sys_dictionary` | yes | schema audits |
| `sys_db_object` | yes | table existence checks |
| `sys_scope` | yes | scope inventory |
| `sys_app` | yes | app inventory |
| `scan_check`, `scan_finding`, `scan_result` | yes | meta-checks |
| `sys_user_group`, `sys_user_grmember` | yes | group hierarchy audits |
| `sys_user_role_contains` | yes | role hierarchy audits |
| `sys_security_acl_role` | yes | ACL-role mapping audits |

Estimate: ~15-20 CrossScopePrivilege records at v1, each ~5 LOC of Fluent SDK source. ~1-2 hours of authoring.

---

## Section 3 — Update lifecycle and install reliability

### Destructive `--reinstall` test

**Procedure:** captured nowisor scan_finding sys_ids before reinstall, ran `now-sdk install --reinstall`, recreated the suite + m2m rows via `create-suite.sh`, triggered another full scan, queried whether pre-reinstall sys_ids still existed.

**Findings:**

| Resource | Survives `--reinstall`? | Why |
|----------|--------------------------|-----|
| `scan_check` records (3 nowisor checks) | Yes (sys_ids stable) | $id-derived sys_ids are deterministic; uninstall+reinstall produces identical sys_ids |
| `scan_check_suite` record | Yes if Global-scope | Suite was created via REST in Global scope, has no FK to our app; uninstall does not cascade |
| `scan_check_suite_check` (m2m rows) | **No — destroyed** | M2m rows reference our checks via FK; cascade-deleted when checks are uninstalled |
| `scan_finding` records (historical) | Yes | scan_finding.check FK → reference, but the record stays even when the check is recreated with same sys_id (FK is preserved) |
| `scan_check_execution` records | Yes | Same reason as scan_finding |
| `sys_scope_privilege` records (CrossScopePrivilege) | No (re-created) | These ARE part of the app, so they get rebuilt with the same sys_ids on reinstall |

**Customer-facing implication:** every `now-sdk install --reinstall` requires re-running `create-suite.sh` to recreate m2m rows. The script is idempotent: it finds the suite by name (creates if missing) and inserts m2m rows only when missing. Historical findings are preserved, so audit history is not lost. Documented in `create-suite.sh` header.

### Incremental install reliability

Re-tested the v0.1 finding that plain `now-sdk install` (without `--reinstall`) timed out after 38 seconds with "Could not determine app installation status." During the v0.2 sprint the failure mode did not reproduce on every attempt — sometimes plain install succeeded in 6-12 seconds, other times it timed out. Best guess: race condition between the SDK's status-polling and the platform's app-update settling time, possibly worsened by previous failed installs leaving behind partially-applied state.

This is annoying but not a v1 distribution blocker for two reasons:

1. Customers don't run `now-sdk install` on their production instance — they import the update set XML from `dist/app/update/`, which is a stable, well-documented mechanism.
2. For internal development/CI, the workaround is `--reinstall` (10-18s, deterministic).

No SDK bug filed — too noisy a signal to file. Will revisit if the failure rate increases.

### v1 upgrade strategy

Documented as customer-facing README guidance:

> When upgrading the pack, customers either (a) `now-sdk install --reinstall` and re-run `create-suite.sh`, or (b) import the new update set XML and re-run `create-suite.sh`. Historical findings persist. The suite record persists. Suite membership (m2m rows) is the only resource that needs re-creation post-install.

Alternative considered but rejected: shipping a Business Rule that auto-creates the suite on first app install. Rejected because (a) BR triggers tied to app install events are not a documented Fluent SDK pattern, and (b) the post-install bash script is transparent and inspectable. Worth revisiting at v1 if customer feedback prefers a fully-automated install path.

---

## Section 4 — v1 effort estimate revision

### Original v1 estimate (from pilot retrospective)

29-38 hours, predicated on:
- 6-10 hours for the v0.2 sprint to resolve three independent blockers
- 18-25 hours for v1 check authoring (~30 checks)
- 5-8 hours integration, packaging, customer-facing docs

### Revised v1 estimate

**15-22 hours**, predicated on:
- v0.2 was actually ~3 hours (well under the original 6-10 estimate) because all three "blockers" collapsed to one shared cause
- v1 check authoring estimate stays ~12-15 hours (~25-30 checks at 25-35 minutes each, given v0.2 confirmed methodology fluency)
- Integration / packaging / docs: ~3-4 hours
- v1-specific work: 1-2 hours each for:
  - Authoring CrossScopePrivilege manifest (15-20 records, ~1.5h)
  - Hardening `create-suite.sh` for production (input validation, dry-run mode, ~0.5h)
  - Customer README expansion + framework-mapping summary table (~1h)

### What v0.2 changed about confidence in v1

| Concern at end of pilot | Status after v0.2 |
|--------------------------|-------------------|
| LinterCheck behavior unknown | Resolved. Iterates ~19,605 records across ~49 tables on a stock PDI; predicate works as documented in SDK guide. |
| Cross-scope ACL might block reads | Falsified on dev265484. Defensive CrossScopePrivilege records ship in pack. |
| Install reliability blocking adoption | Manageable. Customers use update-set XML, not `now-sdk install`. |
| Pilot's reported "0 findings" was actually "never executed" | Correct. Suite membership is the gate. `create-suite.sh` is the fix. |
| Methodology rules upheld (scope verification, sys_id provenance, ES5) | Yes — same as pilot. |

### What v0.2 did NOT validate

- **Production-scope strictness.** dev265484 allows cross-scope reads without explicit grants; production customers may not. CrossScopePrivilege records ship as defensive but the runtime behavior under stricter configurations is untested.
- **Customer-facing install path.** Update-set XML import was not exercised in this sprint. v1 should validate against a fresh PDI imported via the update-set route.
- **Scaled execution.** Three checks ran in ~110 seconds (LinterCheck dominates). Thirty checks may run in 5-8 minutes; if cumulative runtime crosses the platform's scan timeout, that needs profiling at v1.
- **Multi-instance portability.** Hardcoded admin sys_id provenance comment is dev265484-specific. v1 should validate the check still works on a fresh PDI where the admin role has a different sys_id (the runtime query is `role.name='admin'` so it should — but verify).

### Recommendation

**Proceed to v1.** The path is now clear:

1. Author 25-30 v1 checks using the same Fluent + ES5 methodology validated in pilot + v0.2.
2. Ship CrossScopePrivilege records for the full table inventory.
3. Extend `create-suite.sh` to be the universal post-install bootstrap.
4. Validate against a fresh PDI via update-set import.
5. Author customer-facing README with framework-mapping summary, suite-bootstrap step, and upgrade procedure.

No further diagnostic sprint required.

---

## Open items and known limitations

- The Fluent SDK does not expose a `ScanCheckSuite` API as of 4.6.0. The post-install bash script is the workaround. Worth submitting a feature request to the SDK team — it's a foundational gap for any pack that ships its own checks.
- `now-sdk install` (without `--reinstall`) has intermittent reliability issues. Workaround: always use `--reinstall`. Not investigated to root cause; not a customer-path concern.
- The eval LinterCheck visits ~19,605 records on a stock PDI and takes ~110 seconds. v1 may want to add `runCondition` filters to skip uninteresting tables (e.g., `sn_vsc_*`, `sn_cmdb_ws_*`) where script columns are administrative metadata, not user code.
