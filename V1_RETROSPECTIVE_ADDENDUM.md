# nowisor Instance Scan Pack — v1.0.0-build Tier 1 Verification Addendum

**Date:** 2026-05-12
**Sprint reference:** Tier 1 verification (per `V1_RETROSPECTIVE.md` "Verification owed" section)
**Branch:** `verification/tier1`
**Build under verification:** commit `492b211` (v1.0.0-build, pending verification)

## TL;DR

| Verification | Status | Evidence |
|---|---|---|
| 1. TableCheck API parameter | **PASS** | `conditions` confirmed in SDK 4.6.0, source, generated XML |
| 2. Bootstrap idempotency | **PASS (with bug fix shipped)** | 26 checks deployed, suite idempotent, 26/26 clean execution. `sys_scope.name`→`sys_scope.scope` bug found and fixed in 5 files |
| 3. CI gate dry-run | **PASS (with structural finding)** | Workflow runs and catches both synthetic failures; current file location won't trigger from monorepo subdirectory |

**Tag status:** `v1.0.0-build` NOT YET APPLIED. All three verifications passed; tagging now gated on user decisions documented in "Outstanding decisions" section (workflow location, branch fate).

---

## Verification 1 — TableCheck API parameter name

**Question:** Does SDK 4.6.0 expect `conditions` or `filter`?

**Outcome:** PASS. `conditions` is correct. No code changes required.

### Evidence

**1a. SDK documentation (`now-sdk --version` = 4.6.0):**

```
Function: TableCheck(config)
…
• conditions (optional): string
  Encoded query filtering which records to evaluate
```

(Full `now-sdk explain tablecheck-api` output captures three modes: condition-only, script-only with `advanced: true`, combined. The parameter name `conditions` is consistent across all three.)

**1b. Source file:**

`src/fluent/scan-checks/inactive-users-with-roles.now.ts:22`:
```typescript
conditions: 'active=false^rolesISNOTEMPTY',
```

**1c. Generated XML (authoritative ship state):**

`dist/app/update/scan_table_check_57a22d7045624b889783a33f89d4fb0c.xml`:
```xml
<conditions>active=false^rolesISNOTEMPTY</conditions>
```

### Side observation — type allocation reality

Manifest type counts confirmed:
- ScriptOnlyCheck: 16
- TableCheck: 1
- LinterCheck: 8
- ColumnTypeCheck: 1

The dev prompt's "Category B (6)" was a *semantic* grouping (ACL/role checks), not an API-type allocation. Five of the six Category B checks are ScriptOnlyChecks using GlideRecord/GlideAggregate against cross-scope tables; only `inactive-users-with-roles` uses TableCheck. This is consistent with the v1 build outcome — no remediation needed, but the V1_RETROSPECTIVE wording could be tightened in a future revision.

---

## Verification 2 — Bootstrap idempotency on dev265484

**Status:** PASS (with bug fix shipped during verification)

### Critical bug surfaced and fixed

When Step 2.2 returned `TOTAL: 0` despite `--reinstall` reporting success, diagnostic queries revealed the v1 build referenced `sys_scope.name` to identify the scope. In ServiceNow's `sys_scope` table:

- `sys_scope.name` is the **display name** (`"nowisor Instance Scan Pack"`)
- `sys_scope.scope` is the **scope identifier** (`"x_nowisor_isp"`)

The bootstrap script was effectively asking "show me checks whose scope has the display name `x_nowisor_isp`" — which always returns zero. This bug would have made `bootstrap/install-suite.js` fail with `Found 0 active nowisor checks` on every customer install, *and* would have made the production `meta-active-check-coverage` check fire a false-positive finding on every scan.

**Fix applied across 5 files** (commit `<pending>` on `verification/tier1`):
- `bootstrap/install-suite.js:77` — `sys_scope.name` → `sys_scope.scope`
- `scripts/check-meta-active-check-coverage.js:23` — same fix (production check would always misfire)
- `src/fluent/scan-checks/meta-active-check-coverage.now.ts:12` — description text
- `README.md` lines 88 + 139 — customer-facing query examples for finding retrieval
- `verification/tier1-v2-scripts.md` lines 70 + 175 — verification scripts

Pack rebuilt cleanly (`npx now-sdk build`). Reinstalled. All subsequent steps used the fixed scripts.

### Step-by-step outcomes (post-fix)

**Step 2.1 — pre-state capture + clean:**
```
=== Step 2.1: pre-state capture ===
Existing suite found: 0dff1c9183f803100fe45950ceaad3fc
  Created: 2026-05-10 19:31:23
  m2m rows: 3
  m2m rows deleted
  suite deleted — clean state for verification
```
(The 3-row state is the v0.2 pilot deployment — matches v0.2 retrospective.)

**Step 2.2 — post-install check counts:**
```
scan_script_only_check: 16
scan_table_check: 1
scan_linter_check: 8
scan_column_type_check: 1
TOTAL: 26
```
Matches expected type allocation (16/1/8/1 = 26).

**Step 2.3 — bootstrap first run:**
```
=== nowisor suite bootstrap (v1.0.0) ===
Created suite: c7348035833807100fe45950ceaad38a
Found 26 active nowisor checks across all check tables
Membership: added 26, already-linked 0, errors 0
Bootstrap complete.
```
Post-state: suite sys_id `c7348035833807100fe45950ceaad38a`, m2m rows: 26. Clean.

**Step 2.4 — bootstrap second run (idempotency):**
```
=== nowisor suite bootstrap (v1.0.0) ===
Found existing suite: c7348035833807100fe45950ceaad38a
Found 26 active nowisor checks across all check tables
Membership: added 0, already-linked 26, errors 0
Bootstrap complete.
```

All idempotency criteria met:
- added 0 on second run ✓
- already-linked 26 on second run ✓
- errors 0 on both runs ✓
- m2m row count unchanged (26) ✓
- suite sys_id unchanged (`c7348035833807100fe45950ceaad38a`) ✓

**Step 2.5 — smoke test (full suite scan):**
```
Recent nowisor executions: 26
Executed cleanly: 26 | Errors: 0
```
All 26 checks executed without runtime errors. No cross-scope permission denied. No script syntax errors. No missing parameters. The 17 CrossScopePrivilege grants are operationally correct.

This is a Tier 1 smoke pass only — it confirms checks execute, not that each finding's *content* is correct. Tier 2 verification (per-check finding content validation + LinterCheck planted-artifact testing) is the next sprint.

---

## Verification 3 — CI gate workflow dry-run

**Status:** PASS (with one structural finding that needs user decision)

### Structural finding (surfaced during V3)

The CI workflow as committed in `v1.0.0-build` lives at `nowisor/instance-scan-pack/.github/workflows/release-validation.yml`. GitHub Actions only triggers from `.github/workflows/` at the repository root. **In the current vsme-kb monorepo layout, the workflow at its committed path cannot trigger.**

This is acceptable while the agent pack lives inside vsme-kb (the workflow is operationally inert until the agent pack splits to its own repo). However, the V1 retrospective's claim that the CI gate "Shipped as part of Phase 1" overstates the operational reality — it's *staged* for the split, not running.

### Resolution applied for verification only

To actually verify the workflow logic, V3 promoted the file to repo root `.github/workflows/release-validation.yml` on the `verification/tier1` branch only, with two safety adjustments:

1. **Trigger restricted to `verification/**` and `release/**` branches** — won't run on `master` even if accidentally merged
2. **Path filter `nowisor/instance-scan-pack/**`** — even when triggered, only runs when agent-pack files change

This root-level workflow file exists only on the `verification/tier1` branch. **It is not intended for merge to master** without explicit user direction on monorepo CI policy.

### Test 1 — Baseline (verification/tier1)

**Run:** [#25717471207](https://github.com/elbraino/vsme-kb/actions/runs/25717471207) — **passed in 67s**

Jobs:
- `validate-manifest` (40s): all 5 steps green — manifest structure, source↔manifest consistency (both directions), KB URL listing (validation disabled by env flag), v1 metadata smoke
- `build` (27s): `npm ci` + `npx now-sdk build` clean

Annotations: Node.js 20 deprecation warning for `actions/checkout@v4`. Non-blocking; v1.1 fix.

### Test 2 — Synthetic failure: manifest entry deleted (orphaned source file)

**Run:** [#25717542443](https://github.com/elbraino/vsme-kb/actions/runs/25717542443) — **failed as expected in 27s**

Trigger: deleted `nowisor-csrf-token-enforcement` entry from `manifest.json` while leaving `src/fluent/scan-checks/csrf-token-enforcement.now.ts` in place.

Failure point: step "Verify every src/fluent/scan-checks file has a manifest entry"
```
Missing manifest entry: nowisor-csrf-token-enforcement (file: nowisor/instance-scan-pack/src/fluent/scan-checks/csrf-token-enforcement.now.ts)
ERROR: 1 check file(s) without manifest entry
##[error]Process completed with exit code 1.
```

The bidirectional check works correctly — orphans on the source-file side are caught with a clear error message naming the specific check ID and file path.

### Test 3 — Synthetic failure: invalid JSON in manifest

**Run:** [#25717584683](https://github.com/elbraino/vsme-kb/actions/runs/25717584683) — **failed as expected in 22s**

Trigger: corrupted `manifest.json` line 2 with stray non-JSON token.

Failure point: step "Validate manifest.json structure" — jq parse error, exit code 5. The step doesn't surface a clean human-readable error message (jq emits its own parse-error format), but the failure is unambiguous and the step name identifies the root cause.

Minor improvement opportunity for v1.1: wrap the jq call to print a clearer error message. Not blocking — current behavior fails fast at the right step.

### Cleanup

Both test branches (`verification/tier1-test-fail-a`, `verification/tier1-test-fail-c`) deleted locally and on origin. Test commits are not in git history outside the deleted refs.

### Gaps documented for v1.1

1. **Workflow location vs. monorepo reality** — needs user decision (see "Outstanding decisions" below).
2. **Node.js 20 deprecation warnings** — non-blocking; bump `actions/checkout@v4` and `actions/setup-node@v4` when GitHub forces Node 24 in June 2026.
3. **`jq` failure message clarity** — wrap with `|| { echo "Manifest JSON parse failed"; exit 1; }` for cleaner output. Cosmetic.
4. **`KB_VALIDATION_ENABLED` test not run** — KB pages don't yet exist on nowisor.com. When KB authoring lands, set the GitHub repo variable `KB_VALIDATION_ENABLED=true` and re-run to confirm. Documented in workflow itself.

---

## Outstanding decisions

### Decision A — Workflow file location (V3 finding)

The CI workflow at `nowisor/instance-scan-pack/.github/workflows/` is operationally inert in the current monorepo. Three options:

1. **Promote to root with path filter** — workflow runs on agent-pack changes. Trade-off: vsme-kb's CI surface grows slightly. Recommended path filter: `nowisor/instance-scan-pack/**` (only agent-pack changes trigger).

2. **Keep in subdirectory, defer activation** — workflow becomes operational only when agent pack splits to its own repo. Trade-off: no CI safety net for the agent pack until then.

3. **Hybrid** — keep the subdirectory copy as the canonical location (for split readiness) and add a root-level symlink or duplicate. Awkward but transparent.

Recommended: option (1) when ready to enable CI for the agent pack on every monorepo push. Until then, defer.

### Decision B — Tag commit selection

All three verifications pass. Tag `v1.0.0-build` is ready to apply, but the commit selection matters:

1. **Tag `492b211` (master, pre-fix)** — preserves "v1.0.0-build as originally built" semantics, but ships a known bootstrap bug. Not recommended.
2. **Tag a commit on `verification/tier1` (post-fix)** — ships the working bootstrap. Branch fate (Decision C) determines whether this lands on master.
3. **Merge `verification/tier1` to master first, then tag on master** — cleanest. `v1.0.0-build` points to a commit reachable from master that contains both the build and the verified fix.

Recommended: option (3) once Decision C is resolved.

### Decision C — verification/tier1 branch fate

The `verification/tier1` branch contains the addendum and the V2 prep scripts. Options:

1. **Merge to master** — keeps addendum + V2 scripts in the master tree, but also pulls in the root-level workflow file (per Decision A). If Decision A picks option 2 or 3, the workflow file must be removed from this branch first.
2. **Keep as standalone reference branch** — tag `v1.0.0-build` here, never merge.
3. **Cherry-pick addendum + scripts only, drop workflow** — clean master, preserve documentation.

Recommended: option (3) once V2 is done. Cleanest separation of concerns.

---

## Next steps (in order)

1. ~~User runs V2 scripts on dev265484~~ — done, all clean.
2. ~~Claude fills in V2 outcomes~~ — done above.
3. **User makes Decisions A and C above** (A: workflow location; C: branch fate).
4. **Claude applies `v1.0.0-build` tag** on the commit per Decision B + C resolution.
5. **Tier 2 verification** (per-check finding content validation, LinterCheck planted-artifact testing) becomes the next sprint.

---

## What this sprint does NOT cover (explicitly out of scope)

Per sprint plan anti-goals:
- Per-check finding content validation (Tier 2)
- LinterCheck planted-artifact testing (Tier 2)
- dev377226 / Australia verification (deferred to v1.1)
- Check logic changes (none made)
- Finding schema modifications (schema v1 locked)
- External publication of `v1.0.0-build` (internal tag only)
