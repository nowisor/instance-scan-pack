# nowisor Instance Scan Pack — v1.0.0-build Tier 1 Verification Addendum

**Date:** 2026-05-12
**Sprint reference:** Tier 1 verification (per `V1_RETROSPECTIVE.md` "Verification owed" section)
**Branch:** `verification/tier1`
**Build under verification:** commit `492b211` (v1.0.0-build, pending verification)

## TL;DR

| Verification | Status | Evidence |
|---|---|---|
| 1. TableCheck API parameter | **PASS** | `conditions` confirmed in SDK 4.6.0, source, generated XML |
| 2. Bootstrap idempotency | **PENDING USER** | Scripts prepared at `verification/tier1-v2-scripts.md`, dev265484 access required |
| 3. CI gate dry-run | **PASS (with structural finding)** | Workflow runs and catches both synthetic failures; current file location won't trigger from monorepo subdirectory |

**Tag status:** `v1.0.0-build` NOT YET APPLIED. Gated on V2 completion + user decision on workflow-location finding (V3).

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

**Status:** PENDING USER EXECUTION

**Why pending:** This verification requires interactive Background Script execution on dev265484. Scripts have been prepared and staged at `verification/tier1-v2-scripts.md` for paste-and-run. Outcomes will be appended below once the user reports back.

### Scripts staged

The handoff document walks through five steps:

1. **Pre-state capture + clean** — captures any existing nowisor suite, deletes it for a true idempotency test
2. **Post-install check counts** — confirms `now-sdk install --reinstall` deployed all 26 checks across 4 tables (expected: 16/1/8/1 = 26)
3. **Bootstrap first run** — paste `bootstrap/install-suite.js`, expect `added 26, already-linked 0`
4. **Bootstrap second run (idempotency)** — paste same script, expect `added 0, already-linked 26`
5. **Smoke test** — trigger suite scan, confirm 26 execution records with zero or near-zero errors

### Expected outcomes block (to be filled in after user reports)

```
Step 2.1 outcome: [PENDING]
Step 2.2 totals: [PENDING]
Step 2.3 bootstrap first-run output: [PENDING]
Step 2.4 bootstrap second-run output: [PENDING]
Step 2.5 smoke test: executed N, errors M: [PENDING]

Idempotency criteria check:
- added 0 on second run: [ ]
- already-linked 26 on second run: [ ]
- errors 0 on both runs: [ ]
- m2m row count unchanged: [ ]
- suite sys_id unchanged: [ ]
```

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

### Decision B — Tag application timing

Per sprint plan: tag `v1.0.0-build` applied "to the resulting commit" if all three verifications pass. V1 and V3 pass; V2 is pending user execution. Two paths:

1. **Wait for V2 completion** — apply tag once user reports V2 outcomes and they're clean.
2. **Apply tag now if V2 expected to pass** — risky if V2 surfaces a real bootstrap issue.

Recommended: option (1). The bootstrap script has not yet been validated against the v1.0.0 build artifact on a real instance — `--reinstall` reliability and check-count expectations could surface anomalies that warrant a fix before tagging.

### Decision C — verification/tier1 branch fate

The `verification/tier1` branch contains the addendum and the V2 prep scripts. Options:

1. **Merge to master** — keeps addendum + V2 scripts in the master tree, but also pulls in the root-level workflow file (per Decision A). If Decision A picks option 2 or 3, the workflow file must be removed from this branch first.
2. **Keep as standalone reference branch** — tag `v1.0.0-build` here, never merge.
3. **Cherry-pick addendum + scripts only, drop workflow** — clean master, preserve documentation.

Recommended: option (3) once V2 is done. Cleanest separation of concerns.

---

## Next steps (in order)

1. User runs `verification/tier1-v2-scripts.md` against dev265484, reports outcomes.
2. Claude fills in V2 outcome block above. If clean, V2 marked PASS.
3. User makes Decisions A, B, C above.
4. If V2 passes and decision B is "apply tag": Claude tags `v1.0.0-build` on the agreed commit.
5. Tier 2 verification (per-check finding content validation, LinterCheck planted-artifact testing) becomes the next sprint.

---

## What this sprint does NOT cover (explicitly out of scope)

Per sprint plan anti-goals:
- Per-check finding content validation (Tier 2)
- LinterCheck planted-artifact testing (Tier 2)
- dev377226 / Australia verification (deferred to v1.1)
- Check logic changes (none made)
- Finding schema modifications (schema v1 locked)
- External publication of `v1.0.0-build` (internal tag only)
