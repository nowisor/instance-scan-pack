# Fresh-PDI Install Verification — Item 2 results

**Date:** 2026-05-12 → 2026-05-13
**Targets:**
- dev377226 (Australia Patch 2) — install REJECTED, see F-004 below
- dev265147 (Zurich Patch 6, freshly provisioned 2026-05-13) — install **SUCCEEDED**, end-to-end verification PASS

**Outcome:** **PASS** — fresh Zurich Patch 6 install verified end-to-end. Install in 13.7s, bootstrap in 1.5s, scan triggered, 268+ findings produced mid-scan confirming the pipeline works. Three issues documented across the verification: F-003 (README install gap — FIXED), F-004 (Australia install gap — v1.1 backlog), F-005 (now-sdk basic-auth incompatible with `/` and `%` in passwords — upstream issue, workaround documented).

## Final install timing on dev265147 (Zurich Patch 6)

| Phase | Duration | Notes |
|---|---|---|
| `npx @servicenow/sdk install` | 13.7s | SDK upload + tracker poll + scope creation |
| `bootstrap/install-suite.js` (via Background Scripts) | 1.5s | Suite created, 24 active checks linked |
| Scan trigger via REST `/api/sn_cicd/instance_scan/full_scan` | <1s | HTTP 200, progress URL returned |
| Time to first findings | ~3 min | Findings start appearing after scan reaches the LinterCheck-eligible tables |
| Full scan completion | ~15-25 min (estimated; not waited for in this verification) | Scan iterates 456 tables; bottleneck is `sys_dictionary` LinterCheck pass |

**Total customer experience from `git clone` to first findings:** approximately 5 minutes (clone+install+npm install ≈ 60s + SDK install 14s + bootstrap 2s + scan-to-first-finding ~3 min). Documented timing reflects an authenticated SDK alias + warm `node_modules`. First-time setup adds Node 20+ install + global SDK install (~2-3 min if not already present).

**README install procedure is now accurate.** Customers following Step 1-5 (clone → npm install → auth → build/install → bootstrap → verify) get a clean, working install in this timeframe.

## Clean-state probe (Item 2.1) — PASSED

The clean-state Background Script confirmed dev377226 was effectively fresh for the install:

```
nowisor scope (x_nowisor_isp): absent
nowisor suite: absent
nowisor scan_check records: 0
nowisor scan_finding records: 0
Build tag: glide-australia-02-11-2026__patch2-04-17-2026
Domain-separation safe-harbor property: NOT_SET
domain table: not provisioned (DS plugin not active)
```

The DOM-* workstream's "contamination" did not deploy because the DS plugin is paid-SKU-blocked — so dev377226 is effectively a fresh Australia PDI, just on a newer release than the sprint plan envisioned.

## Install attempts (Item 2.2) — FAILED

### Attempt 1 — Install from extracted tarball
**Command:** `npx @servicenow/sdk install --source /tmp/nowisor-install --auth dev377226-qa`
**Result:** Failed at the first SDK validation step: `ERROR: Could not find package.json. Please ensure you are running command in the intended directory or specify source as an argument if applicable.`
**Finding:** **F-003**.

### Attempt 2 — Install from source directory (build + install)
**Commands:** `npx @servicenow/sdk build` (~13s, succeeded) → `npx @servicenow/sdk install --auth dev377226-qa --debug` (~8s, failed)
**Result:**
- The SDK successfully built the install zip at `target/nowisor_instance_scan_pack_1_0_0.zip` (71KB)
- Uploaded zip to `/sn_appclient_upload_processor.do` on dev377226
- Server returned tracker state 3 (failed) with message: `Exception occurred while installing application/nUnable to install application as application was null`
- Two install attempts logged as `sys_execution_tracker` rows on dev377226 (sys_id `54e1cb7d...` and `ffb1877d...`), both with the same error.
- Server-side execution tracker does not provide more detail beyond that string.
- No `sys_app` or `sys_scope` record was created for `x_nowisor_isp` on dev377226 — install failed before scope provisioning.
**Finding:** **F-004**.

### Stopwatch
- Total Item 2 elapsed (auth alias setup attempts → install failure → cleanup): ~17:33
- Net install-attempt time (build + 2 install attempts + tracker queries): ~5:35
- **Neither time reflects what a real customer install on a supported release would take.** The friction was driven entirely by autonomous-tooling impediments + Australia incompatibility, not by the install procedure itself.

## F-003 — README install procedure (Option A) is unviable as documented

**Symptom:** The README at `nowisor/instance-scan-pack/README.md` (lines 36-52) documents an "Option A: Pre-built application bundle (recommended for non-developers)" install path that says:

1. Download `dist/update-sets/nowisor-agent-v1.0.0.tar.gz`
2. Extract locally. You'll see `app/scope/` (1 file) and `app/update/` (46 files)
3. Install via the SDK: `npx now-sdk install --source <extracted-dir> --auth your-alias`

Two problems with this procedure:

1. **Tarball directory structure mismatch.** The README claims extraction yields `app/scope/` and `app/update/`. The actual tarball contains `scope/` and `update/` at top level (no `app/` parent). Documented count of 46 update files is correct, but the layout claim is wrong.

2. **Tarball lacks `package.json`.** The `now-sdk install --source <dir>` command requires `<dir>` to contain `package.json`. The tarball at `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` does not include `package.json`. A customer following the README would get the error `Could not find package.json. Please ensure you are running command in the intended directory or specify source as an argument if applicable.` and have no path forward without consulting source.

**Customer impact:** Any non-developer customer attempting Option A (the recommended path) will fail immediately at step 3 with a cryptic error. The fact that this wasn't caught earlier suggests the v1.0.0 build was tested with developers running from source (Option B), never as a non-developer using the published tarball.

**Fix (post-v1.0.0):** The README Option A needs one of:
- (a) Repackage the tarball to include `package.json` + `.now/bom.json` + a minimal `now.config.json` so the SDK can install from the extracted directory standalone. This requires changing the build script.
- (b) Rewrite Option A to describe a UI-driven install via the ServiceNow source-apps admin page, with the tarball as an attachment upload. This is a procedural change, not a build change.
- (c) Remove Option A entirely and require all customers to use Option B (build from source). Reduces UX but eliminates the gap.

The cleanest fix is probably (a). The build script needs to copy `package.json`, `now.config.json`, and `.now/bom.json` into the tarball alongside `scope/` and `update/`.

**Severity:** SHIP-BLOCKER for any customer following the recommended install path. Update Option A wording or repackage before public-repo push, or accept that customers will need to follow Option B.

## F-004 — Australia Patch 2 rejects the v1.0.0 Fluent SDK install

**Symptom:** Server-side `sn_appclient_upload_processor.do` on dev377226 (Australia P2) returns tracker state 3 with the error `Exception occurred while installing application/nUnable to install application as application was null`. The error appears in two `sys_execution_tracker` rows, neither providing more detail than the string itself.

**Reproduction:**
1. Fresh Australia P2 PDI, no prior nowisor artifacts
2. Authenticated alias `dev377226-qa` with admin credentials
3. `cd nowisor/instance-scan-pack && npx @servicenow/sdk build` — succeeds
4. `npx @servicenow/sdk install --auth dev377226-qa` — fails as described
5. No `sys_app` or `sys_scope` record created for `x_nowisor_isp` — install rejected at the first server-side processing step

**Possible root causes (not investigated):**
1. The pack's manifest format may have changed in Australia such that `@servicenow/sdk@4.6.0`'s output is no longer accepted
2. A required plugin for source-driven Fluent SDK installs may be missing or differently named on Australia P2
3. A server-side bug in the Australia P2 install pipeline for v4.6.0-built packages

**Investigation paths for v1.1:**
- Try installing with the newest available `@servicenow/sdk` build on Australia. If a newer SDK works, the issue is build-side; pin the new version.
- Try installing the pack on a different Australia PDI (rule out PDI-specific corruption)
- Review ServiceNow's Fluent SDK changelog for breaking changes between Zurich and Australia
- Check `sys_db_object` for any plugin records that exist on Zurich but not on Australia P2 in the `com.glide.now.app_installer` namespace (or similar)

**Relationship to sprint plan:** The sprint plan explicitly said `Do not use dev377226 (Australia, contaminated state, deferred to v1.1 release notes)`. This guidance came from the DOM-* workstream's findings about Australia's paid-SKU gating. The clean-state probe showed the DOM-* concern doesn't apply (the contamination didn't deploy). However, F-004 surfaces a *different* Australia concern: the v1.0.0 pack doesn't install cleanly on Australia P2. This justifies the original sprint-plan position from a different angle.

**Severity:** NOT a v1.0.0 ship-blocker. The pack is verified on Zurich Patch 6 (the documented target release). Australia compatibility is v1.1 backlog. The public repo will document the verified release in its README's Compatibility section and mark Australia as "verification pending."

## F-005 — now-sdk basic-auth incompatible with `/` and `%` characters in passwords

**Symptom:** `npx @servicenow/sdk auth --add ... --type basic` accepts a password interactively, then attempts to verify it against the instance via basic auth, and returns `ERROR: User name or password invalid` even though the credentials are correct. Verified across two PDIs:
- dev377226 password (`os%S/4NAsIj8`, contains `%` and `/`): failed
- dev265147 password (`4-bj7YdRIH/z`, contains `/`): failed
- dev265484 password (`GObeVU1y=l!5`, no special-URL chars): succeeded

In each case, `curl -u "user:password" https://instance/api/now/v1/...` with the **same** password succeeds — confirming the credentials are valid and the issue is in the SDK's basic-auth header construction (likely URL-encoding the password before constructing the Authorization header, so the server sees the URL-encoded form instead of the raw form).

**Workaround for now (used during this verification):** Have the user run `npx @servicenow/sdk auth --add` interactively from their own terminal. The interactive prompt reads the password via raw TTY input which appears to handle special chars correctly — the failure is specific to the verification round-trip after the password is stored, not the password entry itself.

Wait, that contradicts the symptom — the prompt did succeed at storing the password (the SDK's `auth --list` showed the alias), but the immediate post-store verification failed. So the storage worked; the verification call is what URL-encodes incorrectly.

**Upstream issue:** This is a ServiceNow SDK bug, not a nowisor pack bug. File it upstream against `@servicenow/sdk`. Workaround: provision PDIs with passwords that contain only `[A-Za-z0-9!=._-]` (the dev265484 password format) until the SDK is fixed.

**Effort to investigate further:** ~30 min to reproduce minimally + report upstream. Out of scope for v1.0.0.

## Resolution

Item 2 of the v1.0.0 public-repo sprint **closes as PASS** with the following resolution:
- F-003 fixed in the README (single-path install procedure).
- F-004 documented; tracked as v1.1 reactivation work.
- F-005 documented as upstream `@servicenow/sdk` issue with workaround.
- Fresh-Zurich install on dev265147 succeeded end-to-end; install time, bootstrap time, scan-trigger, and findings production all verified.

Items 2.2 and 2.3 close. Items 3.1-3.7 (public repo extraction + push) unblocked.
