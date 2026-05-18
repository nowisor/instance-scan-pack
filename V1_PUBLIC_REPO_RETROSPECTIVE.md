# v1.0.0 Public Repo — Sprint Retrospective

**Date:** 2026-05-12 → 2026-05-13
**Sprint:** Public repo split + verification gates
**Outcome:** Agent pack live as public open-source repository at [github.com/nowisor/instance-scan-pack](https://github.com/nowisor/instance-scan-pack)

## What shipped

A standalone public repository carrying the full v1.0.0 trajectory:

- 13 commits (pilot v0.1 → v0.2 → v1.0.0-build → tier-1 verification → tier-2 verification with four bugs fixed → kb-authoring → bundle test results → install-procedure fixes), preserved via `git filter-repo` from the originating monorepo.
- 5 release tags: `pilot-v0.1`, `pilot-v0.2`, `v1.0.0-build`, `v1.0.0-build-tier2`, `kb-v1.0.0-content`.
- Apache-2.0 license.
- CI gate (release-validation workflow) active and passing on `main`.
- Topics tagged for discoverability: `servicenow`, `security`, `nis2`, `dora`, `iso27001`, `compliance`, `instance-scan`, `fluent-sdk`.

## Item 1 — Background Script bundle test

24 verification scripts tested live on the v1.0.0-build verification instance (Zurich Patch 6 PDI).

**Result mix:** 21 PASS + 3 PASS-WITH-NOTE + 0 FAIL. Two of the 21 PASS outcomes required in-pass script rewrites (F-001, F-002).

**Two bugs found and fixed during the test pass:**

- **F-001 — `nowisor-session-timeout` paste-pipeline substitution hazard.** The script's companion-property output used `≤` (U+2264) and `<=` characters inside JS string literals. On at least one ServiceNow paste pipeline, these tripped Rhino's lexer with "unterminated string literal" errors. Diagnosis required four runs across two instances. Fix: rewrite the companion output to plain prose ("recommended max 15 minutes" / "recommended max 5 minutes"). Defensive rule logged: verification-script printed output should avoid operator symbols and non-ASCII in string literals because paste pipelines vary across instance variants.

- **F-002 — `nowisor-domain-separation-script-include` unguarded `GlideRecord('domain')`.** The verification script's informational "instance DS context" section unconditionally queried the `domain` table, which only exists when the domain-separation plugin is active (paid SKU). Fix: gate every `GlideRecord('domain')` call on `GlideTableDescriptor.isValid('domain')` with a graceful fallback advisory. Three substitutions across the bundle and the mirrored customer-facing KB page. The same plugin-existence pattern is the right hardening for N-001 (MFA-table accessibility wording).

**Three PASS-WITH-NOTE items logged for v1.1 polish:**

- **N-001** — `mfa-enforcement` catch-branch wording misdirects toward scope investigation when the actual issue is "plugin not active". 5-min fix in v1.1.
- **N-002** — `set-workflow-false-detector` and `glide-record-vs-secure` produce large unpartitioned findings dumps where the actionable signal (customer-authored code) is buried under OOB platform code. v1.1 should partition first-party from third-party. ~30 min per check.
- **N-003** — a small number of findings on `set-roles-detector` and `domain-separation-script-include` render with empty `source` display values. v1.1 should either fix upstream LinterCheck source resolution or substitute a sys_id fallback in the verification script.

**Methodology note:** the test ran in two modes — 14 scripts via interactive paste cadence on the verification instance, 11 scripts via an autonomous runner (POST to `/sys.scripts.do` with a parsed session cookie + CSRF token). The autonomous runner cleaned up after itself: scratch files lived in `/tmp` and were deleted on completion; credentials lived in environment variables only and were never written to disk or committed.

## Item 2 — Fresh-PDI install verification

**Outcome:** PASS after one false-start.

The sprint plan called for a fresh Zurich Patch 6 PDI. Two instances were tried:

- **First target (a contaminated Australia Patch 2 PDI from a prior workstream).** Clean-state probe confirmed no agent-pack artifacts had deployed (the prior workstream's plugin couldn't activate because of paid-SKU gating, so no scope/scan-check/finding records were created). Install proceeded but the server-side `sn_appclient_upload_processor.do` endpoint rejected the v1.0.0-built ZIP with `Exception occurred while installing application/nUnable to install application as application was null`. Two `sys_execution_tracker` rows landed on the instance, neither providing more detail. Root cause not investigated; logged as **F-004 — Australia install gap**, v1.1 reactivation work.

- **Second target (a freshly-provisioned Zurich Patch 6 PDI).** Install succeeded in well under a minute (SDK build → upload → scope creation → 26 checks installed, 24 active and 2 deferred). Suite bootstrap took seconds (24 checks linked to the suite). REST-triggered scan returned a progress URL in sub-second time. Findings began appearing within a few minutes; hundreds of nowisor findings produced mid-scan confirmed the pipeline works end-to-end. Total `git clone` → first-findings time approximately 5 minutes for an authenticated SDK alias with a warm `node_modules`.

**A README install gap was surfaced in the process:**

- **F-003 — README Option A was unviable as written.** The pre-fix README documented "Option A: Pre-built application bundle (recommended for non-developers)" with instructions to extract `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` and run `now-sdk install --source <extracted-dir>`. Two problems: the tarball's actual layout (`scope/`, `update/` at top level) did not match the README's claim (`app/scope/`, `app/update/`); and more critically, the tarball lacked `package.json`, so the SDK install rejected the extracted directory at the first validation step. The fix consolidated the install procedure to a single Step 1-5 path: clone → npm install → auth → build → install → bootstrap → verify. The pre-built tarball was redesignated as a build-output artifact rather than a standalone installer, with a note that pure-UI install is on the v1.1 roadmap.

**A third issue surfaced too:**

- **F-005 — `@servicenow/sdk` basic-auth interoperability with `/` and `%` in passwords.** The SDK's `auth --add` command verifies credentials against the instance immediately after storing them, and the verification call returns "username or password invalid" when the password contains `/` or `%`. The same credentials work correctly via curl's basic auth, so the underlying issue appears to be in how the SDK constructs the Authorization header (working hypothesis: the password is being URL-encoded before the header is built, so the server sees a different value than the user typed). We observed this across two PDIs whose auto-generated admin passwords contained those characters. We will reproduce minimally and open a report with the SDK team. The agent itself is not affected — this is a CLI-side authentication issue, not a runtime issue. Workaround for customers: reset the PDI password via the developer portal to one within `[A-Za-z0-9!=._-]` before configuring the SDK alias.

## Item 3 — Public repo split

History extracted via `git filter-repo --path nowisor/instance-scan-pack/ --path-rename nowisor/instance-scan-pack/:`, preserving 13 trajectory commits and (after re-tagging) 5 release tags.

A second `git filter-repo --message-callback` pass scrubbed instance-specific identifiers from sprint-era commit messages — substituting role-based names (`test-instance-A`, `test-instance-B`, `test-instance-C`) for the PDI URLs, generalizing specific timing and finding-count values to qualitative descriptions. The matching scrub was applied to the two QA artifact files (`docs/qa/bundle-test-results.md` and `docs/qa/pdi-install-verification.md`) on top of the filter-repo work.

After the public push completed and the sprint was nominally closed, a follow-up cleanup pass reorganized the repo root: the build-trajectory retrospectives (`PILOT_RETROSPECTIVE.md`, `V0_2_RETROSPECTIVE.md`, `V1_RETROSPECTIVE.md`, `V1_RETROSPECTIVE_TIER2.md`) moved to `docs/retrospectives/`; the QA artifacts moved from the original `kb-authoring/qa/` location to `docs/qa/`; the `V1_RETROSPECTIVE_ADDENDUM.md` file was removed because it contained dead links to the originating monorepo's private CI runs; and the truly-internal `kb-authoring/BACKLOG.md` and `kb-authoring/coverage-audit.md` files (which referenced monorepo-relative paths that don't exist publicly) were also removed. The result is an install-focused root (`README`, `LICENSE`, `manifest.json`, `package.json`, `src/`, `bootstrap/`, `scripts/`) with all methodology evidence still present and reachable under `docs/`.

The CI gate workflow at `.github/workflows/release-validation.yml` originally referenced monorepo-relative paths (`nowisor/instance-scan-pack/manifest.json`). The first CI run after public push failed at the manifest validation step. A follow-up commit (`ci: rewrite paths for standalone repo`) stripped the monorepo prefix from every path reference and removed the `defaults.run.working-directory` line; the second CI run passed in under a minute.

Repo was created via `gh repo create`, pulled the initial Apache-2.0 LICENSE commit as the base, and the local extracted history was rebased on top with `git pull --rebase --allow-unrelated-histories`. Tags were updated to point at the rebased commits (rebase preserves history content but not commit SHAs).

## What this milestone represents

The agent pack is now live in the disciplined sense:

- All 24 verification scripts tested on a live instance, with two real bugs fixed in-pass.
- Install procedure validated end-to-end on a freshly-provisioned PDI, with one README gap and two upstream/release-compat issues documented.
- Public repository exists with full project history preserved.
- CI gate operates as designed (manifest validation, source-to-manifest consistency, optional KB URL validation gated behind a repo variable).
- Zero unresolved script-level defects against the documented target release.

## Trajectory recap

This sprint closes a multi-step trajectory:

1. **Pilot** (3 checks proof-of-concept, v0.1)
2. **v0.2** (suite-bootstrap fix, the first paid-down debt against the discovery that Fluent SDK 4.6.0 does not expose a `ScanCheckSuite` API)
3. **v1.0.0 build** (26 checks built — 8 platform-property, 6 ACL/role, 6 AST-based code analysis at the time of build with two more added later, 4 cross-cutting)
4. **Tier 1 verification** (build mechanics validated against the live instance)
5. **Tier 2 verification** (per-check content validated; 4 bugs caught and fixed in-pass, 2 checks deferred to v1.1 for predicate-shape rework)
6. **KB authoring** (26 customer-facing pages produced for the project's documentation surface)
7. **Public repo** (this sprint)

Methodology lessons across the trajectory are documented in the
preserved retrospective files in this repository.

## v1.1 backlog (carried forward from this sprint)

- Reactivate `nowisor-hardcoded-credentials` (AST predicate redesign — current predicate matches LITERAL node values alone, but `var password = '...'` splits the assignment into NAME + OP + LITERAL nodes that the LITERAL alone never contains the labelled-assignment shape).
- Reactivate `nowisor-direct-property-write` (AST anchor investigation — predicate produced zero findings against the planted test artifact in Tier 2 verification).
- Investigate F-004 — Australia Patch 2 install rejection. Try the install with a newer `@servicenow/sdk` build; review ServiceNow's Fluent SDK changelog between Zurich and Australia; check for plugin-state differences between the two releases.
- Reproduce F-005 minimally and report to the `@servicenow/sdk` team (basic-auth password handling).
- Apply N-001 (`mfa-enforcement` catch-branch wording), N-002 (set-workflow + glide-record-vs-secure OOB-vs-customer partition), N-003 (empty-source-display fallback) from the bundle test results.
- Cookie cluster hardening: `glide.cookies.samesite` was found `NOT_REGISTERED` on the Zurich Patch 6 default; recommend the customer set this property.
- **Turnkey installer workstream (8–16h estimate).** Build a single Customer Update Set XML wrapping the 47 per-record XMLs as `sys_update_xml` children under a `sys_remote_update_set` envelope, so customers can install via *Retrieved Update Sets → Import Update Set from XML* with no local Node + SDK toolchain. Requires: (a) a packaging script that consumes the SDK's `target/*.zip` and emits the wrapping XML; (b) install verification on a clean PDI via the UI path; (c) update README install procedure to surface the new path as primary, demoting clone-source to "build from source / contributor path".
- **Canonical release-artifact pipeline (part of the same workstream).** Today's release pipeline produced two different artifacts at two different SHAs — `dist/update-sets/nowisor-agent-v1.0.0.tar.gz` (built 2026-05-12, predates Tier 2 fixes) vs. `target/nowisor_instance_scan_pack_1_0_0.zip` (built 2026-05-13 at the tag SHA). The v1.0.0-build-tier2 release attaches the tag-matching artifact, but the in-repo `dist/` path needed manual rebuild. v1.1 should make `npm run release:build` (or equivalent) idempotently produce a single canonical artifact matching the tag SHA, gated by CI on push of any `v*` tag.

## Next

The agent pack is live as open source. The next workstream is launch coordination (announcement, marketing alignment, advisor product cross-reference review) — a separate sprint with separate decision authority.

The trajectory closes.
