# nowisor Instance Scan Pack — v1.0.0 Retrospective

**Status:** build complete 2026-05-11; awaiting deployment verification on dev265484
**Target tag:** `v1.0.0-build` (not `v1.0.0` — reserved for actual launch with KB pages + advisor ready)
**Sprint reference:** `nowisor/V1_DEV_PROMPT.md`
**Strategic reference:** `nowisor/SCOPING_v1.md`

## Pack inventory at v1.0.0

26 checks (down from 28 specified in dev prompt). See "Deferred to v1.1" below for the 2 dropped + 1 renamed.

- Category A (property checks): 8 (`nowisor-csrf-token-enforcement`, `-session-timeout`, `-cookie-http-only`, `-cookie-secure`, `-secure-cookies`, `-rest-anonymous-access`, `-mfa-enforcement`, `-external-auth-policy`)
- Category B (ACL/role checks): 6
- Category C (LinterChecks): 8
- Category D (cross-cutting): 4

## Deferred to v1.1

The dev prompt's Category A inventory listed 10 property checks. Empirical verification against `nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json` (Zurich Patch 6, 3,585 properties) on 2026-05-11 surfaced three property-name discrepancies. The 2-evidence verification rule (CLAUDE.md) caught them before they shipped.

### 1. Session absolute lifetime audit (was `nowisor-session-absolute-max`)

**Why deferred:** The proposed property `glide.ui.session_timeout.max` does not exist in the Zurich Patch 6 baseline. The unsuffixed/`.max`-variant naming pattern from the dev prompt was incorrect; only `glide.ui.session_timeout` (idle timeout, already audited by `nowisor-session-timeout`) and a few namespace-prefixed variants (`glide.guest.session_timeout`, `glide.unauthorized.session_timeout`) exist.

**v1.1 plan:** Investigate the actual detection model for absolute session lifetime — likely involves session record TTL on `sys_user_session`, not a static property. May require a TableCheck against session records rather than a ScriptOnlyCheck against a property.

### 2. Build version exposure (was `nowisor-build-version-exposure`)

**Why deferred:** Property-comparison detection (the only mechanism available to a ScriptOnlyCheck) cannot detect the underlying attack surface. The actual exposure is build info appearing in HTTP responses, error pages, and login pages — observable only via HTTP response inspection. The proposed property names (`glide.buildtag`, `glide.buildname`) are also not in the Zurich baseline; only `glide.buildtag.last` and `glide.builddate.last` exist, and those track the last-applied patch metadata, not response-header exposure.

**v1.1 plan:** Requires a different detection model — either:
- An out-of-instance HTTP probe (separate from the in-instance scan pack)
- A check that audits known build-revealing endpoints (`/stats.do`, error pages) for response content patterns
- Document as a hardening-guide item rather than an automated check

### 3. REST basic-auth required (renamed to `nowisor-rest-anonymous-access`)

**Why renamed:** The proposed single property `glide.basicauth.required.rest` does not exist. The verified baseline has a family of granular per-processor properties: `glide.basicauth.required.api`, `.scriptedprocessor`, `.soap`, `.wsdl`, `.xsd`, `.databrokerrestapiprocessor`, `.unl`. The original check's intent — preventing anonymous access to REST and related processors — is better served by a multi-property audit that reports one finding listing every property in the family whose value isn't `true`.

**Action taken:** Renamed in manifest.json from `nowisor-rest-basic-auth-required` to `nowisor-rest-anonymous-access`. Evidence schema enumerates each audited property and its actual value. Framework mappings unchanged (NIS2 21.2.d, ISO 27001 A.5.16, DORA 9). Priority unchanged (1).

## Why this is the right outcome

The dev prompt was wrong on three property names. The 2-evidence verification rule from CLAUDE.md (PDI evidence + canonical docs reference) caught it before any check shipped. Shipping checks that reference fabricated property names would have generated silent-fail findings in customer instances and damaged advisor confidence — exactly the risk class the rule was written to prevent.

Pack total at 26 is still in the 25-30 scoping target range. The two dropped checks have clear v1.1 reactivation paths once their detection models are correctly scoped.

## Sprint hours (Claude-time, single session)

| Phase | Dev-prompt estimate | Claude actual | Notes |
|---|---|---|---|
| 1. Scaffolding | 1h | ✓ | manifest.json built as full 28-entry skeleton; revised to 26 mid-sprint after property-name verification |
| 2. CrossScopePrivilege | 2h | ✓ | 17 records authored (3 pilot + 14 new) |
| 3. Category A (8 checks) | 4h | ✓ | Revised from 10 (3 dropped/renamed). Subagent dispatched in parallel with 4, 5, 6 |
| 4. Category B (6 checks) | 3h | ✓ | TableCheck API verified via `now-sdk explain tablecheck-api` (uses `conditions` parameter) |
| 5. Category C (8 checks) | 6h | ✓ | AST API uncertainties documented in code comments (verification deferred to dev265484 planting) |
| 6. Category D (4 checks) | 2h | ✓ | ColumnTypeCheck binding `columnType: 'xml'` confirmed correct against SDK 4.6.0 .d.ts |
| 7. Suite bootstrap | 1h | ✓ | bootstrap/install-suite.js — idempotent, paste-and-run |
| 8. Customer README | 2h | ✓ | 243 lines (target was 300-500; reads tight) |
| 9. CI gate | 1h | ✓ | Shipped as part of Phase 1; KB URL validation behind `KB_VALIDATION_ENABLED` flag |
| 10. Update set XML | 0.5h | ✓ | `now-sdk build` succeeded; 46 per-record XMLs packaged as `nowisor-agent-v1.0.0.tar.gz` (34KB). Single-XML format deferred to v1.1 |
| 11. Retrospective | 0.5h | ✓ | This document |

## Verification owed (interactive, requires ServiceNow access)

The Claude-side sprint completed without dev265484 access. The following verifications are owed before the `v1.0.0-build` tag:

1. **Suite bootstrap dry-run.** Run `bootstrap/install-suite.js` against dev265484 (Background Script). Confirm: suite created, 26 checks linked, idempotent on re-run.
2. **Cross-scope privilege grants applied.** Confirm scan_check_execution doesn't surface "permission denied" errors against any of the 17 declared Global tables.
3. **Each check produces expected output.** Trigger a full scan; for each of the 26 checks, confirm either (a) a finding emitted with valid v1 metadata that parses via `JSON.parse()`, or (b) zero findings with the instance configured into the compliant state (documented in the retrospective).
4. **LinterCheck planted-artifact verification.** For the 8 LinterChecks, plant known-pattern Script Includes on dev265484, run the suite, confirm findings, delete planted artifacts. Per dev prompt anti-goal: "Delete all planted artifacts before sprint completion." This step has NOT yet run.
5. **CI gate dry-run.** Push the branch to GitHub; confirm the release-validation workflow passes (with `KB_VALIDATION_ENABLED=false` for now).

## Open questions / deferred

- Single-XML distribution format (vs. SDK-driven tarball). Customer demand signal needed before v1.1.
- LinterCheck AST predicate verification — some predicates ship with documented uncertainty (see `glide-record-vs-secure`, `direct-property-write`, `domain-separation-script-include` code comments). Each needs planted-artifact verification on dev265484.
- TableCheck API: subagent #4 used `conditions` parameter; if SDK 4.6.0 prefers `filter`, a one-line change is needed.
- ColumnTypeCheck `columnType: 'xml'`: confirmed in `node_modules/@servicenow/sdk-core/dist/instancescan/InstanceScan.d.ts` (literal type `'script' | 'xml' | 'html'`). No uncertainty.
- Australia (dev377226) property baseline: pack ships against Zurich-verified properties only. Australia GA verification owed for v1.1 release notes.

## v1.1 candidate backlog (surfaced during v1 build)

1. Session absolute lifetime audit (proper detection model)
2. Build version exposure (HTTP response inspection)
3. (additional candidates to be appended as authoring surfaces them)

## Sprint decisions log (cross-reference to dev prompt's decision authority table)

| Date | Decision | Authority class | Reasoning |
|---|---|---|---|
| 2026-05-11 | Drop `nowisor-session-absolute-max` | Stop-and-ask (de-facto check removal) | Property name not in verified baseline; user authorized the drop |
| 2026-05-11 | Rename `nowisor-rest-basic-auth-required` → `nowisor-rest-anonymous-access` | Stop-and-ask (de-facto check redefinition) | Single-property check substituted with multi-property family audit; user authorized rename |
| 2026-05-11 | Drop `nowisor-build-version-exposure` | Stop-and-ask (de-facto check removal) | Property-comparison can't reach the attack surface; user authorized the drop |

(Append additional decisions as the sprint progresses.)
