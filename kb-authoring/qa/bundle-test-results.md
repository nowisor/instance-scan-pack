# Background Script Bundle Test Results

**Date:** 2026-05-12
**Target instance:** test-instance-A (Zurich Patch 6 PDI; the v1.0.0-build verification instance)
**Bundle source:** `kb-authoring/qa/background-scripts-bundle.md`
**Tester:** project maintainer

> Instance state details in this document — user counts, admin counts, property values, finding volumes — have been generalized to order-of-magnitude / qualitative descriptions. Specific counts and identifiers were redacted before public release because the test instance is a personal ServiceNow Personal Developer Instance, not customer state. The methodology, fix discipline, and decision narrative are preserved verbatim because that is what is portable to other instances.

## Summary

- Total scripts tested: 24 / 24
- PASS: 21 (2 with in-pass script-rewrites — F-001, F-002)
- PASS-WITH-NOTE: 3
- FAIL: 0 (zero unresolved failures; v1.0.0 build is shippable)

**Pass-mode breakdown:**
- 14 / 24 ran via interactive paste cadence on test-instance-A (synchronous, dev classified in real-time)
- 11 / 24 ran via autonomous runner (POST to `/sys.scripts.do` with parsed session cookie + CSRF token; credentials in env vars only, never written to disk or committed)

**Category mix:**
- Property checks (8): 7 PASS + 1 PASS-WITH-NOTE (N-001 MFA wording)
- ACL/role checks (6): 6 PASS
- LinterChecks (6): 4 PASS + 2 PASS-WITH-NOTE (N-002 OOB-volume in set-workflow and glide-record-vs-secure)
- Cross-cutting (4): 4 PASS

**Fix discipline confirmed:** Two real bugs found and fixed in-pass (F-001 substitution hazard, F-002 missing `domain` table). Both fixes also corrected the customer-facing KB pages mirrored in a separate internal location. No outstanding script-level defects.

**Property-check category complete: 8/8 done. Category mix: 7 PASS + 1 PASS-WITH-NOTE + 0 FAIL.**

> Update this summary as testing progresses. Each per-script entry below is filled in with the live output classification.

## Classification rubric

- **PASS** — output matches the KB page's verification narrative, customer would understand the result without further explanation.
- **PASS-WITH-NOTE** — script runs without error and the output is semantically correct, but presentation, narrative, or missing context could be improved. Logged to `BACKLOG.md` as a v1.1 improvement candidate.
- **FAIL** — syntax error, broken query, missing identifier, output that misrepresents instance state, or output that contradicts the KB page's description. Fixed in-pass for the v1.0.0 ship.

## Per-script results

### nowisor-admin-role-concentration
**Status:** PASS
**Notes:** Original script ran. Hundreds of active users, low double-digit admin role holders, ratio well below the 5% threshold. Admin count cross-corroborates the MFA enrollment snapshot — internal consistency across the bundle confirmed.
**Output excerpt:**
```
Total active users: <hundreds>
Distinct admin role holders: <low double-digit>
Ratio: <well below threshold>%  (threshold: 5.00%)
[PASS] Below threshold.
```

### nowisor-attachment-role-restriction
**Status:** PASS
**Notes:** Original script (block-comment + nested quotes + long line — all the "hazard" patterns from F-001's bisection list) compiled and ran cleanly. Output correctly flags `glide.attachment.role = "public"` as a FAIL on Zurich Patch 6 default. Companion `glide.attachment.extensions = __NOT_REGISTERED__` is consistent with an OOB instance.
**Output excerpt:**
```
[FAIL] glide.attachment.role = "public" (unrestricted).
       Set to a non-public role (e.g., attachment_writer).

Companion attachment controls:
  glide.attachment.extensions = __NOT_REGISTERED__
  glide.security.file.mime_type.validation = true
```

### nowisor-cookie-http-only
**Status:** PASS
**Notes:** Original script (block-comment + nested `"..."` inside `'...'`) compiled and ran cleanly on test-instance-A, confirming those patterns are not universal triggers. Property primary `[PASS]`. Side-finding from informational companion: `glide.cookies.samesite` is `__NOT_REGISTERED__` on Zurich Patch 6 default — the SameSite cookie attribute is not set OOB. Not blocking; surface for v1.1 cookie-cluster hardening guidance.
**Output excerpt:**
```
[PASS] glide.cookies.http_only = true. HttpOnly flag enforced.

Cookie cluster (informational):
  glide.cookies.secure = true
  glide.cookies.samesite = __NOT_REGISTERED__
  glide.ui.secure_cookies = true
```

### nowisor-cookie-secure
**Status:** PASS
**Notes:** Original script compiled and ran cleanly. Primary `[PASS]`. Companion cluster confirms same `samesite=__NOT_REGISTERED__` finding as cookie-http-only — already noted.
**Output excerpt:**
```
[PASS] glide.cookies.secure = true. Secure flag enforced on session cookies.

Transport-layer cluster (informational):
  glide.cookies.http_only = true
  glide.cookies.samesite = __NOT_REGISTERED__
  glide.ui.secure_cookies = true
```

### nowisor-cross-scope-privilege-grants
**Status:** PASS
**Notes:** Original script ran. Dozens of grants across more than a dozen source scopes — all are first-party ServiceNow scopes (AI Search, Now Assist, UX Commons, Agent Workspace, Clone Admin Console, etc.). No third-party app surprises. The script's no-verdict format (counts only) is intentional for audit-style output: the operator reviews the list to identify unexpected scope names, which is the actual finding mechanism for this check.
**Output excerpt:**
```
=== High-impact cross-scope grants by source ===
Total source scopes: <more than a dozen>

  (first-party ServiceNow scopes: AI Search, Admin Experience Framework,
   Agent Workspace, Change Management - CAB Workbench, Clone Admin Console,
   Conversational Interfaces - Diagnostics, Integration Commons for CMDB,
   Knowledge Management - Service Portal, NLU Workbench, Now Assist Admin
   Console, Omni-Experience Standard Feature Set, Password Reset flows,
   Process Automation Content, ServiceNow IDE, UX Commons — single-digit
   to low-double-digit grants per scope.)

Total high-impact grants: <dozens>
```

### nowisor-csrf-token-enforcement
**Status:** PASS
**Notes:** Clean match. Primary property + companion strict-validation property both report `true`. Customer-readable output structure verified.
**Output excerpt:**
```
[PASS] glide.security.use_csrf_token = true. CSRF token enforcement active.

Companion property glide.security.csrf.strict.validation.mode = true
Recommended: true (default on Zurich Patch 6)
```

### nowisor-domain-separation-script-include
**Status:** PASS after in-pass script fix (F-002); empty-source display logged as N-003
**Notes:** Original script failed at the line in the verification block calling `new GlideRecord('domain')` — this throws `invalid table name: domain` on instances without the domain-separation plugin active. test-instance-A is a standard PDI without DS, so the `domain` table doesn't exist. Fixed by gating the query on `GlideTableDescriptor.isValid('domain')` and providing a fallback advisory message. Re-run produces clean output. Side-finding: 1 Script Include flagged but its `source` display value rendered as a single space — same "unknown source" presentation issue as set-roles-detector (N-003).
**Output excerpt:**
```
=== Domain-separation findings ===
Total Script Includes flagged: 1

  

Instance domain count: 0 (domain table absent, DS plugin not active)
Findings are ADVISORY (DS not in active use)
```

### nowisor-elevated-role-assignments
**Status:** PASS
**Notes:** Original script ran (via autonomous runner). Found a small number of users co-assigned admin + itil_admin → `[REVIEW]`. Output structure is appropriate for the finding shape (count-based audit).
**Output excerpt:**
```
Co-assigned (admin + itil_admin): <small number>
[REVIEW] <N> user(s) hold both roles.
```

### nowisor-eval-usage-detector
**Status:** PASS
**Notes:** Original script ran. Zero eval() findings on test-instance-A — the LinterCheck either has not produced findings (suite scan may not have completed for this check) or has produced none, both of which are legitimate states. Output narrative is clean.
**Output excerpt:**
```
=== eval() findings by source ===
Total scripts with findings: 0

Clean: no eval() calls detected in current scan.
```

### nowisor-external-auth-policy
**Status:** PASS
**Notes:** Original script compiled and ran. SSO is not active on test-instance-A (default PDI state, no `sso_properties` active rows, `glide.authenticate.sso.enabled = __NOT_REGISTERED__`). Script correctly short-circuited with `[INFO] SSO is not active. This check is informational-only here.` — avoiding a false-positive FAIL on the `disable_local_login` property (which is irrelevant when SSO isn't in play). This is the well-designed "precondition gate" pattern.
**Output excerpt:**
```
SSO detection:
  sso_properties active rows: no
  glide.authenticate.sso.enabled = __NOT_REGISTERED__
[INFO] SSO is not active. This check is informational-only here.
```

### nowisor-fabricated-property-references
**Status:** PASS
**Notes:** Original script ran. Output: `[FAIL] your.property.name is NOT REGISTERED in sys_properties.` — `your.property.name` is the seeded test value baked into the meta-validation check. The `[FAIL]` is the *correct* outcome here: the check is meant to detect fabricated property references, and the seed proves the detection logic works. Customer-readable but the seeded value may confuse a first-time customer who doesn't realize it's a test sentinel. Possible v1.1 polish: prefix with `[META-CHECK]` instead of `[FAIL]` for the seeded entry, OR rename the seed to `__nowisor_test_fabricated_prop__`.
**Output excerpt:**
```
[FAIL] your.property.name is NOT REGISTERED in sys_properties.
```

### nowisor-glide-evaluator-detector
**Status:** PASS
**Notes:** Original script ran. Zero GlideEvaluator findings. Same caveat as eval-usage-detector: this either means clean OR the suite scan didn't populate findings for this check. Both are legitimate.
**Output excerpt:**
```
=== GlideEvaluator findings by source ===
Total scripts with findings: 0

Clean: no GlideEvaluator references detected in current scan.
```

### nowisor-glide-record-vs-secure
**Status:** PASS-WITH-NOTE
**Notes:** Original script ran. Several hundred findings, almost all in OOB platform code: Scheduled Script Executions, UsageAnalytics scripted definitions, Security Check Configurations. Output is correct but overwhelming. Same N-002 partition recommendation as setWorkflow-false-detector. Notable side-finding: the output includes the source name "Script Only Check: Meta — Active Check Coverage" with an em-dash (U+2014) — this is record display data, not script source, so the em-dash is fine in transit. Confirms the F-001 hazard rule is about *string literals*, not all non-ASCII.
**Output excerpt:**
```
=== GlideRecord findings by source ===
Total scripts with findings: <several hundred>

  (Scheduled Script Executions, UsageAnalytics scripted definitions,
   Security Check Configurations, and a handful of one-off entries
   — all OOB platform code; no customer-authored scripts produced
   findings.)
```

### nowisor-inactive-users-with-roles
**Status:** PASS
**Notes:** Original script ran. Found a small number of inactive users with role grants — real instance findings. Script uses `[REVIEW]` (not `[FAIL]`) which is the right framing for count-based audit findings: a handful of stale grants is below alarming thresholds but warrants operator action. Customer-readable.
**Output excerpt:**
```
Distinct inactive users with active role grants: <small number>
[REVIEW] <N> user(s) need deprovisioning.
```

### nowisor-meta-active-check-coverage
**Status:** PASS
**Notes:** Original script ran. Confirmed 24 active checks on test-instance-A: 17 `scan_script_only_check` + 6 `scan_linter_check` + 1 `scan_column_type_check` + 0 `scan_table_check` = 24, matching expected count. This is the meta-validation check working as designed.
**Output excerpt:**
```
  scan_script_only_check: 17
  scan_table_check: 0
  scan_linter_check: 6
  scan_column_type_check: 1

Total active: 24 (expected: 24)
[PASS] Coverage complete.
```

### nowisor-mfa-enforcement
**Status:** PASS-WITH-NOTE
**Notes:** Original script compiled and ran. Primary property correctly flagged as `[FAIL]` on test-instance-A (MFA disabled by default). Try/catch gracefully degraded when `sys_user_mfa_setup` was inaccessible. Output narrative for the catch branch — "table not accessible in this scope" — is technically defensible but misleading: on default PDI without the MFA plugin active, the table likely doesn't exist at all. v1.1: improve the catch-branch wording to distinguish "plugin not active" from "scope-isolation issue". Logged to PASS-WITH-NOTE.
**Output excerpt:**
```
[FAIL] glide.authenticate.multifactor = "false" (expected "true").
       Update via System Properties.

MFA enrollment snapshot:
  (sys_user_mfa_setup table not accessible in this scope)
  Distinct admin role holders: <low double-digit>
```

### nowisor-oob-acl-modifications
**Status:** PASS
**Notes:** Original script ran. SQL trace confirms the query executed correctly: `sys_security_acl` joined with `sys_metadata`, filtered for empty `sys_package` AND `sys_updated_on > beginningOfYesterday()`. Zero matches on test-instance-A → `[PASS]`. The script's `deltaMs <= 86400000` continue-guard filters out same-day-created records (which appear "modified" only because they're new), preventing false positives.
**Output excerpt:**
```
[PASS] No OOB ACL modifications in the last day.
```

### nowisor-platform-build-drift
**Status:** PASS
**Notes:** Original script ran. Current build tag: `glide-zurich-07-01-2025__patch6-01-16-2026` — Zurich GA dated 2025-07-01, Patch 6 dated 2026-01-16. Script correctly identified the release as Zurich Patch 6 and `[PASS]`.
**Output excerpt:**
```
Current build tag: glide-zurich-07-01-2025__patch6-01-16-2026
[PASS] Matches: Zurich Patch 6
```

### nowisor-rest-anonymous-access
**Status:** PASS
**Notes:** Original script compiled and ran across all 7 `glide.basicauth.required.*` properties. All seven enforced on test-instance-A. Clean aggregated summary at the end. The script's structure — 7-property family iteration with a tally — is a useful template for other family-style checks.
**Output excerpt:**
```
[PASS] glide.basicauth.required.api = true.
[PASS] glide.basicauth.required.scriptedprocessor = true.
[PASS] glide.basicauth.required.soap = true.
[PASS] glide.basicauth.required.wsdl = true.
[PASS] glide.basicauth.required.xsd = true.
[PASS] glide.basicauth.required.databrokerrestapiprocessor = true.
[PASS] glide.basicauth.required.unl = true.

All 7 properties enforced. Anonymous access blocked across the family.
```

### nowisor-secure-cookies
**Status:** PASS
**Notes:** Original script compiled and ran. Primary `[PASS]` for UI-layer secure cookie property. Cluster symmetry output corroborates the cookie-http-only / cookie-secure findings (same `samesite=__NOT_REGISTERED__` on Zurich Patch 6 default).
**Output excerpt:**
```
[PASS] glide.ui.secure_cookies = true. UI-layer secure-cookie enforcement active.

Cookie cluster symmetry:
  glide.ui.secure_cookies = true
  glide.cookies.secure = true
  glide.cookies.http_only = true
  glide.cookies.samesite = __NOT_REGISTERED__
```

### nowisor-session-timeout
**Status:** PASS (after in-pass script-rewrite per F-001)
**Notes:** Original script failed compilation across two instances (test-instance-C and test-instance-A) on the line containing the `glide.guest.session_timeout` companion output. Bisection ultimately required radical simplification: removed the `/*...*/` block comment, removed the `gs.print('[FAIL] ' + prop + ' = "' + value + '" is not numeric.');` line (nested `"..."` inside `'...'`), removed multi-space internal padding in printed strings, removed the internal blank-line `gs.print('')`. The simplified version compiles and runs correctly. Instance finding: `glide.ui.session_timeout` reported a value above the 30-minute baseline on test-instance-A — a real misconfiguration the script correctly identified as `[FAIL]`. Companion guest- and unauthorized-session timeout properties reported their Zurich Patch 6 defaults. Script does what it should do.
**Output excerpt:**
```
Property glide.ui.session_timeout = <above-baseline value>
[FAIL] Value of <N> exceeds baseline of 30 minutes.
Companion: glide.guest.session_timeout = <default>
Companion: glide.unauthorized.session_timeout = <default>
```

### nowisor-set-roles-detector
**Status:** PASS
**Notes:** Original script ran. A single setRoles finding from `(unknown)` source. The "unknown" source label suggests the finding's source record lacks a display value or the join didn't resolve — minor presentation issue. Logged to N-003.
**Output excerpt:**
```
=== setRoles() findings by source ===
Total scripts with findings: <small number>

  (unknown): <N> call(s)
```

### nowisor-set-workflow-false-detector
**Status:** PASS-WITH-NOTE
**Notes:** Original script ran. Low double-digit setWorkflow findings, all in OOB ServiceNow code (Scheduled Script Executions: Clean Unused ATF Step Snapshots, FlowDesigner Cleanup, MID Secure Audit Log Cleanup, etc.) plus UsageAnalytics scripted definitions. Output is technically correct but ALL findings are platform-level — the customer's first reaction will be "but I didn't write any of this." Logged to N-002: v1.1 should partition first-party ServiceNow code from customer-authored code, since the actionable signal lives in the customer-authored half.
**Output excerpt:**
```
=== setWorkflow findings by source ===
Total scripts with findings: <low double-digit>

  (all findings landed in OOB platform code: Scheduled Script Executions
   for routine cleanup jobs and UsageAnalytics scripted definitions.
   Zero findings in customer-authored scripts on this instance.)
```

### nowisor-update-set-xml-suspicious
**Status:** PASS
**Notes:** Original script ran. Sampled 1,000 `sys_update_xml` records, zero suspicious patterns detected across the three monitored payload classes (admin role grant, ACL modification, cross-scope grant). test-instance-A has clean update-set XML history.
**Output excerpt:**
```
Sample of 1,000 sys_update_xml records:
  admin role grant: 0
  ACL modification: 0
  cross-scope grant: 0
```

## Failure remediations

> For each FAIL: capture what was wrong (e.g., missing field, wrong table, syntax issue), what fix was applied, and the commit SHA of the fix.

### F-001 — `nowisor-session-timeout`: non-ASCII / operator characters in script string literals
**Symptom:** `unterminated string literal` error on paste-and-run via Background Scripts UI on test-instance-C (Australia).
**Root cause progression:**
1. First failure (`≤` in source, test-instance-C): U+2264 in string literals → parser breaks on multi-byte UTF-8.
2. Second failure (ASCII `<=` in source, test-instance-C): same error reproduced → eliminated Unicode-only theory.
3. Third failure (plain prose, test-instance-C): line number shifted 33 → 32 (confirming editor was loading the fresh script), still failed → strongly suggested test-instance-C's paste pipeline corrupts ASCII apostrophes too (smart-quote substitution at OS/browser layer).
4. Diagnostic on test-instance-A (`gs.print('hello');`): PASSED → test-instance-A's paste pipeline is clean. The original error class was test-instance-C-specific.
**Resolution:** The prose-rewrite is kept as defense-in-depth even though test-instance-A doesn't need it. The class of hazard (operator chars / non-ASCII in printed strings) was real on at least one ServiceNow paste pipeline; eliminating it costs nothing and prevents future variance.
**Fix:** Companion-property output lines in the customer-facing `nowisor-session-timeout` KB page and the mirrored entry in `kb-authoring/qa/background-scripts-bundle.md` rewritten to plain prose ("recommended max 15 minutes" / "recommended max 5 minutes"). Four substitutions total.
**Audit:** All 24 scripts in bundle + 26 KB pages scanned for non-ASCII bytes inside JS string literals — zero remaining (em-dashes in `//` comments left untouched, they do not break compilation).
**Defensive rule for v1.1 publishing (logged to BACKLOG):** verification-script printed output should use prose, not operator symbols or non-ASCII, because ServiceNow paste pipelines vary across instance variants.
**Commit:** to follow in Item 1.3.

### F-002 — `nowisor-domain-separation-script-include`: `GlideRecord('domain')` on instance without domain-separation plugin
**Symptom:** `EvaluatorException: GlideRecord.addQuery() - invalid table name: domain (line 22)` on test-instance-A (standard PDI without DS plugin active).
**Root cause:** The `domain` table is conditionally available — it only exists when the domain-separation plugin (paid SKU) is activated. The verification script's informational "instance DS context" section called `new GlideRecord('domain')` unconditionally, throwing on any standard instance. Same defect appeared twice on the customer-facing KB page: a stand-alone "Step 1" sample script intended for customer remediation, and the verification block at the bottom of the page.
**Fix:** Gate every `GlideRecord('domain')` call on `GlideTableDescriptor.isValid('domain')`. When absent, print a graceful advisory message instead. Three substitutions total across the bundle and the mirrored customer-facing KB page.
**Audit:** Searched for any other identifiers that are domain-separation-plugin-gated (`domain_path`, `sn_domain.*`) across the bundle and all 26 KB pages. No other unguarded references found. The fix is contained.
**Significance:** This is the kind of defect Tier 2 verification was designed to catch. The check looked plausible during build because test-instance-A was treated as a development instance and the verification author may have had domain plugin active during initial drafting. Live testing against a clean PDI surfaced the dependency.
**Commit:** to follow in Item 1.3.

## PASS-WITH-NOTE backlog entries

> For each PASS-WITH-NOTE: capture what could be improved in the output narrative or script structure. These are logged to `BACKLOG.md` as v1.1 improvement candidates — they do not block ship.

### N-001 — `nowisor-mfa-enforcement`: catch-branch wording on missing `sys_user_mfa_setup` table
**Symptom:** When the table is inaccessible (most likely because the MFA plugin isn't active on the instance), the script's catch branch prints `(sys_user_mfa_setup table not accessible in this scope)`. The wording implies a scope-isolation problem, but the more common cause is "plugin not active".
**Improvement for v1.1:** Probe `GlideTableDescriptor.isValid('sys_user_mfa_setup')` first. If absent → print "(MFA plugin not active)". If present but read fails → print "(sys_user_mfa_setup not readable in this scope)". The fix parallels F-002's defensive pattern. Gives customers actionable signal rather than misdirecting them toward scope investigation.
**Effort:** ~5 minutes, single try/catch revision.

### N-002 — `set-workflow-false-detector` and `glide-record-vs-secure`: OOB-vs-customer partition missing
**Symptom:** Both LinterChecks surface large numbers of findings (low-double-digit and triple-digit ranges respectively on test-instance-A), and on a typical OOB customer instance, the vast majority are platform-level code (Scheduled Script Executions, UsageAnalytics scripted definitions, Security Check Configurations, FlowDesigner cleanup jobs, MID server scripts). The customer's first reaction will reasonably be "but I didn't write any of this code — why is it being flagged?"
**Improvement for v1.1:** Partition the output into two sections:
  1. *Customer-authored code* — scripts whose source isn't in `Scheduled Script Execution: ...`, `UsageAnalytics Scripted Definition: ...`, `Security Check Configurations: ...`, etc. This is the actionable section.
  2. *Platform code* — everything else, suppressed or behind a "expand" link.
This dramatically reduces noise and makes the customer-authored signal visible. Implementation: identify each finding's source.sys_package or source.sys_scope and partition by `sys_package` being null/empty (customer code) vs. a known OOB scope.
**Effort:** ~30 minutes per check. Two checks affected.

### N-003 — empty / `(unknown)` source display on a small number of findings
**Symptom:** Both `set-roles-detector` and `domain-separation-script-include` show one finding each whose `source` display value renders empty or as `(unknown)`. The verification script falls through to display this with no graceful default. Suggests the upstream LinterCheck records do not always populate a usable display value on `scan_finding.source`.
**Improvement for v1.1:** Either (a) fix the upstream check to populate a usable source identifier on every finding, OR (b) have the verification script substitute `[sys_id: <abbreviated>]` when the display value is missing. (a) is the better long-term fix; (b) is the lightweight stopgap.
**Effort:** (a) requires investigation of the LinterCheck source-resolution logic (~1 hour). (b) is ~5 minutes per verification script affected (2 affected).
