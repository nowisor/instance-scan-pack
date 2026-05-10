# nowisor Instance Scan Pack — Pilot v0.2

Three-check pilot validating the conversion methodology: nowisor verified detection scripts → ServiceNow Fluent SDK Instance Scan checks.

This is a pilot, not a v1 release. The deliverables are `PILOT_RETROSPECTIVE.md` and `V0_2_RETROSPECTIVE.md` (empirical findings). Read the v0.2 retrospective first — it supersedes the v0.1 conclusions where they differ.

## Checks

| $id | Type | Category | Priority | Purpose |
|-----|------|----------|----------|---------|
| `nowisor-csrf-token-enforcement` | ScriptOnlyCheck | security | 1 (Critical) | Verifies `glide.security.use_csrf_token = 'true'` |
| `nowisor-admin-role-concentration` | ScriptOnlyCheck | security | 1 (Critical) | Flags admin role assignments > 5% of active users |
| `nowisor-eval-usage-detector` | LinterCheck | security | 1 (Critical) | Detects `eval()` calls in server-side scripts (AP-007 anti-pattern) |

## Build / deploy

```bash
npm install
npx now-sdk auth --add https://dev265484.service-now.com --type basic --alias dev265484   # one-time
npx now-sdk build
npx now-sdk install --auth dev265484
SN_INSTANCE=https://dev265484.service-now.com SN_USER=admin SN_PASS=... \
  ./scripts/create-suite.sh                           # required: provisions scan_check_suite
```

The post-install bootstrap is mandatory: the Fluent SDK (4.6.0) does not expose a `ScanCheckSuite` API, so the suite and m2m membership rows cannot ship inside the application. Without a suite, the platform's full-scan engine never executes the checks. The bootstrap script is idempotent — safe to re-run after every install.

## Trigger a scan

```bash
curl -u admin:$SN_PASS -H 'Accept: application/json' \
  -X POST 'https://dev265484.service-now.com/api/sn_cicd/instance_scan/full_scan'
# returns { "result": { "status": "0", "links": { "progress": { "id": "...", "url": "..." } } } }
# poll the progress URL; on Successful, query scan_finding by check.sys_scope
```

## Layout

```
src/fluent/scan-checks/   .now.ts check definitions
src/fluent/cross-scope/   CrossScopePrivilege records (defensive)
scripts/                  ES5 server-side scripts (Now.include) + bootstrap helpers
dist/                     build output (gitignored)
```

## Methodology rules in force

- All `gs.getProperty()` references are present in `nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json`.
- Hardcoded sys_ids are documented in source comments with the verification command and timestamp.
- Server-side scripts are ES5-only.
- Scripts use `Now.include('./path.js')` for separation of definition and logic. (Note: SDK guide says inline-only; `Now.include()` works empirically as of 4.6.0 — script body is inlined into the deployed record. v0.1 retrospective documents this discrepancy.)

## Re-installing / upgrading

```bash
npx now-sdk install --auth dev265484 --reinstall
SN_PASS=... ./scripts/create-suite.sh   # required: m2m rows are cascade-deleted by --reinstall
```

`scan_finding` records persist across reinstalls (FK is preserved against deterministic check sys_ids). `scan_check_suite_check` m2m rows do NOT persist — they reference our checks via FK and cascade-delete when the app is uninstalled.

## Target instance

dev265484 (Zurich Patch 6). dev377226 is contaminated for pilot purposes (domain separation install attempts).
