# nowisor Instance Scan Pack — Pilot v0.1

Three-check pilot validating the conversion methodology: nowisor verified detection scripts → ServiceNow Fluent SDK Instance Scan checks.

This is a pilot, not a v1 release. The deliverable is `PILOT_RETROSPECTIVE.md` (empirical findings), not the pack itself.

## Checks

| $id | Type | Category | Priority | Purpose |
|-----|------|----------|----------|---------|
| `nowisor-csrf-token-enforcement` | ScriptOnlyCheck | security | 1 (Critical) | Verifies `glide.security.use_csrf_token = 'true'` |
| `nowisor-admin-role-concentration` | ScriptOnlyCheck | security | 1 (Critical) | Flags admin role assignments > 5% of active users |
| `nowisor-eval-usage-detector` | LinterCheck | security | 1 (Critical) | Detects `eval()` calls in server-side scripts (AP-007 anti-pattern) |

## Build / deploy

```bash
npm install
npx now-sdk auth --add https://dev265484.service-now.com --type basic   # one-time
npx now-sdk build
npx now-sdk install
```

## Layout

```
src/fluent/scan-checks/   .now.ts check definitions
scripts/                  ES5 server-side scripts referenced by Now.include()
dist/                     build output (gitignored)
```

## Methodology rules in force

- All `gs.getProperty()` references are present in `nowisor/verified_schema/releases/zurich/properties/all_properties_zurich_patch6.json`.
- Hardcoded sys_ids are documented in source comments with the verification command and timestamp.
- Server-side scripts are ES5-only.
- Scripts use `Now.include('./path.js')` for separation of definition and logic.

## Target instance

dev265484 (Zurich Patch 6). dev377226 is contaminated for pilot purposes (domain separation install attempts).
