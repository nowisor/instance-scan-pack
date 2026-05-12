# nowisor public KB — coverage audit (v1.0.0 launch)

**Date:** 2026-05-12
**Scope:** 26 checks in v1.0.0-build (24 active + 2 deferred)
**Target:** `nowisor.com/kb/checks/<check-id>` — markdown at `vsme-app/content/kb/checks/<check-id>.md`
**Internal source root:** `content/domain-*/`

## Coverage summary

| State | Count | Means |
|---|---|---|
| **full** | 19 | One or more internal KB articles directly cover the subject; public page derives cleanly |
| **partial** | 3 | Related articles exist but lack dedicated focus; will stitch from multiple sources |
| **deferred** | 2 | v1.1-blocked checks; author shorter stub pages (~300-500 words) with reactivation criteria |
| **missing / meta** | 2 | Operational/internal checks with no vulnerability-class internal KB; thin stub pages |

## Mapping table

| check_id | name | framework_mappings | candidate internal KB | coverage | notes |
|---|---|---|---|---|---|
| nowisor-csrf-token-enforcement | CSRF Token Enforcement | nis2:21.2.a, iso27001:A.5.15, dora:9 | HARD-002, API-002, HARD-001 | **full** | HARD-002 directly covers CSRF; API-002 covers REST endpoint auth |
| nowisor-session-timeout | Session Idle Timeout | nis2:21.2.j, iso27001:A.8.5, dora:9 | IDN-009, HARD-002, MON-007 | **full** | IDN-009 covers glide_session_store and timeout config |
| nowisor-cookie-http-only | Cookie HttpOnly Enforcement | nis2:21.2.e, iso27001:A.8.23, dora:9 | IDN-009, HARD-002 | **full** | IDN-009 documents HttpOnly cookie flag |
| nowisor-cookie-secure | Cookie Secure Flag Enforcement | nis2:21.2.e, iso27001:A.8.23, dora:9 | IDN-009, HARD-002 | **full** | Same as HttpOnly; both flags covered together |
| nowisor-secure-cookies | Secure Cookies UI Property | nis2:21.2.e, iso27001:A.8.23 | IDN-009 | **partial** | IDN-009 covers cookie settings; may need UI property specifics |
| nowisor-rest-anonymous-access | REST Anonymous Access Audit | nis2:21.2.d, iso27001:A.5.16, dora:9 | API-002, API-001, HARD-001, API-003 | **full** | API-002/001 cover REST auth + `glide.basicauth.required.*` family |
| nowisor-mfa-enforcement | MFA Enforcement | nis2:21.2.j, iso27001:A.5.17, dora:9 | IDN-002, IDN-009 | **full** | IDN-002 directly addresses MFA |
| nowisor-external-auth-policy | External Auth — Disable Local Login | nis2:21.2.j, iso27001:A.5.16 | IDN-001, IDN-002, IDN-003 | **full** | IDN-001 covers SAML/SSO; IDN-003 covers alternative auth endpoints |
| nowisor-admin-role-concentration | Admin Role Concentration | nis2:21.2.j, iso27001:A.5.18, A.8.2 | ACL-004, ACL-011, ATTACK-002 | **full** | ACL-004 addresses overly broad admin/security_admin |
| nowisor-inactive-users-with-roles | Inactive Users Retaining Roles | nis2:21.2.j, iso27001:A.5.18 | ACL-011, MON-001 | **full** | ACL-011 is primary: stale access / orphaned accounts |
| nowisor-attachment-role-restriction | Attachment Role Restriction | nis2:21.2.h, iso27001:A.5.34, dora:9 | DATA-003, ACL-005, API-001 | **full** | DATA-003 covers sys_attachment ACL bypass |
| nowisor-oob-acl-modifications | OOB ACL Modifications | nis2:21.2.a, iso27001:A.8.3 | MON-001, MON-008, ATTACK-002 | **partial** | Audit-logging articles exist; lacks OOB-ACL-specific article |
| nowisor-cross-scope-privilege-grants | Cross-Scope Privilege Grants | nis2:21.2.a, iso27001:A.8.3 | ACL-004, DOM-005 | **full** | ACL-004 addresses role breadth + scope isolation |
| nowisor-elevated-role-assignments | Elevated Role Co-Assignments | nis2:21.2.j, iso27001:A.5.18 | ACL-004, ATTACK-002 | **full** | ATTACK-002 (unprivileged-to-admin) contextualizes the risk |
| nowisor-eval-usage-detector | eval() Usage Detector | nis2:21.2.d, iso27001:A.8.28, dora:9 | CODE-003, CODE-005, CODE-004 | **full** | CODE-003 is primary article on eval()/GlideEvaluator |
| nowisor-set-workflow-false-detector | setWorkflow(false) Detector | nis2:21.2.f, iso27001:A.8.15, dora:9 | CODE-004, CODE-005, MON-001 | **partial** | Audit-bypass pattern; no dedicated setWorkflow article |
| nowisor-glide-evaluator-detector | GlideEvaluator Dynamic Evaluation Detector | nis2:21.2.d, iso27001:A.8.28 | CODE-003, CODE-004 | **full** | CODE-003 directly addresses GlideEvaluator |
| nowisor-glide-record-vs-secure | GlideRecord vs GlideRecordSecure | nis2:21.2.h, iso27001:A.8.3 | CODE-005, CODE-001, PORTAL-010 | **full** | PORTAL-010 directly compares the two APIs |
| nowisor-set-roles-detector | setRoles() Escalation Detector | nis2:21.2.j, iso27001:A.5.18 | CODE-005, ATTACK-002, ACL-004 | **full** | CODE-005 covers Script Include privilege escalation |
| nowisor-hardcoded-credentials | Hardcoded Credentials Detector | nis2:21.2.i, iso27001:A.8.5, dora:9 | DATA-006, HARD-001, CODE-003 | **deferred** | v1.1 (predicate redesign); DATA-006 secrets in records |
| nowisor-direct-property-write | Direct sys_properties Write Detector | nis2:21.2.a, iso27001:A.8.9 | HARD-001, MON-001 | **deferred** | v1.1 (AST anchor investigation); HARD-001 covers property manipulation |
| nowisor-domain-separation-script-include | Cross-Domain Script Include Reference | nis2:21.2.j, iso27001:A.5.31, gdpr:32 | DOM-001, DOM-005, CODE-005 | **full** | DOM-001/005 domain separation posture |
| nowisor-update-set-xml-suspicious | Suspicious Update Set XML | nis2:21.2.f, iso27001:A.8.32 | CHG-001, DATA-008 | **full** | CHG-001 update set security + malicious code promotion |
| nowisor-fabricated-property-references | Fabricated Property References | nis2:21.2.a, iso27001:A.8.9 | (fabricated-props-resolution-log) | **missing** | Operational; meta-validation, no vuln-class article |
| nowisor-meta-active-check-coverage | Meta — Active Check Coverage | (none) | (operational/meta) | **missing** | No framework; thin stub for transparency |
| nowisor-platform-build-drift | Platform Build Drift | nis2:21.2.a, iso27001:A.8.32 | HARD-005, MON-008, COMP-001 | **partial** | HARD-005 covers MID patching; build drift conceptually fits |

## Authoring batches (post sign-off)

To minimize context-switching during the batch pass, group by domain shape:

1. **Auth/session/cookies (8):** csrf, session-timeout, cookie-http-only, cookie-secure, secure-cookies, rest-anonymous-access, mfa-enforcement, external-auth-policy
2. **ACL/role (6):** admin-role-concentration, inactive-users-with-roles, attachment-role-restriction, oob-acl-modifications, cross-scope-privilege-grants, elevated-role-assignments
3. **Code analysis (5 active + 1 stub):** eval-usage, glide-evaluator, glide-record-vs-secure, set-roles, set-workflow-false; **+** hardcoded-credentials (deferred stub)
4. **Cross-cutting + domain separation (5 + 1 stub):** domain-separation-script-include, update-set-xml-suspicious, fabricated-property-references, meta-active-check-coverage, platform-build-drift; **+** direct-property-write (deferred stub)

Templates selected for sign-off draft:
- **Auth-property archetype:** `nowisor-csrf-token-enforcement` (full coverage, simplest customer-facing remediation)
- **LinterCheck archetype:** `nowisor-glide-record-vs-secure` (full coverage, code-pattern audience, line-number findings shape)
- **Deferred-stub archetype:** `nowisor-hardcoded-credentials` (validates the deferred-page format)
