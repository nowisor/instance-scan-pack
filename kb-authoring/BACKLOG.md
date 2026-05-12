# KB authoring backlog (v1.0.0 launch + post-launch reconciliation)

## QA-pass items (batch 1 sign-off, 2026-05-12)

These items were flagged during sign-off but are NOT blocking Batch 2 authoring. Address during the final QA pass (Task #39) before the 26 pages are moved from `kb-authoring/drafts/` to `vsme-app/content/kb/checks/`.

### QA-1 — `nowisor-rest-anonymous-access` NIS2 framework reconciliation

**Status:** Accept manifest `21.2.d` as canonical for v1.0.0.

**Context:** The manifest maps this check to NIS2 21.2.d (supply-chain security). The internal KB article (`API-002`) maps the topic more broadly to 21.2.a (risk analysis / IS security policies) + 21.2.j (identity & access). The semantic case for both can be argued — anonymous API access is a supply-chain hygiene issue (third-party integrations are the most common driver of disabled basic-auth properties) AND a broader risk-analysis issue.

**v1.1 reconciliation work:**
- Audit all 26 check manifest mappings against internal KB article `frameworks` frontmatter
- For each disagreement, pick a canonical source-of-truth (likely the manifest, since it's what the finding emits)
- Update internal KB article frontmatter OR manifest entry to align
- Document the source-of-truth rule in `nowisor/instance-scan-pack/manifest.json` schema comment

### QA-2 — `nowisor-external-auth-policy` DORA paragraph reword

**Status:** Reword in final QA pass.

**Current text (draft, lines 56-58):**
> "The check does not carry a DORA mapping in the manifest because DORA Article 9's authentication scope is broader (covering MFA and overall access management) rather than specifically about IdP bypass. The local-login bypass becomes a DORA finding indirectly through the MFA pathway — if the IdP enforces MFA and local doesn't, you have effectively no MFA enforcement on the bypass path."

**Issue:** Defensive tone — frames the manifest as having omitted DORA. Reword to emphasize the routing-through-MFA framing without defensiveness.

**Proposed (rough):**
> "DORA Article 9's authentication requirements route through MFA on this check rather than appearing as a direct mapping. When SSO + IdP-enforced MFA is the entity's authentication baseline, the local-login bypass becomes the path that defeats MFA — so DORA Article 9§4(b) (authentication mechanisms) lands on this finding via the `nowisor-mfa-enforcement` companion."

Refine wording during QA pass.

### QA-3 — Launch URL infrastructure

**Status:** Separate launch-coordination task; not in KB authoring scope.

**Context:** Batch 1 acquisition CTAs use `/demo` and `/early-access` (real pages on nowisor.com). The pages exist but the copy + funnel mechanics on those landing pages need to match the framing each KB page sets up:
- `/demo` should support DORA evidence framing, IdP coexistence framing, session-protection cluster framing
- `/early-access` should support NIS2 evidence framing, REST surface audit framing

**Action item for launch coordination (not KB authoring):**
- Audit `/demo` and `/early-access` page copy against the framing the 26 KB pages set up
- If page copy doesn't deliver on the framing, either update the page copy OR change KB CTAs to point at pages that do
- Decide whether to introduce a `/connect` page for "I want to run this check on my instance" intent — separate from `/demo` (passive view) and `/early-access` (waitlist signup)

---

## v1.1 reactivation tracking

Two checks deferred to v1.1 per `V1_RETROSPECTIVE_TIER2.md` will need KB page updates when reactivated:

- **`nowisor-hardcoded-credentials`** — current stub at `kb-authoring/drafts/nowisor-hardcoded-credentials.md`. When v1.1 reactivates, replace stub content with full active-page content following the LinterCheck archetype. Move out of "deferred" status, remove status banner, add real triage guidance.

- **`nowisor-direct-property-write`** — stub authoring queued in Batch 3. Same v1.1 reactivation path: replace stub with active content when the AST predicate fix ships.

---

## Cross-cutting follow-ups surfaced during authoring

### Reciprocal `related_checks` consistency

Each page lists `related_checks` in frontmatter, but reciprocity should hold: if A lists B in related, B should list A. Audit during final QA pass — currently each page was authored individually so some asymmetries are likely.

### Background Script verification gate

Every KB page's verification Background Script must be paste-and-run tested on dev265484 before the page moves out of drafts. Task #39 covers this — the test should produce the expected `[PASS]` or `[FAIL]` output structure with no runtime errors.

### `canonical_kb_source` path validation

The frontmatter field `canonical_kb_source` points at a path under `content/domain-*/`. Verify each path resolves to a real file during QA. If a check has no canonical source (the `missing` category from coverage-audit.md — `fabricated-property-references`, `meta-active-check-coverage`), use `null` or omit the field; document in the page that the source is the check spec itself.

---

## QA-pass items (batch 2 sign-off, 2026-05-12)

### QA-4 — GDPR schema in `manifest.json`

**Status:** Option 1 (flat array, consistent with nis2/iso27001/dora) — confirmed for v1.0.0 per sign-off.

**Decision:** Keep GDPR as `gdpr: ["32"]` (flat string array). Do NOT migrate to a nested object schema for v1.0.0.

**Rationale:** Consistency with the other framework_mappings keys. The only check currently mapped to GDPR is `nowisor-domain-separation-script-include`. If v1.x adds checks with GDPR sub-article specificity (e.g., `Art.32§1(a)`), revisit the schema then.

**Action:** No manifest change required for v1.0.0. Document the decision in the manifest schema comment during final QA.

### QA-5 — Advisor product scope verification (cross-workstream blocker)

**Status:** Open. Affects the acquisition footers on ~25 of 26 KB pages.

**Context:** Acquisition footers reference advisor product features. Sample claims requiring verification:

- "Packages each scan finding with the regulatory mapping, attack-path narrative, and remediation status into an export your compliance team can attach directly to the relevant control evidence" (CSRF page)
- "Groups these findings into the code-discipline cluster with prioritized remediation guidance based on caller reachability and table sensitivity" (GlideRecord page)
- "Tracks deferred checks and notifies subscribers when reactivation lands" (hardcoded-credentials stub)
- "Cross-references `setWorkflow` findings with audit-log volume metrics" (set-workflow page)
- "Surfaces a 'configuration-as-code' map showing every record whose stored value flows into a `GlideEvaluator` call" (glide-evaluator page)
- "Produces a 'tenant-isolation evidence pack' that combines the domain-separation findings with the ACL audit, cross-scope privilege audit, and configuration-baseline drift" (domain-separation page)
- "DORA evidence flow" / "NIS2 evidence flow" / "IAM evidence flow" — recurring framing across multiple pages

**Required from advisor product workstream:**
- Per-claim label: REAL (shipping in v1.0.0 advisor), ROADMAP (committed for v1.x), or SPECULATIVE (vision, not committed)
- For ROADMAP claims, the target release
- For SPECULATIVE claims, remove or soften before public publish

**Blocker:** No public KB page can ship before this is resolved. Pages remain in `kb-authoring/drafts/` until verified.

### QA-6 — Methodology-as-launch-material extraction

**Status:** Capture, not blocker. Affects launch coordination.

**Context:** Several pages contain methodology moments that excerpt well as launch material — they demonstrate nowisor's distinctive technical voice and discipline.

**Candidate excerpts identified across the batches:**

- "We chose to ship v1.0.0 with the check disabled rather than ship it producing false-negatives. A check that silently misses real exposures is more dangerous than no check at all — it creates a false sense of coverage." (hardcoded-credentials stub)
- "The check is explicitly heuristic. Findings on a non-DS instance are advisory; findings on a DS instance are higher-priority." (domain-separation page)
- "The original predicate required `parent === CALL`, which only matched function-call AST shapes. Because `setRoles` is universally a method call, the original predicate matched nothing. The predicate was rewritten in May 2026 to also accept `grandparent === CALL`." (set-roles page; same pattern in set-workflow)
- "The cost of removing an `eval()` and replacing it with safer alternatives is low (refactor cost), but the cost of leaving it in place is unbounded if any path to user-controlled input exists." (eval-usage page)

**Action:** During launch coordination, mine these for blog post / press / customer-deck excerpts. Don't lose them in the KB content. Suggest a launch-day blog post titled "What we caught at Tier 2 (and why we deferred two checks)" that walks through the methodology.
