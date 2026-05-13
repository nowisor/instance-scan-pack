# Security policy

The nowisor Instance Scan Pack is open-source security tooling. We take both the security of this project and the platform it audits seriously.

## Reporting a vulnerability in this pack

If you've found a security issue in the pack itself — a check that produces false negatives that mask real exposure, a verification script that mutates state when it should be read-only, a build-time issue that affects install integrity — please report it privately rather than opening a public issue.

**Preferred channel:** open a GitHub security advisory via the "Security" tab on this repository. This keeps the conversation private until a fix ships.

**Fallback:** email the maintainers. (Replace with a real contact address before announcing the repo publicly.)

We aim to acknowledge security reports within 5 business days and to ship a fix or a documented mitigation within 30 days for high-severity issues.

## Findings about ServiceNow itself

Some of the checks in this pack target ServiceNow platform properties whose misconfiguration creates real security exposure. The checks themselves describe well-known hardening patterns: the property names, default values, and recommended values are all documented on docs.servicenow.com and on the platform's own Instance Security Center.

If we discover, during the course of authoring or maintaining a check, a security issue in the ServiceNow platform itself that has not been publicly disclosed — for example, an undocumented vulnerability surfaced by a detection technique — we coordinate disclosure with [ServiceNow PSIRT](https://www.servicenow.com/company/trust/security/security-vulnerabilities.html) before publishing.

In practice this means:

- A new check whose detection logic relies on an unpatched vulnerability is held back from `main` and from release tags until coordination with ServiceNow PSIRT is complete.
- Existing checks reference only documented hardening patterns; they do not provide exploitation primitives.
- The verification Background Scripts are read-only. They report state; they do not mutate it.

This isn't a substitute for ServiceNow's own security process — it's how we layer in.

## Findings in your instance

The pack runs entirely inside your ServiceNow instance. It does not phone home, does not send finding data to any external service, and does not require any outbound network access from the instance to function. Findings live in your instance's `scan_finding` table and are visible only to users who have read access to that table.

If you choose to connect your instance to the optional [nowisor advisor](https://nowisor.com) at the higher tiers of that product, the advisor reads `scan_finding` records via authenticated REST. That data flow is opt-in, scoped to the OAuth grant you authorize, and documented separately in the advisor's terms of service. The agent itself remains independent of that data flow.

## Scope

In scope:

- Security issues in the pack's source (`src/`), scripts (`scripts/`), or bootstrap (`bootstrap/`) that affect customer instances on install or at runtime.
- Documentation errors in `docs/` that could lead a customer to apply an incorrect remediation.
- Build- or supply-chain integrity issues in the published artifact (`dist/update-sets/*.tar.gz`).

Out of scope:

- Misconfigurations in the customer's instance unrelated to the pack itself (those are what the pack detects).
- Issues in `@servicenow/sdk`, ServiceNow plugins, or the ServiceNow platform — please report those directly to ServiceNow PSIRT.
- Findings that the pack is *intended* to surface (false-positive disagreements are filed as regular issues, not security reports).

## Supported releases

| Release tag | Supported | Notes |
|---|---|---|
| `v1.0.0-build-tier2` and later on `main` | Yes | Receives security fixes and patch releases. |
| `v1.0.0-build` | Yes | Receives critical security fixes only. |
| `pilot-v0.1`, `pilot-v0.2` | No | Historical tags. Do not deploy. |

The verified platform target is ServiceNow Zurich Patch 6. Compatibility with other releases is best-effort; see the README's Compatibility section.
