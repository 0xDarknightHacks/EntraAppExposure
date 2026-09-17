# Changelog

This project follows Semantic Versioning for public releases.

## [Unreleased]

No unreleased changes.

## [1.0.0] - 2026-09-17

- Refined the report around deterministic identity-level P0/P1/P2/P3 exposure priority; Analyst focus now defaults to correlation-gated P0 rather than mirroring finding severity.
- Removed first-party/activity provenance from Tenant details and removed Core collection from At a glance while retaining collection/source diagnostics in the diagnostics view.
- Removed the duplicated Assessment integrity section from the analyst-facing report; integrity/completeness evidence remains in the dedicated diagnostics view.
- Unified grouped and individual findings into one searchable/filterable Findings workspace; grouped entries now use the same full finding-card structure, are emitted only for repeated rule instances, and retain aggregate affected-identity/evidence context. The filter surface is consolidated into severity shortcuts plus entry-type, category, and service-principal-classification controls.
- Removed the finding-flow Top-N cap so every actionable severity → category → assessed-identity-type combination is rendered.
- Added focused application-registration OAuth/authentication evidence for redirect URIs, implicit issuance, fallback public-client behavior, exposed API scopes/pre-authorized clients, app roles, supported account type, and token configuration context.
- Added deterministic rules for unsafe browser redirect URIs, implicit issuance, fallback public-client behavior, and pre-authorized API clients.
- Replaced the Microsoft four-square mark with a project-owned neutral EA glyph, added an explicit independent-community-project disclaimer, and retained the Alaaeddine Ayedi / 0xDarknightHacks project fingerprint.
- Documented the v1.0 Commercial-cloud boundary and the preview/activity cloud limitation.
- Finalized stable 1.0.0 manifest and repository metadata.

## [0.9.1-rc3] - 2026-09-17

- Refined application-identity activity review around a 90-day lifecycle window, excluding Microsoft-managed service principals, managed identities, and newly created identities from inactivity-style findings while retaining their source evidence.
- Added resource-qualified sensitive-permission policy matching so identical permission names on unrelated resource APIs do not collide.
- Added `-ExcludeMicrosoftFirstParty` to suppress Microsoft first-party enterprise-application findings without removing those identities from the portable snapshot.
- Added rule-level `finding-groups.json`, grouped-finding report triage, actionable-vs-informational metrics, an Analyst focus work queue, and a dependency-free severity → category → identity-type Sankey.
- Preserved the four service-principal activity dimensions, normalized activity timestamps to invariant UTC ISO-8601, and exposed activity-source provenance in diagnostics.
- Added project authorship metadata for Alaaeddine Ayedi / 0xDarknightHacks.

## [0.9.0-rc2] - 2026-09-17

- Renamed the project and public command to **Entra App Exposure** / `Invoke-EntraAppExposure`.
- Collapsed the transitional architecture into one canonical module, one public command, and nine flat private runtime files.
- Removed the duplicate root convenience launcher so the module exposes one canonical invocation surface.
- Removed the legacy `Modules/` layer, test-support module shims, duplicate manifests, retired scoring/dotenv shells, generated reports, and test-result artifacts.
- Replaced the embedded rule metadata with `Rules/Baseline.json` and a versioned `EAE-*` rule-ID taxonomy.
- Expanded the bundled baseline to 28 evidence-backed application identity rules while retaining deterministic offline evaluation and no numerical score.
- Normalized application credential findings onto application-registration objects and made cross-object exposure correlations explicit.
- Simplified CI, release validation, prerequisite validation, and Pester invocation around the canonical runtime.
- Retained snapshot schema `2.1`, offline drift, artifact integrity, finding pagination, report visualizations, and the zero-Graph post-snapshot boundary.

## [0.9.0-rc1] - 2026-09-09

- Added portable snapshot schema `2.1`, deterministic evidence-linked findings, offline semantic drift, artifact integrity, self-contained HTML reports, batched read-only Graph collection, and runtime telemetry.
