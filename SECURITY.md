# Security Policy

## Supported versions

Until the first stable release, security fixes are applied to the latest release-candidate branch/version only. After `v1.0.0`, the project will document any change to that support policy here.

| Version | Security fixes |
| --- | --- |
| Latest `0.9.x` release candidate | Yes |
| Older development snapshots | No |

## Reporting a vulnerability

Please **do not disclose security vulnerabilities in a public GitHub issue, discussion, pull request, or pasted assessment artifact**.

Once the repository's GitHub private vulnerability reporting feature is enabled, use **Security → Advisories → Report a vulnerability**. If that option is not available, open only a minimal public issue asking the maintainers to provide a private reporting channel; do not include vulnerability details, proof-of-concept material, tenant information, or secrets in that public issue.

Useful private reports should include, where possible:

- affected project version/commit;
- affected file/function;
- security impact and prerequisites;
- minimal sanitized reproduction steps;
- whether the issue can expose credentials, tokens, tenant evidence, or permit Graph behavior outside the documented read-only boundary; and
- a proposed mitigation if known.

Maintainers should acknowledge a private report, validate impact, coordinate a fix/release, and avoid public disclosure until a reasonable remediation path is available.

## Never submit real assessment data publicly

This project processes security-sensitive Microsoft Entra metadata. Do **not** attach or paste any of the following into public issues, discussions, or pull requests:

- `snapshot.json`, findings, drift output, HTML reports, diagnostics, manifests, or run transcripts from a real tenant;
- client-secret values or SecretStore exports;
- access/refresh tokens, authorization headers, cookies, or private keys;
- TenantId/ClientId values when they identify a customer environment and are not deliberately sanitized;
- customer names/domains, user principal names, emails, object inventories, credential identifiers/thumbprints, or other tenant-specific evidence; or
- local workstation/user paths that disclose customer or operator information.

Use minimal synthetic fixtures for tests and reproduction cases.

## Security boundaries that changes must preserve

Security-sensitive invariants include:

- live authentication remains app-only client-secret authentication via SecretManagement/SecretStore;
- raw Graph request transport remains confined to `Private/Graph.ps1`, with Graph authentication calls confined to `Private/Auth.ps1`;
- collection APIs are read-only; batch callers cannot supply arbitrary methods or bodies;
- Graph calls stop at the snapshot boundary and `GraphCallsAfterSnapshot` remains zero;
- snapshots/imports fail closed when evidence identity, referential integrity, counts, or completeness do not reconcile;
- absence-based findings/drift are not inferred from incomplete evidence; and
- generated artifacts must not intentionally contain credentials, access tokens, or private keys.

A change that weakens one of these boundaries should be treated as a security-sensitive design change, not a routine refactor.

## Repository security settings

For the public GitHub repository, maintainers should enable where available:

- secret scanning;
- push protection;
- private vulnerability reporting;
- Dependabot alerts/security updates for applicable dependencies; and
- branch protection/rules requiring the CI validation workflow before merge.

`.gitignore` is defense-in-depth only and must not be relied upon as a secret scanner.
