# Entra App Exposure

**Entra App Exposure** is a read-only PowerShell utility for assessing Microsoft Entra application identities. It inventories application registrations and service principals, collects OAuth/application permission, ownership, credential, and optional sign-in evidence, writes a portable snapshot, evaluates deterministic rules offline, compares snapshots for drift, and exports self-contained HTML reports.

> **Status:** `1.0.0` stable.
>
> **Independent community project:** Entra App Exposure is not affiliated with, sponsored by, or endorsed by Microsoft. Microsoft, Microsoft Entra, Microsoft Graph, and related product names are trademarks of Microsoft Corporation. The project name describes the Microsoft Entra technology it assesses; all project branding and report artwork are independently created.

## Scope

In scope:

- application registrations and service principals;
- application permissions (`appRoleAssignments`);
- delegated OAuth consent grants;
- application-registration and service-principal ownership;
- certificate/secret metadata for tenant-visible application registrations;
- focused application OAuth/authentication configuration evidence: supported account type, web/SPA/public-client redirect URIs, implicit issuance, fallback public-client behavior, exposed API scopes/pre-authorized clients, app roles, identifier URIs, and optional-claims context;
- optional recent service-principal sign-in context;
- deterministic evidence-backed findings;
- portable snapshots and offline semantic drift.

Out of scope: attack paths, Conditional Access posture, broad identity-governance posture, tenant-wide consent-policy/admin-consent-request/reviewer workflow assessment, remediation automation, exploit simulation, and numerical risk scoring.

### Cloud support

v1.0 targets the **Microsoft Commercial / global cloud**. Authentication and Microsoft Graph endpoints are currently bound to the global `login.microsoftonline.com` and `graph.microsoft.com` endpoints. Sovereign clouds (US Government, US Government DoD, and China) are not supported by this release.

Optional activity enrichment uses the preview `servicePrincipalSignInActivities` Microsoft Graph API when available, with the existing filtered sign-in-log path as a compatibility fallback. The preview activity API is not available in the US Government, US Government DoD, or China clouds. Preview API behavior can change independently of this project.

The core application permission set intentionally uses `Directory.Read.All` because delegated OAuth grant enumeration is part of the assessment and Microsoft documents it as the least-privileged **application** permission for listing `oauth2PermissionGrants`. `AuditLog.Read.All` is added only when optional activity collection is requested.

## Architecture

The repository is intentionally compact:

```text
EntraAppExposure.psd1
EntraAppExposure.psm1
Public/
  Invoke-EntraAppExposure.ps1

Private/
  Common.ps1
  Auth.ps1
  Graph.ps1
  Collection.ps1
  Snapshot.ps1
  Rules.ps1
  Drift.ps1
  Reporting.ps1
  Pipeline.ps1

Rules/
  Baseline.json

Schemas/
  PortableAssessmentSnapshot.schema.json
  RulePack.schema.json

Scripts/
  Test-EntraAppExposureRequirements.ps1
  Test-EntraAppExposureRelease.ps1

Tests/
```

The runtime pipeline is:

```text
app-only authentication
  -> read-only Graph collection
  -> portable snapshot.json
  -> deterministic rule evaluation
  -> optional offline drift
  -> self-contained reports
```

Raw Graph transport is confined to `Private/Graph.ps1`; authentication lives in `Private/Auth.ps1`. Snapshot validation, rules, drift, and reporting are offline and the run enforces `GraphCallsAfterSnapshot = 0`.

## Rules

Rules are not embedded as metadata inside PowerShell. The bundled assessment baseline is `Rules/Baseline.json`, validated by `Schemas/RulePack.schema.json`.

The baseline contains policy thresholds, resource-qualified sensitive-permission watchlists, activity review policy, and versioned rule definitions. Rule IDs follow:

```text
EAE-<SURFACE>-<CATEGORY>-<NNN>
```

Examples:

```text
EAE-OAUTH-APP-001
EAE-SP-OWNER-001
EAE-APP-CRED-003
EAE-SP-ACTIVITY-001
EAE-EXPOSURE-005
```

`Private/Rules.ps1` contains only deterministic evaluator logic. A rule definition carries its severity, title, rationale, recommendation, applicable object type, required evidence surfaces, and Microsoft references.

## Requirements

- PowerShell 7.6+
- For **live assessments only**: `Microsoft.PowerShell.SecretManagement` 1.1.2+ and `Microsoft.PowerShell.SecretStore` 1.0.6+

The module and offline snapshot-analysis path do not require the authentication modules.

For development/release validation:

- Pester 6.1.0
- PSScriptAnalyzer 1.25.0

Validate the local runtime:

```powershell
.\Scripts\Test-EntraAppExposureRequirements.ps1
```

## Microsoft Graph permissions

Create a dedicated Entra application registration for assessment use and grant Microsoft Graph **application permissions**:

| Permission | Required | Purpose |
| --- | --- | --- |
| `Directory.Read.All` | Yes | Core application/service-principal and OAuth grant evidence. |
| `AuditLog.Read.All` | With `-IncludeActivity` | Optional service-principal sign-in context. |

Grant admin consent. The tool is read-only.

## Authentication setup

Create non-secret tenant/client configuration:

```powershell
$configDirectory = Join-Path $HOME '.entra-app-exposure'
New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null

@{
    TenantId = '<tenant-id>'
    ClientId = '<application-client-id>'
} | ConvertTo-Json | Set-Content (Join-Path $configDirectory 'config.json') -Encoding utf8
```

Register SecretStore and save the **client-secret value**:

```powershell
Register-SecretVault -Name AppExposureVault -ModuleName Microsoft.PowerShell.SecretStore
$secret = Read-Host 'Assessment app client secret' -AsSecureString
Set-Secret -Name AppExposureGraphClientSecret -Vault AppExposureVault -Secret $secret
Remove-Variable secret
```

## Usage

Import the canonical module:

```powershell
Import-Module .\EntraAppExposure.psd1 -Force
```

Run a tenant-wide assessment:

```powershell
$run = Invoke-EntraAppExposure `
    -Scope All `
    -ClientName '<client>' `
    -ConsultantName '<analyst>'
```

Include activity context:

```powershell
$run = Invoke-EntraAppExposure `
    -Scope All `
    -IncludeActivity `
    -ActivityLookbackDays 90 `
    -ClientName '<client>'
```

Activity enrichment prefers Microsoft Graph's preview service-principal sign-in activity report and retains the existing filtered sign-in-log path as a compatibility fallback. `AuditLog.Read.All` is required for this optional path.

Target one service principal by object ID, app/client ID, or unambiguous display name with `-Scope Single` and `-TargetAppId` / `-TargetDisplayName`.

To keep Microsoft-managed enterprise applications in the portable snapshot while excluding their findings from analyst triage:

```powershell
$run = Invoke-EntraAppExposure `
    -Scope All `
    -ExcludeMicrosoftFirstParty `
    -ClientName '<client>'
```

`-ExcludeMicrosoftFirstParty` affects finding evaluation only. Inventory and canonical evidence remain in `snapshot.json` so the assessment stays reproducible and auditable. The bundled activity rule also applies a lower-noise 90-day review policy and excludes Microsoft-managed service principals, managed identities, and identities newer than the review window.

Replay an existing snapshot fully offline:

```powershell
$run = Invoke-EntraAppExposure `
    -OfflineSnapshotPath .\snapshot.json `
    -ClientName '<client>'
```

Compare against a baseline snapshot:

```powershell
$run = Invoke-EntraAppExposure `
    -Scope All `
    -BaselineSnapshotPath .\baseline\snapshot.json `
    -ClientName '<client>'
```

## Output

Each run produces a timestamped directory containing the portable snapshot, individual findings, a grouped-finding artifact for machine-readable triage, optional drift, run summary/telemetry, integrity manifest, transcript, and three self-contained HTML views. Key artifacts include:

- `snapshot.json`
- `findings.json` / `findings.csv`
- `finding-groups.json`
- `run-summary.json`
- `artifact-manifest.json`
- `report.html`
- `evidence.html`
- `diagnostics.html`

The assessment report starts with an **Analyst focus** work queue that defaults to deterministic, identity-level **P0** exposure correlations. Grouped and individual findings share one searchable/paginated Findings workspace and the same visual finding contract: severity/rule tags, what happened, why it matters, recommended action, references, and evidence. A grouped entry is emitted only when the same rule produces multiple concrete findings; singleton rules remain individual-only to avoid duplicate triage cards. The Findings filter panel combines severity shortcuts with entry-type, category, and service-principal-classification controls.

The dependency-free finding-flow Sankey renders **all actionable flow combinations** (severity → category → assessed identity type); informational activity context is excluded from that flow but remains available as evidence/context. Collection/evidence integrity details remain available in `diagnostics.html` rather than being duplicated at the end of the analyst-facing assessment report.

Reports and manifests include a lightweight project fingerprint for **Alaaeddine Ayedi** / `https://github.com/0xDarknightHacks`, while canonical project metadata points to `https://github.com/0xDarknightHacks/EntraAppExposure`.

## Validation

Run Pester from the repository root:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

Run release integrity validation:

```powershell
$r = .\Scripts\Test-EntraAppExposureRelease.ps1
$r.ReleaseEligible
```

Release validation rejects generated tenant reports, secrets/keys, archives, transitional architecture, stale naming, invalid rule IDs, and source files that violate the Graph transport boundary.

## Security

Never commit real assessment artifacts, tenant data, credentials, access tokens, SecretStore state, or private keys. See `SECURITY.md`.
