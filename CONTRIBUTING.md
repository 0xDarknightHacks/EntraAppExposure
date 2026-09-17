# Contributing

Keep changes focused on Entra App Exposure's narrow application-identity assessment scope.

## Development

Recommended tooling:

- PowerShell 7.6+
- Pester 6.1.0
- PSScriptAnalyzer 1.25.0

Run before a pull request:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error
.\Scripts\Test-EntraAppExposureRelease.ps1
```

## Architecture boundaries

1. Keep the runtime self-contained and lightweight.
2. Keep the public surface to `Invoke-EntraAppExposure` unless a deliberate public API change is approved.
3. Keep raw Graph transport in `Private/Graph.ps1` and authentication in `Private/Auth.ps1`.
4. Keep collection read-only; batching may use Graph `$batch`, but generated subrequests remain GET-only.
5. Make no Graph calls after the snapshot boundary; `GraphCallsAfterSnapshot` must remain zero.
6. Treat the portable snapshot/observations as the offline source of truth for rules and drift.
7. Fail closed when evidence is incomplete.
8. Do not introduce a numerical risk score.
9. Keep rule metadata in `Rules/Baseline.json`; evaluator code belongs in `Private/Rules.ps1`.
10. Avoid one-file-per-rule or compatibility layers that unnecessarily expand the repository.

Snapshot schema `2.1` remains a compatibility-sensitive contract. Rule-baseline changes must preserve deterministic evidence linkage and use stable `EAE-*` IDs.

Never commit real assessment exports, tenant identifiers, secrets, keys, tokens, or unsanitized run logs.
