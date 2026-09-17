## Summary

Describe the focused change and why it belongs in this analyzer's scope.

## Validation

- [ ] `./Tests/Run-Tests.ps1` passes.
- [ ] `Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error` returns no errors.
- [ ] No real tenant/customer assessment artifacts, secrets, tokens, private keys, or unsanitized run logs are included.
- [ ] Raw Graph transport remains confined to `Private/Graph.ps1`, with Graph authentication calls confined to `Private/Auth.ps1`.
- [ ] Collection remains read-only; `$batch` subrequests are GET-only.
- [ ] `GraphCallsAfterSnapshot` / the offline boundary is preserved.
- [ ] Snapshot/evidence compatibility has been considered; any contract change is explicitly versioned/documented.
- [ ] Absence-based findings/drift still fail closed on incomplete evidence.

## Contract impact

State whether this changes snapshot schema, observation identity/fingerprint semantics, finding evidence, drift semantics, artifact formats, authentication, or Graph permission requirements. Use "None" when applicable.
