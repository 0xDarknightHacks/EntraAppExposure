@{
    RootModule = 'EntraAppExposure.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'dc9bcaa7-b9f0-426c-af35-abbb09f81a2d'
    Author = 'Alaaeddine Ayedi'
    CompanyName = 'Community'
    Copyright = 'Copyright (c) Alaaeddine Ayedi and project contributors'
    Description = 'Read-only Microsoft Entra application exposure assessment with portable evidence snapshots, deterministic rules, offline drift, and self-contained reporting.'
    PowerShellVersion = '7.6'
    CompatiblePSEditions = @('Core')
    RequiredModules = @()
    FunctionsToExport = @('Invoke-EntraAppExposure')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('MicrosoftEntra','OAuth','ApplicationIdentity','MicrosoftGraph','SecurityAssessment','PowerShell','ReadOnly')
            LicenseUri = 'https://www.apache.org/licenses/LICENSE-2.0'
            ProjectUri = 'https://github.com/0xDarknightHacks/EntraAppExposure'
            ReleaseNotes = '1.0.0: first stable release of the read-only Entra application identity exposure assessment, with deterministic evidence-backed rules, P0-P3 identity prioritization, portable snapshots, offline drift, grouped/individual triage, and self-contained reporting.'
        }
    }
}
