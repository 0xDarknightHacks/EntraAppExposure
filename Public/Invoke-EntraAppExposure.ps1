<#
.SYNOPSIS
    Runs an Entra App Exposure assessment.
.DESCRIPTION
    Canonical public module entry point for live or offline application-identity
    exposure assessment.
#>
function Invoke-EntraAppExposure {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = (Get-AppExposureDefaultConfigPath),

    [Parameter(Mandatory = $false)]
    [string]$SecretVault = 'AppExposureVault',

    [Parameter(Mandatory = $false)]
    [string]$SecretName = 'AppExposureGraphClientSecret',

    [Parameter(Mandatory = $false)][string]$OutputDirectory = '.\Reports',
    [Parameter(Mandatory = $false)][string]$ClientName,
    [Parameter(Mandatory = $false)][string]$ConsultantName,
    [Parameter(Mandatory = $false)][string]$TenantName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Single')]
    [string]$Scope = 'All',

    [Parameter(Mandatory = $false)][string]$TargetAppId,
    [Parameter(Mandatory = $false)][string]$TargetDisplayName,

    [Parameter(Mandatory = $false)][switch]$IncludeActivity,
    [Parameter(Mandatory = $false)][ValidateRange(1, 90)][int]$ActivityLookbackDays = 90,
    [Parameter(Mandatory = $false)][switch]$ExcludeMicrosoftFirstParty,

    [Parameter(Mandatory = $false)][string]$BaselineSnapshotPath,
    [Parameter(Mandatory = $false)][string]$OfflineSnapshotPath,
    [Parameter(Mandatory = $false)][string]$RulePackPath

    )

    return Invoke-AppExposurePipeline @PSBoundParameters
}
