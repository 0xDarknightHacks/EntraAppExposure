<#
.SYNOPSIS
    Validates local prerequisites for Entra App Exposure.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ProjectRoot,
    [string]$ConfigPath,
    [string]$SecretVault = 'AppExposureVault',
    [string]$SecretName = 'AppExposureGraphClientSecret',
    [switch]$InstallMissing,
    [switch]$IncludeOptionalModules,
    [switch]$SkipGalleryReachability,
    [switch]$SkipAuthenticationConfiguration,
    [switch]$AsJson,
    [switch]$NoColor
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifestName = 'EntraAppExposure.psd1'
$minimumPowerShell = [version]'7.6.0'
$liveModules = [ordered]@{ 'Microsoft.PowerShell.SecretManagement' = [version]'1.1.2'; 'Microsoft.PowerShell.SecretStore' = [version]'1.0.6' }
$optionalModules = [ordered]@{ Pester = [version]'6.1.0'; PSScriptAnalyzer = [version]'1.25.0' }

function Write-RequirementStatus {
    param([string]$Text,[ValidateSet('Info','Success','Warning','Error')][string]$Kind='Info')
    if ($AsJson) { return }
    $prefix = switch ($Kind) { 'Success' {'[OK]'} 'Warning' {'[!]'} 'Error' {'[X]'} default {'[i]'} }
    if ($NoColor -or -not [Environment]::UserInteractive) { Write-Host "$prefix $Text"; return }
    $color = switch ($Kind) { 'Success' {'Green'} 'Warning' {'Yellow'} 'Error' {'Red'} default {'Gray'} }
    Write-Host "$prefix $Text" -ForegroundColor $color
}
function New-RequirementCheck {
    param([string]$Name,[bool]$Passed,[string]$Message,[string]$Severity='Required',[object]$Data=$null)
    [pscustomobject]@{ Name=$Name; Passed=$Passed; Severity=$Severity; Message=$Message; Data=$Data }
}
function Get-InstalledModuleState {
    param([string]$Name,[version]$MinimumVersion)
    $module = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    [pscustomobject]@{ Name=$Name; Installed=[bool]$module; Version=if($module){[string]$module.Version}else{$null}; Minimum=[string]$MinimumVersion; Passed=[bool]($module -and $module.Version -ge $MinimumVersion) }
}

$root = if ($ProjectRoot) { (Resolve-Path -LiteralPath $ProjectRoot).Path } else { (Split-Path -Parent $PSScriptRoot) }
$manifestPath = Join-Path $root $manifestName
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Could not resolve project root containing $manifestName." }

$checks = [System.Collections.Generic.List[object]]::new()
$psReady = $PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion -ge $minimumPowerShell
$checks.Add((New-RequirementCheck 'PowerShell runtime' $psReady "PowerShell $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition); required Core $minimumPowerShell+."))

if (-not $SkipGalleryReachability) {
    try { $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop; $checks.Add((New-RequirementCheck 'PowerShell Gallery' $true "PSGallery is registered at $($repo.SourceLocation)." 'Recommended')) }
    catch { $checks.Add((New-RequirementCheck 'PowerShell Gallery' $false "PSGallery is unavailable: $($_.Exception.Message)" 'Recommended')) }
}

$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
foreach ($name in $liveModules.Keys) {
    $minimum = $liveModules[$name]
    $state = Get-InstalledModuleState -Name $name -MinimumVersion $minimum
    if (-not $state.Passed -and $InstallMissing -and $PSCmdlet.ShouldProcess("$name $minimum",'Install live-assessment module')) {
        Install-Module $name -MinimumVersion $minimum -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
        $state = Get-InstalledModuleState -Name $name -MinimumVersion $minimum
    }
    $severity = if ($SkipAuthenticationConfiguration) { 'Recommended' } else { 'Required' }
    $checks.Add((New-RequirementCheck "Live module: $name" $state.Passed $(if($state.Passed){"Installed $($state.Version)."}else{"Missing or below $minimum. Offline replay remains available."}) $severity $state))
}
if ($IncludeOptionalModules) {
    foreach ($name in $optionalModules.Keys) {
        $minimum = $optionalModules[$name]
        $state = Get-InstalledModuleState -Name $name -MinimumVersion $minimum
        if (-not $state.Passed -and $InstallMissing -and $PSCmdlet.ShouldProcess("$name $minimum",'Install optional module')) {
            Install-Module $name -MinimumVersion $minimum -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -SkipPublisherCheck
            $state = Get-InstalledModuleState -Name $name -MinimumVersion $minimum
        }
        $checks.Add((New-RequirementCheck "Module: $name" $state.Passed $(if($state.Passed){"Installed $($state.Version)."}else{"Missing or below $minimum."}) 'Optional' $state))
    }
}

$canonical = @(
    'EntraAppExposure.psd1','EntraAppExposure.psm1','Public/Invoke-EntraAppExposure.ps1',
    'Private/Common.ps1','Private/Auth.ps1','Private/Graph.ps1','Private/Collection.ps1','Private/Snapshot.ps1','Private/Rules.ps1','Private/Drift.ps1','Private/Reporting.ps1','Private/Pipeline.ps1',
    'Rules/Baseline.json','Schemas/PortableAssessmentSnapshot.schema.json','Schemas/RulePack.schema.json'
)
$missing = @($canonical | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf) })
$checks.Add((New-RequirementCheck 'Canonical runtime inventory' ($missing.Count -eq 0) $(if($missing.Count -eq 0){'Canonical runtime inventory is complete.'}else{"Missing: $($missing -join ', ')"}) 'Required' $missing))

try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    $commands = @(Get-Command -Module EntraAppExposure -CommandType Function -ErrorAction Stop)
    if ($commands.Count -ne 1 -or $commands[0].Name -ne 'Invoke-EntraAppExposure') { throw "Expected exactly one public command; found $($commands.Name -join ', ')." }
    $checks.Add((New-RequirementCheck 'Canonical module import' $true 'Module imports and the public command resolves.'))
}
catch { $checks.Add((New-RequirementCheck 'Canonical module import' $false $_.Exception.Message)) }

if (-not $SkipAuthenticationConfiguration) {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path (Join-Path $HOME '.entra-app-exposure') 'config.json' }
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($name in @('TenantId','ClientId')) { $guid=[guid]::Empty; if(-not $config.PSObject.Properties[$name] -or -not [guid]::TryParse([string]$config.$name,[ref]$guid)){ throw "Config value '$name' must be a GUID." } }
        Import-Module Microsoft.PowerShell.SecretManagement -MinimumVersion 1.1.2 -ErrorAction Stop
        $vault = Get-SecretVault -Name $SecretVault -ErrorAction Stop
        if (-not $vault) { throw "Secret vault '$SecretVault' was not found." }
        $info = @(Get-SecretInfo -Name $SecretName -Vault $SecretVault -ErrorAction Stop)
        if ($info.Count -ne 1) { throw "Secret metadata '$SecretName' was not found in vault '$SecretVault'." }
        $checks.Add((New-RequirementCheck 'Authentication configuration' $true 'Local tenant/client metadata and SecretStore reference are present.'))
    }
    catch { $checks.Add((New-RequirementCheck 'Authentication configuration' $false $_.Exception.Message)) }
}

$requiredFailures = @($checks | Where-Object { $_.Severity -eq 'Required' -and -not $_.Passed })
$result = [pscustomobject]@{
    PSTypeName='EntraAppExposure.Requirements'; SchemaVersion='3.0.0'; Ready=($requiredFailures.Count -eq 0); ProjectRoot=$root;
    FailedRequiredChecks=@($requiredFailures | ForEach-Object Name); Checks=$checks.ToArray()
}
if ($AsJson) { $result | ConvertTo-Json -Depth 10; return }
foreach ($check in $checks) { Write-RequirementStatus "$($check.Name): $($check.Message)" $(if($check.Passed){'Success'}elseif($check.Severity -eq 'Required'){'Error'}else{'Warning'}) }
if ($result.Ready) { Write-RequirementStatus 'Environment is ready for Entra App Exposure.' 'Success' } else { Write-RequirementStatus "Required checks failed: $($result.FailedRequiredChecks -join ', ')" 'Error' }
return $result
