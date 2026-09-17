<#
.SYNOPSIS
    Validates source and release integrity for Entra App Exposure.
#>
[CmdletBinding()]
param([string]$RepositoryPath=(Split-Path -Parent $PSScriptRoot),[switch]$AsJson)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $RepositoryPath).Path
$violations=[System.Collections.Generic.List[string]]::new()

$required=@(
 'EntraAppExposure.psd1','EntraAppExposure.psm1','Public/Invoke-EntraAppExposure.ps1',
 'Private/Common.ps1','Private/Auth.ps1','Private/Graph.ps1','Private/Collection.ps1','Private/Snapshot.ps1','Private/Rules.ps1','Private/Drift.ps1','Private/Reporting.ps1','Private/Pipeline.ps1',
 'Rules/Baseline.json','Schemas/PortableAssessmentSnapshot.schema.json','Schemas/RulePack.schema.json','Tests/Run-Tests.ps1'
)
foreach($file in $required){if(-not(Test-Path -LiteralPath (Join-Path $root $file) -PathType Leaf)){$violations.Add("Missing canonical file: $file")}}

foreach($dir in @('Modules','Reports','OfflineReports','OfflineValidation','BaselineValidation','TestResults','Coverage','logs','snapshots','Tests/Support')){
    if(Test-Path -LiteralPath (Join-Path $root $dir) -PathType Container){$violations.Add("Generated or transitional directory present: $dir")}
}
foreach($legacy in @('Invoke-EntraAppExposure.ps1','EntraApplicationExposureAnalyzer.psd1','EntraApplicationExposureAnalyzer.psm1','Invoke-EntraApplicationExposureAnalyzer.ps1','OAuthApplicationIdentityExposureAnalyzer.psd1','testResults.xml')){
    if(Test-Path -LiteralPath (Join-Path $root $legacy)){$violations.Add("Legacy file present: $legacy")}
}
foreach($pattern in @('snapshot.json','findings.json','finding-groups.json','findings.csv','drift.json','run-summary.json','artifact-manifest.json','report.html','evidence.html','diagnostics.html','*.log','*.pfx','*.p12','*.pem','*.key','*.zip','*.7z','*.bak','*.tmp')){
    foreach($item in @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue)){
        if($item.FullName -notmatch '[\\/]Tests[\\/]'){$violations.Add("Generated/local file present: $([IO.Path]::GetRelativePath($root,$item.FullName))")}
    }
}

foreach($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1','*.psm1')){
    $tokens=$null;$errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    foreach($error in @($errors)){$violations.Add("PowerShell syntax: $([IO.Path]::GetRelativePath($root,$file.FullName)):$($error.Extent.StartLineNumber): $($error.Message)")}
}
try{Test-ModuleManifest -Path (Join-Path $root 'EntraAppExposure.psd1') -ErrorAction Stop|Out-Null}catch{$violations.Add("Manifest validation: $($_.Exception.Message)")}
try{
    $manifest=Import-PowerShellDataFile -Path (Join-Path $root 'EntraAppExposure.psd1')
    if([string]$manifest.ModuleVersion -ne '1.0.0'){$violations.Add("Stable release manifest ModuleVersion must be 1.0.0; found $($manifest.ModuleVersion).")}
    if($manifest.PrivateData.PSData.ContainsKey('Prerelease') -and -not [string]::IsNullOrWhiteSpace([string]$manifest.PrivateData.PSData.Prerelease)){$violations.Add('Stable release manifest must not define Prerelease metadata.')}
    if([string]$manifest.PrivateData.PSData.ProjectUri -ne 'https://github.com/0xDarknightHacks/EntraAppExposure'){$violations.Add('Manifest ProjectUri must point to the canonical public repository.')}
}catch{$violations.Add("Stable release metadata validation: $($_.Exception.Message)")}

try{
    $baseline=Get-Content -LiteralPath (Join-Path $root 'Rules/Baseline.json') -Raw|ConvertFrom-Json -ErrorAction Stop
    $definitions=@($baseline.Definitions)
    if($baseline.SchemaVersion -ne '2.1'){$violations.Add('Rule baseline SchemaVersion must be 2.1.')}
    if($definitions.Count -lt 25){$violations.Add("Rule baseline is unexpectedly small: $($definitions.Count) definitions.")}
    $ids=@($definitions|ForEach-Object{[string]$_.Id})
    if(@($ids|Sort-Object -Unique).Count -ne $ids.Count){$violations.Add('Rule baseline contains duplicate rule IDs.')}
    foreach($id in $ids){if($id -notmatch '^EAE-[A-Z]+(?:-[A-Z]+)*-[0-9]{3}$'){$violations.Add("Invalid rule ID taxonomy: $id")}}
}catch{$violations.Add("Rule baseline validation: $($_.Exception.Message)")}

$privateDirs=@(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -Directory -ErrorAction SilentlyContinue)
if($privateDirs.Count -gt 0){$violations.Add("Private runtime must remain flat; nested directories found: $($privateDirs.Name -join ', ')")}
$privateFiles=@(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1')
if($privateFiles.Count -ne 9){$violations.Add("Expected 9 compact private runtime files, found $($privateFiles.Count).")}

$graphText=Get-Content -LiteralPath (Join-Path $root 'Private/Graph.ps1') -Raw
if($graphText -notmatch 'Invoke-RestMethod'){$violations.Add('Graph transport boundary does not contain the expected read-only HTTP transport.')}
$outsideGraph=@(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1'|Where-Object{$_.Name -notin @('Graph.ps1','Auth.ps1')})
$outsideGraph+=@(Get-ChildItem -LiteralPath (Join-Path $root 'Public') -File -Filter '*.ps1')
if((($outsideGraph|Get-Content -Raw)-join "`n") -match 'Invoke-RestMethod|Invoke-MgGraphRequest|Connect-MgGraph|Get-MgContext|Disconnect-MgGraph'){$violations.Add('Raw Graph/HTTP transport escaped the Auth/Graph boundary.')}

$sourceFiles=@(Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1','*.psm1','*.psd1','*.md','*.yml','*.yaml' | Where-Object { $_.FullName -ne $PSCommandPath })
$sourceText=($sourceFiles|Get-Content -Raw)-join "`n"
$legacyNamespace = ('OAuth' + 'Analyzer')
if($sourceText -match ('\b' + [regex]::Escape($legacyNamespace) + '\b')){$violations.Add('Legacy internal namespace remains in source.')}
$reportingSource=Get-Content -LiteralPath (Join-Path $root 'Private/Reporting.ps1') -Raw
if($reportingSource -match 'class="ms-mark"|aria-label="Microsoft"'){$violations.Add('Microsoft logo/mark remnants remain in source reporting markup.')}

$result=[pscustomobject]@{PSTypeName='EntraAppExposure.ReleaseValidation';SchemaVersion='3.0.0';ReleaseEligible=$violations.Count -eq 0;ProjectRoot=$root;Violations=$violations.ToArray()}
if($AsJson){$result|ConvertTo-Json -Depth 6;return}
if($result.ReleaseEligible){Write-Host '[OK] Entra App Exposure release integrity check passed.' -ForegroundColor Green}else{Write-Host "[X] Release integrity failed:`n$($violations|ForEach-Object{' - '+$_}|Out-String)" -ForegroundColor Red}
return $result
