Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:EntraAppExposureRoot = $PSScriptRoot

$privateFiles = @(
    'Private/Common.ps1',
    'Private/Auth.ps1',
    'Private/Graph.ps1',
    'Private/Collection.ps1',
    'Private/Snapshot.ps1',
    'Private/Rules.ps1',
    'Private/Drift.ps1',
    'Private/Reporting.ps1',
    'Private/Pipeline.ps1'
)

$publicFiles = @('Public/Invoke-EntraAppExposure.ps1')

foreach ($relativePath in ($privateFiles + $publicFiles)) {
    $path = Join-Path $PSScriptRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required module file was not found: $path"
    }
    . $path
}

Export-ModuleMember -Function 'Invoke-EntraAppExposure'
