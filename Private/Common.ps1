<# Shared object/path helpers for Entra App Exposure. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function ConvertTo-AppExposureSafePathName {
    param([Parameter(Mandatory = $true)][string]$Name)
    $safe = $Name.Trim()
    foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) { $safe = $safe.Replace($c, '_') }
    $safe = $safe -replace '\s+', '_'
    $safe = $safe -replace '_{2,}', '_'
    $safe = $safe.Trim('_')
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'Unknown_Client' }
    return $safe
}

function Get-AppExposurePropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        foreach ($key in @($Object.Keys)) {
            if ([string]$key -ieq $Name) { return $Object[$key] }
        }
        return $null
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Test-AppExposurePropertyExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $true }
        foreach ($key in @($Object.Keys)) { if ([string]$key -ieq $Name) { return $true } }
        return $false
    }
    return [bool]($null -ne $Object.PSObject.Properties[$Name])
}

function New-AppExposureLocalCollectionResult {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $false)][string]$Error
    )
    return [PSCustomObject]@{
        CollectionState = $State
        SourceUri       = $null
        Error           = $Error
        Items           = @()
    }
}

function Get-AppExposureSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}


<# Runtime phase timing helpers for Entra App Exposure. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Complete-AppExposurePhase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][System.Diagnostics.Stopwatch]$Stopwatch,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$PhaseTimings
    )
    $Stopwatch.Stop()
    $milliseconds = [int64][Math]::Round($Stopwatch.Elapsed.TotalMilliseconds)
    $PhaseTimings[$Name] = $milliseconds
    Write-Verbose ("Phase {0}: {1:n2} s" -f $Name, ($milliseconds / 1000.0))
}


<# Microsoft Graph transport telemetry state and accessors. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$script:GraphTelemetry = [ordered]@{ StartedAtUtc=[datetime]::UtcNow.ToString('o'); Requests=0; Pages=0; BatchRequests=0; BatchSubRequests=0; Retries=0; Throttles=0; ServiceUnavailable=0; TransportFailures=0; LastRequestUtc=$null }

function Reset-AppExposureGraphTelemetry {
    [CmdletBinding()]
    param()

    $script:GraphTelemetry = [ordered]@{
        StartedAtUtc        = [datetime]::UtcNow.ToString('o')
        Requests            = 0
        Pages               = 0
        BatchRequests       = 0
        BatchSubRequests    = 0
        Retries             = 0
        Throttles           = 0
        ServiceUnavailable  = 0
        TransportFailures   = 0
        LastRequestUtc      = $null
    }
}

function Get-AppExposureGraphTelemetry {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        StartedAtUtc        = $script:GraphTelemetry.StartedAtUtc
        Requests            = [int]$script:GraphTelemetry.Requests
        Pages               = [int]$script:GraphTelemetry.Pages
        BatchRequests       = [int]$script:GraphTelemetry.BatchRequests
        BatchSubRequests    = [int]$script:GraphTelemetry.BatchSubRequests
        Retries             = [int]$script:GraphTelemetry.Retries
        Throttles           = [int]$script:GraphTelemetry.Throttles
        ServiceUnavailable  = [int]$script:GraphTelemetry.ServiceUnavailable
        TransportFailures   = [int]$script:GraphTelemetry.TransportFailures
        LastRequestUtc      = $script:GraphTelemetry.LastRequestUtc
    }
}


<#
.SYNOPSIS
    Microsoft Entra portal deep-link helpers used by offline reports.
.DESCRIPTION
    Adapted from the sibling EntraTopology navigation pattern. URL generation is
    deterministic and requires no Microsoft Graph access.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppExposurePortalBaseUri {
    [CmdletBinding()]
    param([AllowNull()][string]$TenantId)

    if ([string]::IsNullOrWhiteSpace($TenantId)) { return 'https://entra.microsoft.com' }
    return "https://entra.microsoft.com/$([uri]::EscapeDataString($TenantId))"
}

function Get-AppExposurePortalUri {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$TenantId,
        [Parameter(Mandatory)][ValidateSet('Application','ServicePrincipal')][string]$Kind,
        [AllowNull()][string]$ObjectId,
        [AllowNull()][string]$AppId
    )

    $base = Get-AppExposurePortalBaseUri -TenantId $TenantId
    $escapedObjectId = if ($ObjectId) { [uri]::EscapeDataString($ObjectId) } else { '' }
    $escapedAppId = if ($AppId) { [uri]::EscapeDataString($AppId) } else { '' }

    switch ($Kind) {
        'Application' {
            if ($escapedAppId) { return "$base/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$escapedAppId" }
        }
        'ServicePrincipal' {
            if ($escapedObjectId -and $escapedAppId) { return "$base/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$escapedObjectId/appId/$escapedAppId" }
        }
    }
    return $null
}

