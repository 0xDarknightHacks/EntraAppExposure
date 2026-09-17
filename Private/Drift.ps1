<#
.SYNOPSIS
    Deterministic offline drift comparison between portable snapshots.

.DESCRIPTION
    Compares application registrations and service principals using canonical
    observations only. Removal/absence drift is emitted only when the relevant
    collection surface was complete in both snapshots.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppExposureObjectMap {
    param([Parameter(Mandatory=$true)]$Snapshot,[Parameter(Mandatory=$true)][ValidateSet('Applications','ServicePrincipals')][string]$Property)
    $map = @{}
    foreach ($item in @((Get-AppExposurePropertyValue -Object $Snapshot -Name $Property))) {
        $id = [string](Get-AppExposurePropertyValue -Object $item -Name 'ObjectId')
        if ($id) { $map[$id] = $item }
    }
    return $map
}

function Get-AppExposureObjectObservations {
    param([Parameter(Mandatory=$true)]$Snapshot,[Parameter(Mandatory=$true)][string]$ObjectId,[Parameter(Mandatory=$true)][string]$Category)
    return @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Observations') | Where-Object {
        [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') -eq $ObjectId -and
        [string](Get-AppExposurePropertyValue -Object $_ -Name 'Category') -eq $Category
    })
}

function Test-AppExposureSurfaceComparable {
    param([Parameter(Mandatory=$true)]$PreviousObject,[Parameter(Mandatory=$true)]$CurrentObject,[Parameter(Mandatory=$true)][string]$Surface)
    $previousCollection = Get-AppExposurePropertyValue -Object $PreviousObject -Name 'Collection'
    $currentCollection = Get-AppExposurePropertyValue -Object $CurrentObject -Name 'Collection'
    return [bool]([string](Get-AppExposurePropertyValue -Object $previousCollection -Name $Surface) -eq 'Complete' -and
                  [string](Get-AppExposurePropertyValue -Object $currentCollection -Name $Surface) -eq 'Complete')
}

function New-AppExposureDriftRecord {
    param(
        [Parameter(Mandatory=$true)][string]$ChangeType,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$ObjectId,
        [Parameter(Mandatory=$true)][string]$ObjectDisplayName,
        [Parameter(Mandatory=$true)][string]$IdentityKey,
        [Parameter(Mandatory=$false)]$PreviousObservation,
        [Parameter(Mandatory=$false)]$CurrentObservation
    )
    $evidenceIds = @()
    if ($PreviousObservation) { $evidenceIds += [string](Get-AppExposurePropertyValue -Object $PreviousObservation -Name 'ObservationId') }
    if ($CurrentObservation) { $evidenceIds += [string](Get-AppExposurePropertyValue -Object $CurrentObservation -Name 'ObservationId') }
    $description = switch ($Category) {
        'ApplicationRegistration' { "$ChangeType application registration: $IdentityKey" }
        'ApplicationOwner' { "$ChangeType application owner: $IdentityKey" }
        'ApplicationCredential' { "$ChangeType application credential: $IdentityKey" }
        'ApplicationPermission' { "$ChangeType application permission: $IdentityKey" }
        'DelegatedPermission' { "$ChangeType delegated permission: $IdentityKey" }
        'Owner' { "$ChangeType service principal owner: $IdentityKey" }
        'Credential' { "$ChangeType credential: $IdentityKey" }
        'ServicePrincipal' { "$ChangeType service principal state: $IdentityKey" }
        default { "$ChangeType ${Category}: $IdentityKey" }
    }
    return [PSCustomObject]@{
        ChangeType        = $ChangeType
        Category          = $Category
        ObjectId          = $ObjectId
        ObjectDisplayName = $ObjectDisplayName
        IdentityKey       = $IdentityKey
        Description       = $description
        PreviousValue     = if ($PreviousObservation) { Get-AppExposurePropertyValue -Object $PreviousObservation -Name 'Value' } else { $null }
        CurrentValue      = if ($CurrentObservation) { Get-AppExposurePropertyValue -Object $CurrentObservation -Name 'Value' } else { $null }
        EvidenceIds       = @($evidenceIds | Where-Object { $_ })
    }
}

function Add-AppExposureObservationSetDrift {
    param(
        [Parameter(Mandatory=$true)]$Changes,
        [Parameter(Mandatory=$true)]$PreviousSnapshot,
        [Parameter(Mandatory=$true)]$CurrentSnapshot,
        [Parameter(Mandatory=$true)][string]$ObjectId,
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][string]$Category
    )
    $previousMap = @{}
    foreach ($obs in @(Get-AppExposureObjectObservations -Snapshot $PreviousSnapshot -ObjectId $ObjectId -Category $Category)) { $previousMap[[string](Get-AppExposurePropertyValue -Object $obs -Name 'ObservationKey')] = $obs }
    $currentMap = @{}
    foreach ($obs in @(Get-AppExposureObjectObservations -Snapshot $CurrentSnapshot -ObjectId $ObjectId -Category $Category)) { $currentMap[[string](Get-AppExposurePropertyValue -Object $obs -Name 'ObservationKey')] = $obs }

    foreach ($key in @($currentMap.Keys | Where-Object { -not $previousMap.ContainsKey($_) })) {
        $obs = $currentMap[$key]
        $Changes.Add((New-AppExposureDriftRecord -ChangeType 'Added' -Category $Category -ObjectId $ObjectId -ObjectDisplayName $DisplayName -IdentityKey ([string](Get-AppExposurePropertyValue -Object $obs -Name 'IdentityKey')) -CurrentObservation $obs))
    }
    foreach ($key in @($previousMap.Keys | Where-Object { -not $currentMap.ContainsKey($_) })) {
        $obs = $previousMap[$key]
        $Changes.Add((New-AppExposureDriftRecord -ChangeType 'Removed' -Category $Category -ObjectId $ObjectId -ObjectDisplayName $DisplayName -IdentityKey ([string](Get-AppExposurePropertyValue -Object $obs -Name 'IdentityKey')) -PreviousObservation $obs))
    }
    foreach ($key in @($currentMap.Keys | Where-Object { $previousMap.ContainsKey($_) })) {
        $previousObs = $previousMap[$key]
        $currentObs = $currentMap[$key]
        if ([string](Get-AppExposurePropertyValue -Object $previousObs -Name 'Fingerprint') -ne [string](Get-AppExposurePropertyValue -Object $currentObs -Name 'Fingerprint')) {
            $Changes.Add((New-AppExposureDriftRecord -ChangeType 'Modified' -Category $Category -ObjectId $ObjectId -ObjectDisplayName $DisplayName -IdentityKey ([string](Get-AppExposurePropertyValue -Object $currentObs -Name 'IdentityKey')) -PreviousObservation $previousObs -CurrentObservation $currentObs))
        }
    }
}

function Compare-AppExposureSnapshots {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$PreviousSnapshot,[Parameter(Mandatory=$true)]$CurrentSnapshot)

    $previousTenant = [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $PreviousSnapshot -Name 'Tenant') -Name 'Id')
    $currentTenant = [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $CurrentSnapshot -Name 'Tenant') -Name 'Id')
    if ($previousTenant -ne $currentTenant) { throw 'Cannot compare snapshots from different tenants.' }
    $previousCollection = Get-AppExposurePropertyValue -Object $PreviousSnapshot -Name 'Collection'
    $currentCollection = Get-AppExposurePropertyValue -Object $CurrentSnapshot -Name 'Collection'
    $previousScope = [string](Get-AppExposurePropertyValue -Object $previousCollection -Name 'Scope')
    $currentScope = [string](Get-AppExposurePropertyValue -Object $currentCollection -Name 'Scope')
    if ($previousScope -ne $currentScope) { throw 'Cannot compare snapshots with different collection scopes.' }
    if ($currentScope -eq 'Single') {
        if ([string](Get-AppExposurePropertyValue -Object $previousCollection -Name 'ScopeTarget') -ne [string](Get-AppExposurePropertyValue -Object $currentCollection -Name 'ScopeTarget')) { throw 'Cannot compare Single-scope snapshots for different targets.' }
    }

    $changes = New-Object System.Collections.Generic.List[object]
    $previousApps = Get-AppExposureObjectMap -Snapshot $PreviousSnapshot -Property Applications
    $currentApps = Get-AppExposureObjectMap -Snapshot $CurrentSnapshot -Property Applications
    $previousSps = Get-AppExposureObjectMap -Snapshot $PreviousSnapshot -Property ServicePrincipals
    $currentSps = Get-AppExposureObjectMap -Snapshot $CurrentSnapshot -Property ServicePrincipals

    foreach ($id in @($currentApps.Keys | Where-Object { -not $previousApps.ContainsKey($_) })) {
        $app = $currentApps[$id]; $core = @(Get-AppExposureObjectObservations -Snapshot $CurrentSnapshot -ObjectId $id -Category 'ApplicationRegistration')
        $changes.Add((New-AppExposureDriftRecord -ChangeType 'Added' -Category 'ApplicationRegistration' -ObjectId $id -ObjectDisplayName ([string](Get-AppExposurePropertyValue -Object $app -Name 'DisplayName')) -IdentityKey 'Core' -CurrentObservation $core[0]))
    }
    foreach ($id in @($previousApps.Keys | Where-Object { -not $currentApps.ContainsKey($_) })) {
        $app = $previousApps[$id]; $core = @(Get-AppExposureObjectObservations -Snapshot $PreviousSnapshot -ObjectId $id -Category 'ApplicationRegistration')
        $changes.Add((New-AppExposureDriftRecord -ChangeType 'Removed' -Category 'ApplicationRegistration' -ObjectId $id -ObjectDisplayName ([string](Get-AppExposurePropertyValue -Object $app -Name 'DisplayName')) -IdentityKey 'Core' -PreviousObservation $core[0]))
    }
    foreach ($id in @($currentApps.Keys | Where-Object { $previousApps.ContainsKey($_) })) {
        $previousApp=$previousApps[$id]; $currentApp=$currentApps[$id]; $display=[string](Get-AppExposurePropertyValue -Object $currentApp -Name 'DisplayName')
        $previousCore=@(Get-AppExposureObjectObservations -Snapshot $PreviousSnapshot -ObjectId $id -Category 'ApplicationRegistration')
        $currentCore=@(Get-AppExposureObjectObservations -Snapshot $CurrentSnapshot -ObjectId $id -Category 'ApplicationRegistration')
        if ($previousCore.Count -eq 1 -and $currentCore.Count -eq 1 -and [string](Get-AppExposurePropertyValue -Object $previousCore[0] -Name 'Fingerprint') -ne [string](Get-AppExposurePropertyValue -Object $currentCore[0] -Name 'Fingerprint')) {
            $changes.Add((New-AppExposureDriftRecord -ChangeType 'Modified' -Category 'ApplicationRegistration' -ObjectId $id -ObjectDisplayName $display -IdentityKey 'Core' -PreviousObservation $previousCore[0] -CurrentObservation $currentCore[0]))
        }
        if (Test-AppExposureSurfaceComparable -PreviousObject $previousApp -CurrentObject $currentApp -Surface 'Owners') { Add-AppExposureObservationSetDrift -Changes $changes -PreviousSnapshot $PreviousSnapshot -CurrentSnapshot $CurrentSnapshot -ObjectId $id -DisplayName $display -Category 'ApplicationOwner' }
        if (Test-AppExposureSurfaceComparable -PreviousObject $previousApp -CurrentObject $currentApp -Surface 'Credentials') { Add-AppExposureObservationSetDrift -Changes $changes -PreviousSnapshot $PreviousSnapshot -CurrentSnapshot $CurrentSnapshot -ObjectId $id -DisplayName $display -Category 'ApplicationCredential' }
    }

    foreach ($id in @($currentSps.Keys | Where-Object { -not $previousSps.ContainsKey($_) })) {
        $sp=$currentSps[$id]; $core=@(Get-AppExposureObjectObservations -Snapshot $CurrentSnapshot -ObjectId $id -Category 'ServicePrincipal')
        $changes.Add((New-AppExposureDriftRecord -ChangeType 'Added' -Category 'ServicePrincipal' -ObjectId $id -ObjectDisplayName ([string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')) -IdentityKey 'Core' -CurrentObservation $core[0]))
    }
    foreach ($id in @($previousSps.Keys | Where-Object { -not $currentSps.ContainsKey($_) })) {
        $sp=$previousSps[$id]; $core=@(Get-AppExposureObjectObservations -Snapshot $PreviousSnapshot -ObjectId $id -Category 'ServicePrincipal')
        $changes.Add((New-AppExposureDriftRecord -ChangeType 'Removed' -Category 'ServicePrincipal' -ObjectId $id -ObjectDisplayName ([string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')) -IdentityKey 'Core' -PreviousObservation $core[0]))
    }

    $spCategorySurface = [ordered]@{ ApplicationPermission='ApplicationPermissions'; DelegatedPermission='DelegatedPermissions'; Owner='Owners'; Credential='Credentials' }
    foreach ($id in @($currentSps.Keys | Where-Object { $previousSps.ContainsKey($_) })) {
        $previousSp=$previousSps[$id]; $currentSp=$currentSps[$id]; $display=[string](Get-AppExposurePropertyValue -Object $currentSp -Name 'DisplayName')
        $previousCore=@(Get-AppExposureObjectObservations -Snapshot $PreviousSnapshot -ObjectId $id -Category 'ServicePrincipal')
        $currentCore=@(Get-AppExposureObjectObservations -Snapshot $CurrentSnapshot -ObjectId $id -Category 'ServicePrincipal')
        if ($previousCore.Count -eq 1 -and $currentCore.Count -eq 1 -and [string](Get-AppExposurePropertyValue -Object $previousCore[0] -Name 'Fingerprint') -ne [string](Get-AppExposurePropertyValue -Object $currentCore[0] -Name 'Fingerprint')) {
            $changes.Add((New-AppExposureDriftRecord -ChangeType 'Modified' -Category 'ServicePrincipal' -ObjectId $id -ObjectDisplayName $display -IdentityKey 'Core' -PreviousObservation $previousCore[0] -CurrentObservation $currentCore[0]))
        }
        foreach ($category in $spCategorySurface.Keys) {
            if (Test-AppExposureSurfaceComparable -PreviousObject $previousSp -CurrentObject $currentSp -Surface $spCategorySurface[$category]) {
                Add-AppExposureObservationSetDrift -Changes $changes -PreviousSnapshot $PreviousSnapshot -CurrentSnapshot $CurrentSnapshot -ObjectId $id -DisplayName $display -Category $category
            }
        }
    }

    return @($changes.ToArray())
}

