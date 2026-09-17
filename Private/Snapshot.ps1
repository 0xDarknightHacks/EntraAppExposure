<#
.SYNOPSIS
    Portable snapshot model and evidence normalization.

.DESCRIPTION
    Converts completed live collection results into an immutable JSON-serializable
    snapshot. Application registrations and service principals are both first-class
    assessment objects. The snapshot is the only input required by findings, drift,
    and reporting modules; those modules do not call Microsoft Graph.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:SnapshotSchemaVersion = '2.1'

function Get-AppExposureObservationFingerprintValue {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)]$Value
    )

    switch ($Category) {
        'ApplicationPermission' {
            return [PSCustomObject][ordered]@{
                ResourceId = Get-AppExposurePropertyValue -Object $Value -Name 'ResourceId'
                AppRoleId  = Get-AppExposurePropertyValue -Object $Value -Name 'AppRoleId'
            }
        }
        'DelegatedPermission' {
            return [PSCustomObject][ordered]@{
                ResourceId      = Get-AppExposurePropertyValue -Object $Value -Name 'ResourceId'
                ConsentType     = Get-AppExposurePropertyValue -Object $Value -Name 'ConsentType'
                PrincipalId     = Get-AppExposurePropertyValue -Object $Value -Name 'PrincipalId'
                PermissionValue = Get-AppExposurePropertyValue -Object $Value -Name 'PermissionValue'
            }
        }
        { $_ -in @('Owner', 'ApplicationOwner') } {
            return [PSCustomObject][ordered]@{
                ObjectType     = Get-AppExposurePropertyValue -Object $Value -Name 'ObjectType'
                UserType       = Get-AppExposurePropertyValue -Object $Value -Name 'UserType'
                AccountEnabled = Get-AppExposurePropertyValue -Object $Value -Name 'AccountEnabled'
            }
        }
        { $_ -in @('Credential', 'ApplicationCredential') } {
            return [PSCustomObject][ordered]@{
                CredentialType = Get-AppExposurePropertyValue -Object $Value -Name 'CredentialType'
                KeyId          = Get-AppExposurePropertyValue -Object $Value -Name 'KeyId'
                StartDateTime  = Get-AppExposurePropertyValue -Object $Value -Name 'StartDateTime'
                EndDateTime    = Get-AppExposurePropertyValue -Object $Value -Name 'EndDateTime'
            }
        }
        default { return $Value }
    }
}

function New-AppExposureObservation {
    param(
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$ObjectDisplayName,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$IdentityKey,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $false)]$FingerprintValue,
        [Parameter(Mandatory = $false)][string]$SourceUri,
        [Parameter(Mandatory = $true)][string]$CollectedAtUtc
    )

    $stableKey = "$ObjectId|$Category|$IdentityKey"
    $fingerprintInput = if ($PSBoundParameters.ContainsKey('FingerprintValue')) { $FingerprintValue } else { Get-AppExposureObservationFingerprintValue -Category $Category -Value $Value }
    $fingerprintJson = ConvertTo-Json -InputObject $fingerprintInput -Depth 20 -Compress
    $idHash = Get-AppExposureSha256 -Text $stableKey
    $fingerprint = Get-AppExposureSha256 -Text $fingerprintJson

    return [PSCustomObject]@{
        ObservationId     = "OBS-$($idHash.Substring(0, 24))"
        ObservationKey    = $stableKey
        ObjectId          = $ObjectId
        ObjectDisplayName = $ObjectDisplayName
        Category          = $Category
        IdentityKey       = $IdentityKey
        Fingerprint       = $fingerprint
        SourceUri         = $SourceUri
        CollectedAtUtc    = $CollectedAtUtc
        Value             = $Value
    }
}

function Add-AppExposureCanonicalObservation {
    param(
        [Parameter(Mandatory = $true)]$Observation,
        [Parameter(Mandatory = $true)]$ObservationByKey,
        [Parameter(Mandatory = $true)]$CanonicalObservations
    )

    $key = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'ObservationKey')
    $fingerprint = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'Fingerprint')
    if (-not $ObservationByKey.ContainsKey($key)) {
        $ObservationByKey[$key] = $Observation
        $CanonicalObservations.Add($Observation)
        return
    }

    $existingFingerprint = [string](Get-AppExposurePropertyValue -Object $ObservationByKey[$key] -Name 'Fingerprint')
    if ($existingFingerprint -eq $fingerprint) { return }
    throw "Observation identity collision for '$key': duplicate semantic key produced different fingerprints. Refine the observation IdentityKey instead of discarding evidence."
}


function New-AppExposureObservationValidationIndex {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Observations)

    $index = @{}
    foreach ($observation in @($Observations)) {
        if ($null -eq $observation) { continue }
        $objectId = [string](Get-AppExposurePropertyValue -Object $observation -Name 'ObjectId')
        $category = [string](Get-AppExposurePropertyValue -Object $observation -Name 'Category')
        $identityKey = [string](Get-AppExposurePropertyValue -Object $observation -Name 'IdentityKey')
        if ([string]::IsNullOrWhiteSpace($objectId) -or [string]::IsNullOrWhiteSpace($category) -or [string]::IsNullOrWhiteSpace($identityKey)) { continue }
        if (-not $index.ContainsKey($objectId)) { $index[$objectId] = @{} }
        if (-not $index[$objectId].ContainsKey($category)) { $index[$objectId][$category] = @{} }
        if (-not $index[$objectId][$category].ContainsKey($identityKey)) {
            $index[$objectId][$category][$identityKey] = New-Object System.Collections.Generic.List[object]
        }
        $index[$objectId][$category][$identityKey].Add($observation)
    }
    return $index
}

function Get-AppExposureIndexedObservations {
    param(
        [Parameter(Mandatory = $true)]$ObservationIndex,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$IdentityKey
    )

    if (-not $ObservationIndex.ContainsKey($ObjectId)) { return @() }
    if (-not $ObservationIndex[$ObjectId].ContainsKey($Category)) { return @() }
    if (-not $ObservationIndex[$ObjectId][$Category].ContainsKey($IdentityKey)) { return @() }
    return @($ObservationIndex[$ObjectId][$Category][$IdentityKey].ToArray())
}

function New-AppExposureSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $false)][string]$TenantName,
        [Parameter(Mandatory = $false)][string]$ClientName,
        [Parameter(Mandatory = $false)][string]$ConsultantName,
        [Parameter(Mandatory = $true)][ValidateSet('All', 'Single')][string]$Scope,
        [Parameter(Mandatory = $false)][string]$ScopeTarget,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Applications,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipalAssessments,
        [Parameter(Mandatory = $false)]$GraphTelemetry,
        [Parameter(Mandatory = $false)][string]$CollectedAtUtc = ([datetime]::UtcNow.ToString('o'))
    )

    $rawObservations = New-Object System.Collections.Generic.List[object]
    $snapshotApps = New-Object System.Collections.Generic.List[object]
    $snapshotSps = New-Object System.Collections.Generic.List[object]
    $coreIncomplete = New-Object System.Collections.Generic.List[string]

    foreach ($app in @($Applications)) {
        if ($null -eq $app) { continue }
        $objectId = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        $displayName = [string](Get-AppExposurePropertyValue -Object $app -Name 'DisplayName')
        if ([string]::IsNullOrWhiteSpace($objectId)) { throw 'Application assessment is missing ObjectId.' }

        $owners = Get-AppExposurePropertyValue -Object $app -Name 'Owners'
        $credentials = Get-AppExposurePropertyValue -Object $app -Name 'Credentials'
        $ownerState = [string](Get-AppExposurePropertyValue -Object $owners -Name 'CollectionState')
        $credentialState = [string](Get-AppExposurePropertyValue -Object $credentials -Name 'CollectionState')
        $coreComplete = ($ownerState -eq 'Complete') -and ($credentialState -eq 'Complete')
        if (-not $coreComplete) { $coreIncomplete.Add($objectId) }

        $linkedSpIds = @((Get-AppExposurePropertyValue -Object $app -Name 'LinkedServicePrincipalIds') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $coreValue = [PSCustomObject][ordered]@{
            AppId                     = Get-AppExposurePropertyValue -Object $app -Name 'AppId'
            CreatedDateTime           = Get-AppExposurePropertyValue -Object $app -Name 'CreatedDateTime'
            SignInAudience            = Get-AppExposurePropertyValue -Object $app -Name 'SignInAudience'
            PublisherDomain           = Get-AppExposurePropertyValue -Object $app -Name 'PublisherDomain'
            VerifiedPublisher         = Get-AppExposurePropertyValue -Object $app -Name 'VerifiedPublisher'
            Authentication            = Get-AppExposurePropertyValue -Object $app -Name 'Authentication'
            ApiConfiguration          = Get-AppExposurePropertyValue -Object $app -Name 'ApiConfiguration'
            LinkedServicePrincipalIds = $linkedSpIds
        }
        $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ApplicationRegistration' -IdentityKey 'Core' -Value $coreValue -SourceUri 'https://graph.microsoft.com/v1.0/applications' -CollectedAtUtc $CollectedAtUtc))

        foreach ($surface in @('Owners', 'Credentials')) {
            $result = if ($surface -eq 'Owners') { $owners } else { $credentials }
            $state = if ($surface -eq 'Owners') { $ownerState } else { $credentialState }
            $stateValue = [PSCustomObject][ordered]@{ Surface = $surface; State = $state }
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ApplicationCollectionState' -IdentityKey $surface -Value $stateValue -SourceUri (Get-AppExposurePropertyValue -Object $result -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }

        foreach ($item in @((Get-AppExposurePropertyValue -Object $owners -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $identity = [string](Get-AppExposurePropertyValue -Object $item -Name 'OwnerId')
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ApplicationOwner' -IdentityKey $identity -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $owners -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }
        foreach ($item in @((Get-AppExposurePropertyValue -Object $credentials -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $credentialType = Get-AppExposurePropertyValue -Object $item -Name 'CredentialType'
            $keyId = Get-AppExposurePropertyValue -Object $item -Name 'KeyId'
            $identity = "$credentialType|$keyId"
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ApplicationCredential' -IdentityKey $identity -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $credentials -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }

        $snapshotApps.Add([PSCustomObject]@{
            ObjectId                  = $objectId
            AppId                     = Get-AppExposurePropertyValue -Object $app -Name 'AppId'
            DisplayName               = $displayName
            CreatedDateTime           = Get-AppExposurePropertyValue -Object $app -Name 'CreatedDateTime'
            SignInAudience            = Get-AppExposurePropertyValue -Object $app -Name 'SignInAudience'
            PublisherDomain           = Get-AppExposurePropertyValue -Object $app -Name 'PublisherDomain'
            VerifiedPublisher         = Get-AppExposurePropertyValue -Object $app -Name 'VerifiedPublisher'
            Authentication            = Get-AppExposurePropertyValue -Object $app -Name 'Authentication'
            ApiConfiguration          = Get-AppExposurePropertyValue -Object $app -Name 'ApiConfiguration'
            LinkedServicePrincipalIds = $linkedSpIds
            IsOrphan                  = [bool]($linkedSpIds.Count -eq 0)
            Collection                = [PSCustomObject]@{
                CoreComplete = $coreComplete
                Owners       = $ownerState
                Credentials  = $credentialState
            }
        })
    }

    foreach ($sp in @($ServicePrincipalAssessments)) {
        if ($null -eq $sp) { continue }
        $objectId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        $displayName = [string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')
        if ([string]::IsNullOrWhiteSpace($objectId)) { throw 'Service principal assessment is missing ObjectId.' }

        $appPerms = Get-AppExposurePropertyValue -Object $sp -Name 'ApplicationPermissions'
        $delegated = Get-AppExposurePropertyValue -Object $sp -Name 'DelegatedPermissions'
        $owners = Get-AppExposurePropertyValue -Object $sp -Name 'Owners'
        $credentials = Get-AppExposurePropertyValue -Object $sp -Name 'Credentials'
        $activity = Get-AppExposurePropertyValue -Object $sp -Name 'Activity'

        $surfaceStates = [ordered]@{
            ApplicationPermissions = [string](Get-AppExposurePropertyValue -Object $appPerms -Name 'CollectionState')
            DelegatedPermissions   = [string](Get-AppExposurePropertyValue -Object $delegated -Name 'CollectionState')
            Owners                 = [string](Get-AppExposurePropertyValue -Object $owners -Name 'CollectionState')
            Credentials            = [string](Get-AppExposurePropertyValue -Object $credentials -Name 'CollectionState')
            Activity               = [string](Get-AppExposurePropertyValue -Object $activity -Name 'CollectionState')
        }

        $coreComplete = ($surfaceStates.ApplicationPermissions -eq 'Complete') -and
                        ($surfaceStates.DelegatedPermissions -eq 'Complete') -and
                        ($surfaceStates.Owners -in @('Complete', 'NotApplicable')) -and
                        ($surfaceStates.Credentials -in @('Complete', 'NotApplicable'))
        if (-not $coreComplete) { $coreIncomplete.Add($objectId) }

        $coreValue = [PSCustomObject][ordered]@{
            AppId                   = Get-AppExposurePropertyValue -Object $sp -Name 'AppId'
            Classification          = Get-AppExposurePropertyValue -Object $sp -Name 'Classification'
            ServicePrincipalType    = Get-AppExposurePropertyValue -Object $sp -Name 'ServicePrincipalType'
            AppOwnerOrganizationId  = Get-AppExposurePropertyValue -Object $sp -Name 'AppOwnerOrganizationId'
            AccountEnabled          = Get-AppExposurePropertyValue -Object $sp -Name 'AccountEnabled'
            CreatedDateTime         = Get-AppExposurePropertyValue -Object $sp -Name 'CreatedDateTime'
            AppRegistrationObjectId = Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId'
            VerifiedPublisher       = Get-AppExposurePropertyValue -Object $sp -Name 'VerifiedPublisher'
        }
        $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ServicePrincipal' -IdentityKey 'Core' -Value $coreValue -SourceUri 'https://graph.microsoft.com/v1.0/servicePrincipals' -CollectedAtUtc $CollectedAtUtc))

        foreach ($surface in $surfaceStates.Keys) {
            $stateValue = [PSCustomObject][ordered]@{ Surface = $surface; State = $surfaceStates[$surface] }
            $sourceResult = switch ($surface) {
                'ApplicationPermissions' { $appPerms }
                'DelegatedPermissions' { $delegated }
                'Owners' { $owners }
                'Credentials' { $credentials }
                'Activity' { $activity }
            }
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'CollectionState' -IdentityKey $surface -Value $stateValue -SourceUri (Get-AppExposurePropertyValue -Object $sourceResult -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }

        foreach ($item in @((Get-AppExposurePropertyValue -Object $appPerms -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $resourceId = Get-AppExposurePropertyValue -Object $item -Name 'ResourceId'
            $appRoleId = Get-AppExposurePropertyValue -Object $item -Name 'AppRoleId'
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'ApplicationPermission' -IdentityKey "$resourceId|$appRoleId" -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $appPerms -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }
        foreach ($item in @((Get-AppExposurePropertyValue -Object $delegated -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $resourceId = Get-AppExposurePropertyValue -Object $item -Name 'ResourceId'
            $consentType = Get-AppExposurePropertyValue -Object $item -Name 'ConsentType'
            $principalId = Get-AppExposurePropertyValue -Object $item -Name 'PrincipalId'
            $permissionValue = Get-AppExposurePropertyValue -Object $item -Name 'PermissionValue'
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'DelegatedPermission' -IdentityKey "$resourceId|$consentType|$principalId|$permissionValue" -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $delegated -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }
        foreach ($item in @((Get-AppExposurePropertyValue -Object $owners -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'Owner' -IdentityKey ([string](Get-AppExposurePropertyValue -Object $item -Name 'OwnerId')) -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $owners -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }
        foreach ($item in @((Get-AppExposurePropertyValue -Object $credentials -Name 'Items'))) {
            if ($null -eq $item) { continue }
            $credentialType = Get-AppExposurePropertyValue -Object $item -Name 'CredentialType'
            $keyId = Get-AppExposurePropertyValue -Object $item -Name 'KeyId'
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'Credential' -IdentityKey "$credentialType|$keyId" -Value $item -SourceUri (Get-AppExposurePropertyValue -Object $credentials -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }
        if ($activity -and (Get-AppExposurePropertyValue -Object $activity -Name 'CollectionState') -eq 'Complete') {
            $activityValue = [PSCustomObject][ordered]@{
                SourceKind         = Get-AppExposurePropertyValue -Object $activity -Name 'SourceKind'
                LookbackDays       = Get-AppExposurePropertyValue -Object $activity -Name 'LookbackDays'
                LastSignInDateTime = Get-AppExposurePropertyValue -Object $activity -Name 'LastSignInDateTime'
                ApplicationAuthenticationClientLastSignInDateTime = Get-AppExposurePropertyValue -Object $activity -Name 'ApplicationAuthenticationClientLastSignInDateTime'
                ApplicationAuthenticationResourceLastSignInDateTime = Get-AppExposurePropertyValue -Object $activity -Name 'ApplicationAuthenticationResourceLastSignInDateTime'
                DelegatedClientLastSignInDateTime = Get-AppExposurePropertyValue -Object $activity -Name 'DelegatedClientLastSignInDateTime'
                DelegatedResourceLastSignInDateTime = Get-AppExposurePropertyValue -Object $activity -Name 'DelegatedResourceLastSignInDateTime'
                NoActivityObserved = Get-AppExposurePropertyValue -Object $activity -Name 'NoActivityObserved'
            }
            $rawObservations.Add((New-AppExposureObservation -ObjectId $objectId -ObjectDisplayName $displayName -Category 'Activity' -IdentityKey 'Lookback' -Value $activityValue -SourceUri (Get-AppExposurePropertyValue -Object $activity -Name 'SourceUri') -CollectedAtUtc $CollectedAtUtc))
        }

        $snapshotSps.Add([PSCustomObject]@{
            ObjectId                = $objectId
            AppId                   = Get-AppExposurePropertyValue -Object $sp -Name 'AppId'
            DisplayName             = $displayName
            Classification          = Get-AppExposurePropertyValue -Object $sp -Name 'Classification'
            ServicePrincipalType    = Get-AppExposurePropertyValue -Object $sp -Name 'ServicePrincipalType'
            AppOwnerOrganizationId  = Get-AppExposurePropertyValue -Object $sp -Name 'AppOwnerOrganizationId'
            AccountEnabled          = Get-AppExposurePropertyValue -Object $sp -Name 'AccountEnabled'
            CreatedDateTime         = Get-AppExposurePropertyValue -Object $sp -Name 'CreatedDateTime'
            AppRegistrationObjectId = Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId'
            VerifiedPublisher       = Get-AppExposurePropertyValue -Object $sp -Name 'VerifiedPublisher'
            Collection              = [PSCustomObject]@{
                CoreComplete           = $coreComplete
                ApplicationPermissions = $surfaceStates.ApplicationPermissions
                DelegatedPermissions   = $surfaceStates.DelegatedPermissions
                Owners                 = $surfaceStates.Owners
                Credentials            = $surfaceStates.Credentials
                Activity               = $surfaceStates.Activity
            }
        })
    }

    $canonicalObservations = New-Object System.Collections.Generic.List[object]
    $observationByKey = @{}
    foreach ($observation in @($rawObservations.ToArray())) {
        Add-AppExposureCanonicalObservation -Observation $observation -ObservationByKey $observationByKey -CanonicalObservations $canonicalObservations
    }

    $snapshotAppArray = @($snapshotApps.ToArray())
    $snapshotSpArray = @($snapshotSps.ToArray())
    $incompleteIds = @($coreIncomplete.ToArray() | Where-Object { $_ } | Sort-Object -Unique)
    return [PSCustomObject]@{
        SchemaVersion  = $script:SnapshotSchemaVersion
        SnapshotId     = [guid]::NewGuid().Guid
        CollectedAtUtc = $CollectedAtUtc
        Tenant         = [PSCustomObject]@{ Id = $TenantId; Name = $TenantName }
        Assessment     = [PSCustomObject]@{ ClientName = $ClientName; ConsultantName = $ConsultantName }
        Collection     = [PSCustomObject]@{
            Scope                 = $Scope
            ScopeTarget           = $ScopeTarget
            CoreComplete          = [bool]($incompleteIds.Count -eq 0)
            IncompleteObjectIds   = $incompleteIds
            ApplicationCount      = $snapshotAppArray.Count
            OrphanApplicationCount = @($snapshotAppArray | Where-Object { [bool](Get-AppExposurePropertyValue -Object $_ -Name 'IsOrphan') }).Count
            ServicePrincipalCount = $snapshotSpArray.Count
            ObservationCount      = $canonicalObservations.Count
            GraphTelemetry        = $GraphTelemetry
        }
        Applications      = $snapshotAppArray
        ServicePrincipals = $snapshotSpArray
        Observations      = @($canonicalObservations.ToArray())
    }
}

function Test-AppExposureSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Snapshot)

    $errors = New-Object System.Collections.Generic.List[string]
    $schemaVersion = [string](Get-AppExposurePropertyValue -Object $Snapshot -Name 'SchemaVersion')
    if (-not $schemaVersion) { $errors.Add('SchemaVersion is missing.') }
    elseif ($schemaVersion -ne $script:SnapshotSchemaVersion) { $errors.Add("Unsupported SchemaVersion '$schemaVersion'. Expected $script:SnapshotSchemaVersion.") }
    if (-not (Get-AppExposurePropertyValue -Object $Snapshot -Name 'SnapshotId')) { $errors.Add('SnapshotId is missing.') }
    if (-not (Get-AppExposurePropertyValue -Object $Snapshot -Name 'CollectedAtUtc')) { $errors.Add('CollectedAtUtc is missing.') }
    $tenant = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Tenant'
    if (-not $tenant -or -not (Get-AppExposurePropertyValue -Object $tenant -Name 'Id')) { $errors.Add('Tenant.Id is missing.') }

    $collection = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Collection'
    if (-not $collection) { $errors.Add('Collection is missing.') }
    else {
        $scope = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Scope')
        if ($scope -notin @('All', 'Single')) { $errors.Add("Collection.Scope '$scope' is invalid.") }
        if ($scope -eq 'Single' -and -not (Get-AppExposurePropertyValue -Object $collection -Name 'ScopeTarget')) { $errors.Add('Collection.ScopeTarget is required for Single scope.') }
        $telemetry = Get-AppExposurePropertyValue -Object $collection -Name 'GraphTelemetry'
        if ($telemetry) {
            $requests = Get-AppExposurePropertyValue -Object $telemetry -Name 'Requests'
            if ($null -eq $requests -or -not ($requests -is [byte] -or $requests -is [int16] -or $requests -is [int32] -or $requests -is [int64] -or $requests -is [uint16] -or $requests -is [uint32] -or $requests -is [uint64])) {
                $errors.Add('Collection.GraphTelemetry.Requests must be numeric when telemetry is present.')
            }
            elseif ([int64]$requests -lt 0) { $errors.Add('Collection.GraphTelemetry.Requests cannot be negative.') }
        }
    }

    $applications = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Applications'))
    $servicePrincipals = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'ServicePrincipals'))
    $observations = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Observations'))
    $observationIndex = New-AppExposureObservationValidationIndex -Observations $observations
    if ($collection) {
        $applicationCount = Get-AppExposurePropertyValue -Object $collection -Name 'ApplicationCount'
        $servicePrincipalCount = Get-AppExposurePropertyValue -Object $collection -Name 'ServicePrincipalCount'
        $observationCount = Get-AppExposurePropertyValue -Object $collection -Name 'ObservationCount'
        if ($null -eq $applicationCount -or [int]$applicationCount -ne $applications.Count) { $errors.Add('Collection.ApplicationCount does not match Applications.') }
        if ($null -eq $servicePrincipalCount -or [int]$servicePrincipalCount -ne $servicePrincipals.Count) { $errors.Add('Collection.ServicePrincipalCount does not match ServicePrincipals.') }
        if ($null -eq $observationCount -or [int]$observationCount -ne $observations.Count) { $errors.Add('Collection.ObservationCount does not match Observations.') }
        $expectedOrphanCount = @($applications | Where-Object { [bool](Get-AppExposurePropertyValue -Object $_ -Name 'IsOrphan') }).Count
        $orphanCount = Get-AppExposurePropertyValue -Object $collection -Name 'OrphanApplicationCount'
        if ($null -eq $orphanCount -or [int]$orphanCount -ne $expectedOrphanCount) { $errors.Add('Collection.OrphanApplicationCount does not match Applications.') }
        if (-not (Test-AppExposurePropertyExists -Object $collection -Name 'CoreComplete')) { $errors.Add('Collection.CoreComplete is missing.') }
        # IncompleteObjectIds is legitimately an empty array for a complete snapshot. Testing
        # its value through Get-AppExposurePropertyValue would collapse @() to $null because
        # PowerShell enumerates function output, incorrectly treating the property as absent.
        if (-not (Test-AppExposurePropertyExists -Object $collection -Name 'IncompleteObjectIds')) { $errors.Add('Collection.IncompleteObjectIds is missing.') }
    }

    $appIds = @($applications | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') })
    $spIds = @($servicePrincipals | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') })
    if (@($appIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $errors.Add('One or more application ObjectId values are missing.') }
    if (@($spIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $errors.Add('One or more service principal ObjectId values are missing.') }
    if (@($appIds | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) { $errors.Add('Application ObjectId values are not unique.') }
    if (@($spIds | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) { $errors.Add('Service principal ObjectId values are not unique.') }
    if (@($appIds | Where-Object { $spIds -contains $_ }).Count -gt 0) { $errors.Add('Application and service principal ObjectId sets overlap.') }

    $appByObjectId = @{}
    foreach ($app in $applications) { $appByObjectId[[string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')] = $app }
    $spByObjectId = @{}
    foreach ($sp in $servicePrincipals) { $spByObjectId[[string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')] = $sp }
    $knownObjectIds = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($id in @($appIds + $spIds)) { if ($id) { [void]$knownObjectIds.Add($id) } }

    $expectedIncomplete = New-Object System.Collections.Generic.List[string]
    foreach ($app in $applications) {
        $id = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        $appCollection = Get-AppExposurePropertyValue -Object $app -Name 'Collection'
        if (-not $appCollection) { $errors.Add("Application '$id' is missing Collection."); continue }
        $isComplete = [bool](Get-AppExposurePropertyValue -Object $appCollection -Name 'CoreComplete')
        $ownersState = [string](Get-AppExposurePropertyValue -Object $appCollection -Name 'Owners')
        $credentialsState = [string](Get-AppExposurePropertyValue -Object $appCollection -Name 'Credentials')
        if ([string]::IsNullOrWhiteSpace($ownersState)) { $errors.Add("Application '$id' Collection.Owners is missing.") }
        if ([string]::IsNullOrWhiteSpace($credentialsState)) { $errors.Add("Application '$id' Collection.Credentials is missing.") }
        $expectedComplete = ($ownersState -eq 'Complete') -and ($credentialsState -eq 'Complete')
        if ($isComplete -ne $expectedComplete) { $errors.Add("Application '$id' Collection.CoreComplete does not reconcile with required surfaces.") }
        if (-not $expectedComplete) { $expectedIncomplete.Add($id) }

        $linkedIds = @((Get-AppExposurePropertyValue -Object $app -Name 'LinkedServicePrincipalIds'))
        $expectedIsOrphan = [bool]($linkedIds.Count -eq 0)
        if ([bool](Get-AppExposurePropertyValue -Object $app -Name 'IsOrphan') -ne $expectedIsOrphan) { $errors.Add("Application '$id' IsOrphan does not reconcile with LinkedServicePrincipalIds.") }
        foreach ($linkedId in $linkedIds) {
            $sid = [string]$linkedId
            if (-not $spByObjectId.ContainsKey($sid)) { $errors.Add("Application '$id' links unknown service principal '$sid'."); continue }
            if ([string](Get-AppExposurePropertyValue -Object $spByObjectId[$sid] -Name 'AppId') -ne [string](Get-AppExposurePropertyValue -Object $app -Name 'AppId')) {
                $errors.Add("Application '$id' and linked service principal '$sid' have different AppId values.")
            }
        }
    }
    foreach ($sp in $servicePrincipals) {
        $id = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        $spCollection = Get-AppExposurePropertyValue -Object $sp -Name 'Collection'
        if (-not $spCollection) { $errors.Add("Service principal '$id' is missing Collection."); continue }
        $appPermState = [string](Get-AppExposurePropertyValue -Object $spCollection -Name 'ApplicationPermissions')
        $delegatedState = [string](Get-AppExposurePropertyValue -Object $spCollection -Name 'DelegatedPermissions')
        $ownerState = [string](Get-AppExposurePropertyValue -Object $spCollection -Name 'Owners')
        $credentialState = [string](Get-AppExposurePropertyValue -Object $spCollection -Name 'Credentials')
        $activityState = [string](Get-AppExposurePropertyValue -Object $spCollection -Name 'Activity')
        foreach ($statePair in @([PSCustomObject]@{Name='ApplicationPermissions';Value=$appPermState},[PSCustomObject]@{Name='DelegatedPermissions';Value=$delegatedState},[PSCustomObject]@{Name='Owners';Value=$ownerState},[PSCustomObject]@{Name='Credentials';Value=$credentialState},[PSCustomObject]@{Name='Activity';Value=$activityState})) {
            if ([string]::IsNullOrWhiteSpace([string]$statePair.Value)) { $errors.Add("Service principal '$id' Collection.$($statePair.Name) is missing.") }
        }
        $expectedComplete = ($appPermState -eq 'Complete') -and ($delegatedState -eq 'Complete') -and ($ownerState -in @('Complete','NotApplicable')) -and ($credentialState -in @('Complete','NotApplicable'))
        if ([bool](Get-AppExposurePropertyValue -Object $spCollection -Name 'CoreComplete') -ne $expectedComplete) { $errors.Add("Service principal '$id' Collection.CoreComplete does not reconcile with required surfaces.") }
        if (-not $expectedComplete) { $expectedIncomplete.Add($id) }
        $appObjectId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId')
        if ($appObjectId) {
            if (-not $appByObjectId.ContainsKey($appObjectId)) { $errors.Add("Service principal '$id' references unknown application '$appObjectId'.") }
            elseif ([string](Get-AppExposurePropertyValue -Object $appByObjectId[$appObjectId] -Name 'AppId') -ne [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppId')) {
                $errors.Add("Service principal '$id' and application '$appObjectId' have different AppId values.")
            }
        }
    }

    $ids = @($observations | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId') })
    $keys = @($observations | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObservationKey') })
    if (@($ids | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $errors.Add('One or more ObservationId values are missing.') }
    if (@($ids | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) { $errors.Add('ObservationId values are not unique.') }
    if (@($keys | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $errors.Add('One or more ObservationKey values are missing.') }
    if (@($keys | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) { $errors.Add('ObservationKey values are not unique.') }

    foreach ($obs in $observations) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $obs -Name 'ObjectId')
        $category = [string](Get-AppExposurePropertyValue -Object $obs -Name 'Category')
        $identityKey = [string](Get-AppExposurePropertyValue -Object $obs -Name 'IdentityKey')
        $observationKey = [string](Get-AppExposurePropertyValue -Object $obs -Name 'ObservationKey')
        $observationId = [string](Get-AppExposurePropertyValue -Object $obs -Name 'ObservationId')
        $fingerprint = [string](Get-AppExposurePropertyValue -Object $obs -Name 'Fingerprint')
        $value = Get-AppExposurePropertyValue -Object $obs -Name 'Value'
        if ([string]::IsNullOrWhiteSpace($category)) { $errors.Add("Observation '$observationId' Category is missing.") }
        if ([string]::IsNullOrWhiteSpace($identityKey)) { $errors.Add("Observation '$observationId' IdentityKey is missing.") }
        if ($null -eq $value) { $errors.Add("Observation '$observationId' Value is missing.") }
        if (-not $knownObjectIds.Contains($objectId)) { $errors.Add("Observation '$observationId' references unknown ObjectId '$objectId'.") }
        $expectedKey = "$objectId|$category|$identityKey"
        if ($observationKey -ne $expectedKey) { $errors.Add("Observation '$observationId' ObservationKey does not reconcile with object/category/identity.") }
        $expectedId = "OBS-$((Get-AppExposureSha256 -Text $expectedKey).Substring(0,24))"
        if ($observationId -ne $expectedId) { $errors.Add("Observation '$observationId' does not match its deterministic ObservationId.") }
        $fingerprintInput = Get-AppExposureObservationFingerprintValue -Category $category -Value $value
        $expectedFingerprint = Get-AppExposureSha256 -Text (ConvertTo-Json -InputObject $fingerprintInput -Depth 20 -Compress)
        if ($fingerprint -ne $expectedFingerprint) { $errors.Add("Observation '$observationId' fingerprint does not match its canonical value.") }
    }

    foreach ($app in $applications) {
        $id = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        $coreObs = @(Get-AppExposureIndexedObservations -ObservationIndex $observationIndex -ObjectId $id -Category 'ApplicationRegistration' -IdentityKey 'Core')
        if ($coreObs.Count -ne 1) { $errors.Add("Application '$id' must have exactly one core observation.") }
        else {
            $coreValue = Get-AppExposurePropertyValue -Object $coreObs[0] -Name 'Value'
            if ([string](Get-AppExposurePropertyValue -Object $coreValue -Name 'AppId') -ne [string](Get-AppExposurePropertyValue -Object $app -Name 'AppId')) { $errors.Add("Application '$id' core observation AppId does not reconcile.") }
            $coreLinked = @((Get-AppExposurePropertyValue -Object $coreValue -Name 'LinkedServicePrincipalIds') | ForEach-Object { [string]$_ } | Sort-Object -Unique)
            $appLinked = @((Get-AppExposurePropertyValue -Object $app -Name 'LinkedServicePrincipalIds') | ForEach-Object { [string]$_ } | Sort-Object -Unique)
            if (($coreLinked -join '|') -ne ($appLinked -join '|')) { $errors.Add("Application '$id' core observation links do not reconcile.") }
        }
        foreach ($surface in @('Owners','Credentials')) {
            $obs = @(Get-AppExposureIndexedObservations -ObservationIndex $observationIndex -ObjectId $id -Category 'ApplicationCollectionState' -IdentityKey $surface)
            if ($obs.Count -ne 1) { $errors.Add("Application '$id' must have exactly one collection-state observation for '$surface'."); continue }
            $state = [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $obs[0] -Name 'Value') -Name 'State')
            if ($state -ne [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $app -Name 'Collection') -Name $surface)) { $errors.Add("Application '$id' collection-state observation for '$surface' does not reconcile.") }
        }
    }
    foreach ($sp in $servicePrincipals) {
        $id = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        $coreObs = @(Get-AppExposureIndexedObservations -ObservationIndex $observationIndex -ObjectId $id -Category 'ServicePrincipal' -IdentityKey 'Core')
        if ($coreObs.Count -ne 1) { $errors.Add("Service principal '$id' must have exactly one core observation.") }
        else {
            $coreValue = Get-AppExposurePropertyValue -Object $coreObs[0] -Name 'Value'
            if ([string](Get-AppExposurePropertyValue -Object $coreValue -Name 'AppId') -ne [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppId')) { $errors.Add("Service principal '$id' core observation AppId does not reconcile.") }
            if ([string](Get-AppExposurePropertyValue -Object $coreValue -Name 'AppRegistrationObjectId') -ne [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId')) { $errors.Add("Service principal '$id' core observation AppRegistrationObjectId does not reconcile.") }
        }
        foreach ($surface in @('ApplicationPermissions','DelegatedPermissions','Owners','Credentials','Activity')) {
            $obs = @(Get-AppExposureIndexedObservations -ObservationIndex $observationIndex -ObjectId $id -Category 'CollectionState' -IdentityKey $surface)
            if ($obs.Count -ne 1) { $errors.Add("Service principal '$id' must have exactly one collection-state observation for '$surface'."); continue }
            $state = [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $obs[0] -Name 'Value') -Name 'State')
            if ($state -ne [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $sp -Name 'Collection') -Name $surface)) { $errors.Add("Service principal '$id' collection-state observation for '$surface' does not reconcile.") }
        }
    }

    if ($collection) {
        $expectedIncompleteIds = @($expectedIncomplete.ToArray() | Sort-Object -Unique)
        $actualIncompleteIds = @((Get-AppExposurePropertyValue -Object $collection -Name 'IncompleteObjectIds') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        if (($expectedIncompleteIds -join '|') -ne ($actualIncompleteIds -join '|')) { $errors.Add('Collection.IncompleteObjectIds does not reconcile with per-object collection state.') }
        if ([bool](Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete') -ne [bool]($expectedIncompleteIds.Count -eq 0)) { $errors.Add('Collection.CoreComplete does not reconcile with per-object collection state.') }
    }

    return [PSCustomObject]@{ Valid = [bool]($errors.Count -eq 0); Errors = @($errors.ToArray()) }
}

function Save-AppExposureSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $validation = Test-AppExposureSnapshot -Snapshot $Snapshot
    if (-not $validation.Valid) { throw "Snapshot validation failed: $($validation.Errors -join '; ')" }
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $Snapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8
    return (Resolve-Path -LiteralPath $Path).Path
}

function Import-AppExposureSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Snapshot not found: $Path" }
    $snapshot = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $validation = Test-AppExposureSnapshot -Snapshot $snapshot
    if (-not $validation.Valid) { throw "Snapshot validation failed: $($validation.Errors -join '; ')" }
    return $snapshot
}

