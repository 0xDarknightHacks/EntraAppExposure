<#
.SYNOPSIS
    Deterministic Entra App Exposure rule evaluation.
.DESCRIPTION
    Rule metadata and policy live in Rules/Baseline.json. This file contains only
    the evaluation engine that operates on a validated portable snapshot. It does
    not call Microsoft Graph and does not calculate a numerical score.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Import-AppExposureRulePack {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Rule baseline not found: $Path" }
    try { $pack = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Rule baseline '$Path' is not valid JSON: $($_.Exception.Message)" }

    foreach ($name in @('SchemaVersion','BaselineVersion','Name','Policy','Definitions')) {
        if (-not (Test-AppExposurePropertyExists -Object $pack -Name $name)) { throw "Rule baseline '$name' is missing." }
    }
    if ([string](Get-AppExposurePropertyValue -Object $pack -Name 'SchemaVersion') -ne '2.1') {
        throw "Unsupported rule baseline schema version '$((Get-AppExposurePropertyValue -Object $pack -Name 'SchemaVersion'))'. Expected 2.1."
    }

    $definitions = @((Get-AppExposurePropertyValue -Object $pack -Name 'Definitions'))
    if ($definitions.Count -eq 0) { throw 'Rule baseline Definitions must contain at least one rule.' }
    $seen = @{}
    foreach ($rule in $definitions) {
        $id = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Id')
        if ($id -notmatch '^EAE-[A-Z]+(?:-[A-Z]+)*-[0-9]{3}$') { throw "Rule ID '$id' does not match the EAE taxonomy." }
        if ($seen.ContainsKey($id)) { throw "Duplicate rule ID '$id' in rule baseline." }
        $seen[$id] = $true
        foreach ($field in @('Enabled','Category','Severity','AppliesTo','Title','Rationale','Recommendation','RequiredEvidence','References')) {
            if (-not (Test-AppExposurePropertyExists -Object $rule -Name $field)) { throw "Rule '$id' is missing '$field'." }
        }
    }

    $policy = Get-AppExposurePropertyValue -Object $pack -Name 'Policy'
    foreach ($name in @('Credential','Ownership','Activity','SensitiveApplicationPermissions','SensitiveDelegatedPermissions')) {
        if (-not (Test-AppExposurePropertyExists -Object $policy -Name $name)) { throw "Rule baseline policy '$name' is missing." }
    }
    foreach ($listName in @('SensitiveApplicationPermissions','SensitiveDelegatedPermissions')) {
        foreach ($entry in @((Get-AppExposurePropertyValue -Object $policy -Name $listName))) {
            $resourceAppId = [string](Get-AppExposurePropertyValue -Object $entry -Name 'ResourceAppId')
            $permissionValue = [string](Get-AppExposurePropertyValue -Object $entry -Name 'PermissionValue')
            if ([string]::IsNullOrWhiteSpace($resourceAppId) -or [string]::IsNullOrWhiteSpace($permissionValue)) {
                throw "Rule baseline policy '$listName' entries require ResourceAppId and PermissionValue."
            }
        }
    }
    return $pack
}

function New-AppExposureRuleIndex {
    param([Parameter(Mandatory = $true)]$RulePack)
    $index = @{}
    foreach ($rule in @((Get-AppExposurePropertyValue -Object $RulePack -Name 'Definitions'))) {
        $index[[string](Get-AppExposurePropertyValue -Object $rule -Name 'Id')] = $rule
    }
    return $index
}

function New-AppExposureFinding {
    param(
        [Parameter(Mandatory = $true)]$RuleIndex,
        [Parameter(Mandatory = $true)][string]$RuleId,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$ObjectDisplayName,
        [Parameter(Mandatory = $true)][string]$WhatHappened,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$EvidenceIds,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$EvidenceSummary = @()
    )

    if (-not $RuleIndex.ContainsKey($RuleId)) { throw "Evaluator references undefined rule '$RuleId'." }
    $rule = $RuleIndex[$RuleId]
    if (-not [bool](Get-AppExposurePropertyValue -Object $rule -Name 'Enabled')) { return $null }

    $evidence = @($EvidenceIds | Where-Object { $_ } | Sort-Object -Unique)
    $seed = "$RuleId|$ObjectId|$($evidence -join '|')"
    $hash = Get-AppExposureSha256 -Text $seed
    return [PSCustomObject]@{
        FindingId         = "FND-$($hash.Substring(0, 20))"
        RuleId            = $RuleId
        Severity          = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Severity')
        Category          = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Category')
        Title             = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Title')
        ObjectId          = $ObjectId
        ObjectDisplayName = $ObjectDisplayName
        WhatHappened      = $WhatHappened
        WhyItMatters      = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Rationale')
        Recommendation    = [string](Get-AppExposurePropertyValue -Object $rule -Name 'Recommendation')
        References        = @((Get-AppExposurePropertyValue -Object $rule -Name 'References'))
        EvidenceIds       = $evidence
        EvidenceSummary   = @($EvidenceSummary)
    }
}

function Add-AppExposureFinding {
    param(
        [Parameter(Mandatory = $true)]$Findings,
        [Parameter(Mandatory = $true)]$RuleIndex,
        [Parameter(Mandatory = $true)][string]$RuleId,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$ObjectDisplayName,
        [Parameter(Mandatory = $true)][string]$WhatHappened,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$EvidenceIds,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][string[]]$EvidenceSummary = @()
    )
    $finding = New-AppExposureFinding -RuleIndex $RuleIndex -RuleId $RuleId -ObjectId $ObjectId -ObjectDisplayName $ObjectDisplayName -WhatHappened $WhatHappened -EvidenceIds $EvidenceIds -EvidenceSummary $EvidenceSummary
    if ($null -ne $finding) { $Findings.Add($finding) }
}

function New-AppExposureObservationIndex {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Observations)
    $index = @{}
    foreach ($observation in @($Observations)) {
        if ($null -eq $observation) { continue }
        $objectId = [string](Get-AppExposurePropertyValue -Object $observation -Name 'ObjectId')
        $category = [string](Get-AppExposurePropertyValue -Object $observation -Name 'Category')
        if ([string]::IsNullOrWhiteSpace($objectId) -or [string]::IsNullOrWhiteSpace($category)) { continue }
        if (-not $index.ContainsKey($objectId)) { $index[$objectId] = @{} }
        if (-not $index[$objectId].ContainsKey($category)) { $index[$objectId][$category] = [System.Collections.Generic.List[object]]::new() }
        $index[$objectId][$category].Add($observation)
    }
    return $index
}

function Get-AppExposureObservationSubset {
    param(
        [Parameter(Mandatory = $true)]$ObservationIndex,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$Category
    )
    if (-not $ObservationIndex.ContainsKey($ObjectId)) { return @() }
    if (-not $ObservationIndex[$ObjectId].ContainsKey($Category)) { return @() }
    return @($ObservationIndex[$ObjectId][$Category].ToArray())
}

function Get-AppExposureCredentialState {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$CredentialObservations,
        [Parameter(Mandatory = $true)][datetime]$ReferenceDate,
        [Parameter(Mandatory = $true)]$CredentialPolicy
    )

    $expired = [System.Collections.Generic.List[object]]::new()
    $expiring = [System.Collections.Generic.List[object]]::new()
    $longLived = [System.Collections.Generic.List[object]]::new()
    $active = [System.Collections.Generic.List[object]]::new()
    foreach ($obs in @($CredentialObservations)) {
        $value = Get-AppExposurePropertyValue -Object $obs -Name 'Value'
        $startRaw = Get-AppExposurePropertyValue -Object $value -Name 'StartDateTime'
        $endRaw = Get-AppExposurePropertyValue -Object $value -Name 'EndDateTime'
        $start = if ($startRaw) { [datetime]$startRaw } else { $null }
        $end = if ($endRaw) { [datetime]$endRaw } else { $null }
        if ($end -and $end -lt $ReferenceDate) { $expired.Add($obs); continue }
        if ((-not $start -or $start -le $ReferenceDate) -and (-not $end -or $end -ge $ReferenceDate)) { $active.Add($obs) }
        if ($end -and $end -ge $ReferenceDate -and $end -le $ReferenceDate.AddDays([int](Get-AppExposurePropertyValue -Object $CredentialPolicy -Name 'ExpiringSoonDays'))) { $expiring.Add($obs) }
        if ($start -and $end -and ($end - $start).TotalDays -gt [int](Get-AppExposurePropertyValue -Object $CredentialPolicy -Name 'LongLivedDays')) { $longLived.Add($obs) }
    }
    return [PSCustomObject]@{
        Expired   = @($expired.ToArray())
        Expiring  = @($expiring.ToArray())
        LongLived = @($longLived.ToArray())
        Active    = @($active.ToArray())
    }
}

function Get-AppExposureCredentialSummary {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Observations)
    return @($Observations | ForEach-Object {
        $value = Get-AppExposurePropertyValue -Object $_ -Name 'Value'
        "$(Get-AppExposurePropertyValue -Object $value -Name 'CredentialType') $(Get-AppExposurePropertyValue -Object $value -Name 'KeyId') ($(Get-AppExposurePropertyValue -Object $value -Name 'StartDateTime') to $(Get-AppExposurePropertyValue -Object $value -Name 'EndDateTime'))"
    })
}

function Test-AppExposureVerifiedPublisher {
    param([Parameter(Mandatory = $false)]$VerifiedPublisher)
    if ($null -eq $VerifiedPublisher) { return $false }
    $displayName = [string](Get-AppExposurePropertyValue -Object $VerifiedPublisher -Name 'DisplayName')
    $publisherId = [string](Get-AppExposurePropertyValue -Object $VerifiedPublisher -Name 'VerifiedPublisherId')
    return -not ([string]::IsNullOrWhiteSpace($displayName) -and [string]::IsNullOrWhiteSpace($publisherId))
}

function Test-AppExposureSensitivePermissionObservation {
    param(
        [Parameter(Mandatory = $true)]$Observation,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Watchlist = @()
    )

    $value = Get-AppExposurePropertyValue -Object $Observation -Name 'Value'
    $permissionValue = [string](Get-AppExposurePropertyValue -Object $value -Name 'PermissionValue')
    $resourceAppId = [string](Get-AppExposurePropertyValue -Object $value -Name 'ResourceAppId')
    if ([string]::IsNullOrWhiteSpace($permissionValue)) { return $false }

    foreach ($entry in @($Watchlist)) {
        $expectedPermission = [string](Get-AppExposurePropertyValue -Object $entry -Name 'PermissionValue')
        $expectedResourceAppId = [string](Get-AppExposurePropertyValue -Object $entry -Name 'ResourceAppId')
        if (-not [string]::Equals($permissionValue, $expectedPermission, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ([string]::IsNullOrWhiteSpace($expectedResourceAppId) -or $expectedResourceAppId -eq '*') { return $true }
        if ([string]::Equals($resourceAppId, $expectedResourceAppId, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-AppExposureActivityReviewCandidate {
    param(
        [Parameter(Mandatory = $true)]$ServicePrincipal,
        [Parameter(Mandatory = $true)]$ActivityValue,
        [Parameter(Mandatory = $true)]$ActivityPolicy,
        [Parameter(Mandatory = $true)][datetime]$ReferenceDate
    )

    $lookbackDays = [int](Get-AppExposurePropertyValue -Object $ActivityValue -Name 'LookbackDays')
    $minimumLookback = [int](Get-AppExposurePropertyValue -Object $ActivityPolicy -Name 'MinimumReviewLookbackDays')
    if ($lookbackDays -lt $minimumLookback) { return $false }

    $classification = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'Classification')
    if ([bool](Get-AppExposurePropertyValue -Object $ActivityPolicy -Name 'ExcludeMicrosoftFirstParty') -and $classification -eq 'MicrosoftFirstParty') { return $false }

    $spType = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'ServicePrincipalType')
    $excludedTypes = @((Get-AppExposurePropertyValue -Object $ActivityPolicy -Name 'ExcludedServicePrincipalTypes'))
    if ($excludedTypes -contains $spType) { return $false }

    $createdRaw = Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'CreatedDateTime'
    if (-not $createdRaw) { return $false }
    try { $created = [datetimeoffset]::Parse([string]$createdRaw).UtcDateTime }
    catch { return $false }
    $minimumAgeDays = [int](Get-AppExposurePropertyValue -Object $ActivityPolicy -Name 'MinimumIdentityAgeDays')
    if (($ReferenceDate - $created).TotalDays -lt $minimumAgeDays) { return $false }
    return $true
}


function Test-AppExposureLoopbackRedirectUri {
    param([Parameter(Mandatory = $true)][string]$Uri)
    try {
        $parsed = [uri]$Uri
        return $parsed.IsLoopback -or $parsed.Host -in @('localhost','127.0.0.1','[::1]','::1')
    }
    catch { return $false }
}

function Get-AppExposureUnsafeBrowserRedirectUris {
    param([Parameter(Mandatory = $false)]$Authentication)
    if ($null -eq $Authentication) { return @() }
    $unsafe = [System.Collections.Generic.List[string]]::new()
    foreach ($uriValue in @(
        @((Get-AppExposurePropertyValue -Object $Authentication -Name 'WebRedirectUris')) +
        @((Get-AppExposurePropertyValue -Object $Authentication -Name 'SpaRedirectUris'))
    )) {
        $uri = [string]$uriValue
        if ([string]::IsNullOrWhiteSpace($uri)) { continue }
        try { $parsed = [uri]$uri } catch { $unsafe.Add($uri); continue }
        if ($parsed.Scheme -ieq 'https') { continue }
        if ($parsed.Scheme -ieq 'http' -and (Test-AppExposureLoopbackRedirectUri -Uri $uri)) { continue }
        $unsafe.Add($uri)
    }
    return @($unsafe.ToArray() | Sort-Object -Unique)
}

function Invoke-AppExposureRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$RulePack,
        [Parameter(Mandatory = $false)][switch]$ExcludeMicrosoftFirstParty
    )

    $observations = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Observations'))
    $applications = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Applications'))
    $servicePrincipals = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'ServicePrincipals'))
    $policy = Get-AppExposurePropertyValue -Object $RulePack -Name 'Policy'
    $credentialPolicy = Get-AppExposurePropertyValue -Object $policy -Name 'Credential'
    $ownershipPolicy = Get-AppExposurePropertyValue -Object $policy -Name 'Ownership'
    $activityPolicy = Get-AppExposurePropertyValue -Object $policy -Name 'Activity'
    $sensitiveApplicationPermissions = @((Get-AppExposurePropertyValue -Object $policy -Name 'SensitiveApplicationPermissions'))
    $sensitiveDelegatedPermissions = @((Get-AppExposurePropertyValue -Object $policy -Name 'SensitiveDelegatedPermissions'))
    $minimumOwners = [int](Get-AppExposurePropertyValue -Object $ownershipPolicy -Name 'MinimumOwners')
    $maxActiveCredentials = [int](Get-AppExposurePropertyValue -Object $credentialPolicy -Name 'MaxActiveCredentials')
    $referenceDate = [datetime](Get-AppExposurePropertyValue -Object $Snapshot -Name 'CollectedAtUtc')
    $findings = [System.Collections.Generic.List[object]]::new()
    $observationIndex = New-AppExposureObservationIndex -Observations $observations
    $ruleIndex = New-AppExposureRuleIndex -RulePack $RulePack

    $applicationByObjectId = @{}
    $applicationOwnerState = @{}
    $applicationCredentialState = @{}
    foreach ($app in $applications) {
        $appObjectId = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        if (-not [string]::IsNullOrWhiteSpace($appObjectId)) { $applicationByObjectId[$appObjectId] = $app }
    }

    # Application-registration rules. Credentials and registration ownership are
    # evaluated on the application object itself, independent of SP ownership.
    foreach ($app in $applications) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        $displayName = [string](Get-AppExposurePropertyValue -Object $app -Name 'DisplayName')
        $collection = Get-AppExposurePropertyValue -Object $app -Name 'Collection'
        $collectionObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'ApplicationCollectionState')

        if (-not [bool](Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete')) {
            $bad = @($collectionObs | Where-Object {
                $value = Get-AppExposurePropertyValue -Object $_ -Name 'Value'
                [string](Get-AppExposurePropertyValue -Object $value -Name 'State') -ne 'Complete'
            })
            $summary = @($bad | ForEach-Object {
                $value = Get-AppExposurePropertyValue -Object $_ -Name 'Value'
                "$(Get-AppExposurePropertyValue -Object $value -Name 'Surface'): $(Get-AppExposurePropertyValue -Object $value -Name 'State')"
            })
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-DATA-APP-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more required application-registration evidence surfaces could not be collected: $($summary -join ', ')." -EvidenceIds @($bad | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
        }

        $ownerObs = @()
        $ownerState = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Owners')
        if ($ownerState -eq 'Complete') {
            $ownerObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'ApplicationOwner')
            $applicationOwnerState[$objectId] = $ownerObs
            if ($ownerObs.Count -eq 0) {
                $stateEvidence = @($collectionObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'Surface') -eq 'Owners' })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-OWNER-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The application-registration owners relationship was collected successfully and returned zero owners.' -EvidenceIds @($stateEvidence | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Application owners lookup: Complete; owner count: 0')
            }
            elseif ($ownerObs.Count -lt $minimumOwners) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-OWNER-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The application registration has $($ownerObs.Count) owner; the baseline recommends at least $minimumOwners where possible." -EvidenceIds @($ownerObs | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @("Owner count: $($ownerObs.Count)")
            }
            $disabled = @($ownerObs | Where-Object { $enabled = Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'AccountEnabled'; $null -ne $enabled -and -not [bool]$enabled })
            if ($disabled.Count -gt 0) {
                $names = @($disabled | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'DisplayName') })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-OWNER-003' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more application-registration owners are disabled: $($names -join ', ')." -EvidenceIds @($disabled | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
            }
            $guests = @($ownerObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'UserType') -eq 'Guest' })
            if ($guests.Count -gt 0) {
                $names = @($guests | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'DisplayName') })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-OWNER-004' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more application-registration owners are guest users: $($names -join ', ')." -EvidenceIds @($guests | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
            }
        }

        $credentialObs = @()
        $credentialState = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Credentials')
        if ($credentialState -eq 'Complete') {
            $credentialObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'ApplicationCredential')
            $state = Get-AppExposureCredentialState -CredentialObservations $credentialObs -ReferenceDate $referenceDate -CredentialPolicy $credentialPolicy
            $applicationCredentialState[$objectId] = $state
            if ($state.Expired.Count -gt 0) {
                $summary = Get-AppExposureCredentialSummary -Observations $state.Expired
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-CRED-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "Expired credential metadata remains configured: $($summary -join '; ')." -EvidenceIds @($state.Expired | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
            }
            if ($state.Expiring.Count -gt 0) {
                $summary = Get-AppExposureCredentialSummary -Observations $state.Expiring
                $days = [int](Get-AppExposurePropertyValue -Object $credentialPolicy -Name 'ExpiringSoonDays')
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-CRED-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more credentials expire within the configured $days-day warning window: $($summary -join '; ')." -EvidenceIds @($state.Expiring | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
            }
            if ($state.LongLived.Count -gt 0) {
                $summary = Get-AppExposureCredentialSummary -Observations $state.LongLived
                $days = [int](Get-AppExposurePropertyValue -Object $credentialPolicy -Name 'LongLivedDays')
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-CRED-003' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more credentials exceed the configured $days-day lifetime: $($summary -join '; ')." -EvidenceIds @($state.LongLived | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
            }
            if ($state.Active.Count -gt $maxActiveCredentials) {
                $summary = Get-AppExposureCredentialSummary -Observations $state.Active
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-CRED-004' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The application registration has $($state.Active.Count) active credentials, above the configured baseline of $maxActiveCredentials." -EvidenceIds @($state.Active | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
            }
            $isOrphan = [bool](Get-AppExposurePropertyValue -Object $app -Name 'IsOrphan')
            if ($isOrphan -and $state.Active.Count -gt 0) {
                $summary = Get-AppExposureCredentialSummary -Observations $state.Active
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-ORPHAN-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "No local service principal is correlated to this registration, but $($state.Active.Count) active credential(s) remain configured." -EvidenceIds @($state.Active | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
            }
            if ($ownerState -eq 'Complete' -and $ownerObs.Count -eq 0 -and $state.Active.Count -gt 0) {
                $ownerEvidence = @($collectionObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'Surface') -eq 'Owners' })
                $allEvidence = @($ownerEvidence + $state.Active)
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-006' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The owner lookup is complete and returned zero owners while $($state.Active.Count) active credential(s) remain configured." -EvidenceIds @($allEvidence | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Owner count: 0', "Active credentials: $($state.Active.Count)")
            }
        }


        $appCoreObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'ApplicationRegistration')
        if ($appCoreObs.Count -gt 0) {
            $coreValue = Get-AppExposurePropertyValue -Object $appCoreObs[0] -Name 'Value'
            $authentication = Get-AppExposurePropertyValue -Object $coreValue -Name 'Authentication'
            $apiConfiguration = Get-AppExposurePropertyValue -Object $coreValue -Name 'ApiConfiguration'
            $coreEvidenceId = [string](Get-AppExposurePropertyValue -Object $appCoreObs[0] -Name 'ObservationId')

            $unsafeRedirectUris = @(Get-AppExposureUnsafeBrowserRedirectUris -Authentication $authentication)
            if ($unsafeRedirectUris.Count -gt 0) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-AUTH-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more web/SPA redirect URIs are not HTTPS and are not loopback development endpoints: $($unsafeRedirectUris -join ', ')." -EvidenceIds @($coreEvidenceId) -EvidenceSummary $unsafeRedirectUris
            }
            $implicitAccess = [bool](Get-AppExposurePropertyValue -Object $authentication -Name 'WebImplicitAccessTokenIssuanceEnabled')
            $implicitId = [bool](Get-AppExposurePropertyValue -Object $authentication -Name 'WebImplicitIdTokenIssuanceEnabled')
            if ($implicitAccess -or $implicitId) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-AUTH-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "OAuth implicit issuance is enabled (access token: $implicitAccess; ID token: $implicitId)." -EvidenceIds @($coreEvidenceId) -EvidenceSummary @("Access-token issuance: $implicitAccess", "ID-token issuance: $implicitId")
            }
            if ([bool](Get-AppExposurePropertyValue -Object $authentication -Name 'IsFallbackPublicClient')) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-AUTH-003' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'Fallback public-client behavior is enabled on the application registration.' -EvidenceIds @($coreEvidenceId) -EvidenceSummary @('isFallbackPublicClient: true')
            }
            $preAuthorized = @((Get-AppExposurePropertyValue -Object $apiConfiguration -Name 'PreAuthorizedApplications'))
            if ($preAuthorized.Count -gt 0) {
                $preAuthSummary = @($preAuthorized | ForEach-Object { $preAppId = [string](Get-AppExposurePropertyValue -Object $_ -Name 'AppId'); $permCount = @((Get-AppExposurePropertyValue -Object $_ -Name 'DelegatedPermissionIds')).Count; "$preAppId ($permCount delegated permission ID(s))" })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-APP-API-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The application exposes API scopes to $($preAuthorized.Count) pre-authorized client application(s)." -EvidenceIds @($coreEvidenceId) -EvidenceSummary $preAuthSummary
            }
        }
    }

    # Service-principal rules and cross-object correlations.
    foreach ($sp in $servicePrincipals) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        $displayName = [string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')
        $classification = [string](Get-AppExposurePropertyValue -Object $sp -Name 'Classification')
        if ($ExcludeMicrosoftFirstParty -and $classification -eq 'MicrosoftFirstParty') { continue }
        $collection = Get-AppExposurePropertyValue -Object $sp -Name 'Collection'
        $collectionObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'CollectionState')

        if (-not [bool](Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete')) {
            $bad = @($collectionObs | Where-Object {
                $value = Get-AppExposurePropertyValue -Object $_ -Name 'Value'
                $surface = [string](Get-AppExposurePropertyValue -Object $value -Name 'Surface')
                $state = [string](Get-AppExposurePropertyValue -Object $value -Name 'State')
                ($surface -ne 'Activity') -and ($state -notin @('Complete','NotApplicable'))
            })
            $summary = @($bad | ForEach-Object {
                $value = Get-AppExposurePropertyValue -Object $_ -Name 'Value'
                "$(Get-AppExposurePropertyValue -Object $value -Name 'Surface'): $(Get-AppExposurePropertyValue -Object $value -Name 'State')"
            })
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-DATA-SP-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more required service-principal evidence surfaces could not be collected: $($summary -join ', ')." -EvidenceIds @($bad | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $summary
        }

        $applicationPermissionObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'ApplicationPermission')
        $sensitiveAppObs = @($applicationPermissionObs | Where-Object {
            Test-AppExposureSensitivePermissionObservation -Observation $_ -Watchlist $sensitiveApplicationPermissions
        })
        if ($sensitiveAppObs.Count -gt 0) {
            $names = @($sensitiveAppObs | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'PermissionValue') } | Sort-Object -Unique)
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-OAUTH-APP-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has app-only grants from the configured sensitive-permission watchlist: $($names -join ', ')." -EvidenceIds @($sensitiveAppObs | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
        }

        $delegatedObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'DelegatedPermission')
        $sensitiveDelegatedObs = @($delegatedObs | Where-Object {
            Test-AppExposureSensitivePermissionObservation -Observation $_ -Watchlist $sensitiveDelegatedPermissions
        })
        $tenantWideDelegated = @($sensitiveDelegatedObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'ConsentType') -eq 'AllPrincipals' })
        $principalDelegated = @($sensitiveDelegatedObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'ConsentType') -ne 'AllPrincipals' })
        if ($tenantWideDelegated.Count -gt 0) {
            $names = @($tenantWideDelegated | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'PermissionValue') } | Sort-Object -Unique)
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-OAUTH-DEL-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has tenant-wide delegated grants from the configured sensitive-permission watchlist: $($names -join ', ')." -EvidenceIds @($tenantWideDelegated | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
        }
        if ($principalDelegated.Count -gt 0) {
            $names = @($principalDelegated | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'PermissionValue') } | Sort-Object -Unique)
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-OAUTH-DEL-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has user-scoped delegated grants from the configured sensitive-permission watchlist: $($names -join ', ')." -EvidenceIds @($principalDelegated | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
        }

        $hasSensitivePermissions = ($sensitiveAppObs.Count -gt 0 -or $sensitiveDelegatedObs.Count -gt 0)
        $sensitiveEvidence = @($sensitiveAppObs + $sensitiveDelegatedObs)
        $ownerObs = @()
        $ownerState = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Owners')
        if ($ownerState -eq 'Complete' -and $classification -ne 'MicrosoftFirstParty') {
            $ownerObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'Owner')
            if ($ownerObs.Count -eq 0) {
                $stateEvidence = @($collectionObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'Surface') -eq 'Owners' })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-OWNER-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The service-principal owners relationship was collected successfully and returned zero owners.' -EvidenceIds @($stateEvidence | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Owners lookup: Complete; owner count: 0')
                if ($hasSensitivePermissions) {
                    $combined = @($sensitiveEvidence + $stateEvidence)
                    Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The service principal has sensitive permissions and the completed owner lookup returned zero owners.' -EvidenceIds @($combined | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Sensitive permission evidence', 'Owner count: 0')
                }
            }
            elseif ($ownerObs.Count -lt $minimumOwners) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-OWNER-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has $($ownerObs.Count) owner; the baseline recommends at least $minimumOwners where possible." -EvidenceIds @($ownerObs | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @("Owner count: $($ownerObs.Count)")
                if ($hasSensitivePermissions) {
                    $combined = @($sensitiveEvidence + $ownerObs)
                    Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-003' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has sensitive permissions and only $($ownerObs.Count) owner." -EvidenceIds @($combined | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Sensitive permission evidence', "Owner count: $($ownerObs.Count)")
                }
            }
            $disabledOwners = @($ownerObs | Where-Object { $enabled = Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'AccountEnabled'; $null -ne $enabled -and -not [bool]$enabled })
            if ($disabledOwners.Count -gt 0) {
                $names = @($disabledOwners | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'DisplayName') })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-OWNER-003' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more service-principal owners are disabled: $($names -join ', ')." -EvidenceIds @($disabledOwners | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
            }
            $guestOwners = @($ownerObs | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'UserType') -eq 'Guest' })
            if ($guestOwners.Count -gt 0) {
                $names = @($guestOwners | ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'DisplayName') })
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-OWNER-004' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "One or more service-principal owners are guest users: $($names -join ', ')." -EvidenceIds @($guestOwners | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $names
            }
        }

        $linkedAppId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId')
        $linkedCredentialState = $null
        if ($linkedAppId -and $applicationCredentialState.ContainsKey($linkedAppId)) { $linkedCredentialState = $applicationCredentialState[$linkedAppId] }
        if ($hasSensitivePermissions -and $null -ne $linkedCredentialState -and $linkedCredentialState.LongLived.Count -gt 0) {
            $combined = @($sensitiveEvidence + $linkedCredentialState.LongLived)
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The service principal has sensitive OAuth/application permissions and its linked application registration has at least one long-lived credential.' -EvidenceIds @($combined | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Sensitive permission evidence', 'Long-lived credential evidence')
        }

        $accountEnabled = Get-AppExposurePropertyValue -Object $sp -Name 'AccountEnabled'
        if ($null -ne $accountEnabled -and -not [bool]$accountEnabled) {
            if ($hasSensitivePermissions) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-STATE-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The service principal is disabled but sensitive permission grants remain assigned.' -EvidenceIds @($sensitiveEvidence | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('AccountEnabled: false', 'Sensitive permission evidence retained')
            }
            if ($null -ne $linkedCredentialState -and $linkedCredentialState.Active.Count -gt 0) {
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-STATE-002' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal is disabled while its linked application registration retains $($linkedCredentialState.Active.Count) active credential(s)." -EvidenceIds @($linkedCredentialState.Active | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('AccountEnabled: false', "Active linked credentials: $($linkedCredentialState.Active.Count)")
            }
        }

        $activityObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $objectId -Category 'Activity')
        $noActivityObserved = $false
        if ($activityObs.Count -gt 0) {
            $activityValue = Get-AppExposurePropertyValue -Object $activityObs[0] -Name 'Value'
            $noActivityObserved = [bool](Get-AppExposurePropertyValue -Object $activityValue -Name 'NoActivityObserved')
            $isReviewCandidate = Test-AppExposureActivityReviewCandidate -ServicePrincipal $sp -ActivityValue $activityValue -ActivityPolicy $activityPolicy -ReferenceDate $referenceDate
            if ($noActivityObserved -and $isReviewCandidate) {
                $days = [int](Get-AppExposurePropertyValue -Object $activityValue -Name 'LookbackDays')
                $sourceKind = [string](Get-AppExposurePropertyValue -Object $activityValue -Name 'SourceKind')
                $lastObserved = [string](Get-AppExposurePropertyValue -Object $activityValue -Name 'LastSignInDateTime')
                $activitySummary = @("No sign-in observed inside $days-day review window", "Activity source: $sourceKind")
                if (-not [string]::IsNullOrWhiteSpace($lastObserved)) { $activitySummary += "Last observed sign-in: $lastObserved" }
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-SP-ACTIVITY-001' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "No sign-in was observed inside the configured $days-day review window for this application identity." -EvidenceIds @((Get-AppExposurePropertyValue -Object $activityObs[0] -Name 'ObservationId')) -EvidenceSummary $activitySummary
                if ($hasSensitivePermissions) {
                    $combined = @($sensitiveEvidence + $activityObs[0])
                    $combinedActivitySummary = @('Sensitive permission evidence') + @($activitySummary)
                    Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-004' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "Sensitive permissions remain assigned while no sign-in was observed inside the configured $days-day review window." -EvidenceIds @($combined | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary $combinedActivitySummary
                }
            }
        }

        if ($classification -eq 'ThirdParty' -and $hasSensitivePermissions -and -not (Test-AppExposureVerifiedPublisher -VerifiedPublisher (Get-AppExposurePropertyValue -Object $sp -Name 'VerifiedPublisher'))) {
            Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-005' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened 'The service principal is classified as third-party, has sensitive permissions, and no verified publisher metadata was present in the collected identity record.' -EvidenceIds @($sensitiveEvidence | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Classification: ThirdParty', 'Verified publisher metadata: absent', 'Sensitive permission evidence')
        }

        if ($hasSensitivePermissions -and $linkedAppId -and $applicationOwnerState.ContainsKey($linkedAppId)) {
            $linkedOwners = @($applicationOwnerState[$linkedAppId])
            if ($linkedOwners.Count -lt $minimumOwners) {
                $combined = @($sensitiveEvidence + $linkedOwners)
                if ($linkedOwners.Count -eq 0) {
                    $linkedCollectionObs = @(Get-AppExposureObservationSubset -ObservationIndex $observationIndex -ObjectId $linkedAppId -Category 'ApplicationCollectionState' | Where-Object { (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'Surface') -eq 'Owners' })
                    $combined = @($combined + $linkedCollectionObs)
                }
                Add-AppExposureFinding -Findings $findings -RuleIndex $ruleIndex -RuleId 'EAE-EXPOSURE-007' -ObjectId $objectId -ObjectDisplayName $displayName -WhatHappened "The service principal has sensitive permissions and its linked application registration has $($linkedOwners.Count) owner(s), below the configured baseline of $minimumOwners." -EvidenceIds @($combined | ForEach-Object { Get-AppExposurePropertyValue -Object $_ -Name 'ObservationId' }) -EvidenceSummary @('Sensitive permission evidence', "Linked application owners: $($linkedOwners.Count)")
            }
        }
    }

    return @($findings.ToArray())
}
