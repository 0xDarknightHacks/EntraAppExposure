<#
.SYNOPSIS
    Microsoft Entra application and service-principal discovery.

.DESCRIPTION
    Collection-only module. It performs no persistence, scoring, drift logic,
    or report generation. Returned objects are normalized in memory and are
    later written to a portable JSON snapshot by EvidencePackage.psm1.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MicrosoftServicesTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

function Get-AppExposureSPClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AppOwnerOrganizationId,

        [Parameter(Mandatory = $true)]
        [string]$ScanningTenantId
    )

    if ([string]::IsNullOrWhiteSpace($AppOwnerOrganizationId)) { return 'Unknown' }
    if ($AppOwnerOrganizationId -eq $script:MicrosoftServicesTenantId) { return 'MicrosoftFirstParty' }
    if ($AppOwnerOrganizationId -eq $ScanningTenantId) { return 'Local' }
    return 'ThirdParty'
}

function ConvertTo-AppExposureApplicationRecord {
    param(
        [Parameter(Mandatory = $true)]$Application,
        [Parameter(Mandatory = $false)][string]$SourceUri
    )

    $verifiedPublisher = Get-AppExposurePropertyValue -Object $Application -Name 'verifiedPublisher'
    $web = Get-AppExposurePropertyValue -Object $Application -Name 'web'
    $implicitGrant = Get-AppExposurePropertyValue -Object $web -Name 'implicitGrantSettings'
    $spa = Get-AppExposurePropertyValue -Object $Application -Name 'spa'
    $publicClient = Get-AppExposurePropertyValue -Object $Application -Name 'publicClient'
    $api = Get-AppExposurePropertyValue -Object $Application -Name 'api'

    $scopes = @(
        @((Get-AppExposurePropertyValue -Object $api -Name 'oauth2PermissionScopes')) |
        Where-Object { $null -ne $_ } |
        ForEach-Object {
            [PSCustomObject]@{
                Id                      = [string](Get-AppExposurePropertyValue -Object $_ -Name 'id')
                Value                   = [string](Get-AppExposurePropertyValue -Object $_ -Name 'value')
                Type                    = [string](Get-AppExposurePropertyValue -Object $_ -Name 'type')
                IsEnabled               = Get-AppExposurePropertyValue -Object $_ -Name 'isEnabled'
                AdminConsentDisplayName = [string](Get-AppExposurePropertyValue -Object $_ -Name 'adminConsentDisplayName')
                UserConsentDisplayName  = [string](Get-AppExposurePropertyValue -Object $_ -Name 'userConsentDisplayName')
            }
        }
    )
    $preAuthorized = @(
        @((Get-AppExposurePropertyValue -Object $api -Name 'preAuthorizedApplications')) |
        Where-Object { $null -ne $_ } |
        ForEach-Object {
            [PSCustomObject]@{
                AppId                  = [string](Get-AppExposurePropertyValue -Object $_ -Name 'appId')
                DelegatedPermissionIds = @((Get-AppExposurePropertyValue -Object $_ -Name 'delegatedPermissionIds'))
            }
        }
    )
    $appRoles = @(
        @((Get-AppExposurePropertyValue -Object $Application -Name 'appRoles')) |
        Where-Object { $null -ne $_ } |
        ForEach-Object {
            [PSCustomObject]@{
                Id                 = [string](Get-AppExposurePropertyValue -Object $_ -Name 'id')
                Value              = [string](Get-AppExposurePropertyValue -Object $_ -Name 'value')
                DisplayName        = [string](Get-AppExposurePropertyValue -Object $_ -Name 'displayName')
                Description        = [string](Get-AppExposurePropertyValue -Object $_ -Name 'description')
                IsEnabled          = Get-AppExposurePropertyValue -Object $_ -Name 'isEnabled'
                AllowedMemberTypes = @((Get-AppExposurePropertyValue -Object $_ -Name 'allowedMemberTypes'))
            }
        }
    )

    return [PSCustomObject]@{
        ObjectId            = [string](Get-AppExposurePropertyValue -Object $Application -Name 'id')
        AppId               = [string](Get-AppExposurePropertyValue -Object $Application -Name 'appId')
        DisplayName         = [string](Get-AppExposurePropertyValue -Object $Application -Name 'displayName')
        CreatedDateTime     = Get-AppExposurePropertyValue -Object $Application -Name 'createdDateTime'
        SignInAudience      = [string](Get-AppExposurePropertyValue -Object $Application -Name 'signInAudience')
        PublisherDomain     = [string](Get-AppExposurePropertyValue -Object $Application -Name 'publisherDomain')
        VerifiedPublisher   = if ($verifiedPublisher) { [PSCustomObject]@{
            DisplayName         = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'displayName'
            VerifiedPublisherId = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'verifiedPublisherId'
            AddedDateTime       = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'addedDateTime'
        } } else { $null }
        Authentication      = [PSCustomObject]@{
            IsFallbackPublicClient                    = [bool](Get-AppExposurePropertyValue -Object $Application -Name 'isFallbackPublicClient')
            PublicClientRedirectUris                  = @((Get-AppExposurePropertyValue -Object $publicClient -Name 'redirectUris'))
            SpaRedirectUris                           = @((Get-AppExposurePropertyValue -Object $spa -Name 'redirectUris'))
            WebRedirectUris                           = @((Get-AppExposurePropertyValue -Object $web -Name 'redirectUris'))
            WebImplicitAccessTokenIssuanceEnabled     = [bool](Get-AppExposurePropertyValue -Object $implicitGrant -Name 'enableAccessTokenIssuance')
            WebImplicitIdTokenIssuanceEnabled         = [bool](Get-AppExposurePropertyValue -Object $implicitGrant -Name 'enableIdTokenIssuance')
        }
        ApiConfiguration     = [PSCustomObject]@{
            AcceptMappedClaims           = Get-AppExposurePropertyValue -Object $api -Name 'acceptMappedClaims'
            RequestedAccessTokenVersion  = Get-AppExposurePropertyValue -Object $api -Name 'requestedAccessTokenVersion'
            KnownClientApplications      = @((Get-AppExposurePropertyValue -Object $api -Name 'knownClientApplications'))
            Oauth2PermissionScopes        = $scopes
            PreAuthorizedApplications    = $preAuthorized
            AppRoles                     = $appRoles
            IdentifierUris               = @((Get-AppExposurePropertyValue -Object $Application -Name 'identifierUris'))
            OptionalClaims                = Get-AppExposurePropertyValue -Object $Application -Name 'optionalClaims'
        }
        KeyCredentials      = @((Get-AppExposurePropertyValue -Object $Application -Name 'keyCredentials'))
        PasswordCredentials = @((Get-AppExposurePropertyValue -Object $Application -Name 'passwordCredentials'))
        CollectionSourceUri = $SourceUri
    }
}

function ConvertTo-AppExposureServicePrincipalRecord {
    param(
        [Parameter(Mandatory = $true)]$ServicePrincipal,
        [Parameter(Mandatory = $true)][string]$TenantId
    )

    $ownerOrg = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'appOwnerOrganizationId')
    $verifiedPublisher = Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'verifiedPublisher'
    return [PSCustomObject]@{
        ObjectId               = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'id')
        AppId                  = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'appId')
        DisplayName            = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'displayName')
        ServicePrincipalType   = [string](Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'servicePrincipalType')
        AppOwnerOrganizationId = $ownerOrg
        AccountEnabled         = Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'accountEnabled'
        CreatedDateTime        = Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'createdDateTime'
        Tags                   = @((Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'tags'))
        AppRoles               = @((Get-AppExposurePropertyValue -Object $ServicePrincipal -Name 'appRoles'))
        Classification         = Get-AppExposureSPClassification -AppOwnerOrganizationId $ownerOrg -ScanningTenantId $TenantId
        VerifiedPublisher      = if ($verifiedPublisher) { [PSCustomObject]@{
            DisplayName         = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'displayName'
            VerifiedPublisherId = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'verifiedPublisherId'
            AddedDateTime       = Get-AppExposurePropertyValue -Object $verifiedPublisher -Name 'addedDateTime'
        } } else { $null }
    }
}


function Get-AppExposureOrganizationName {
    [CmdletBinding()]
    param()

    $uri = 'https://graph.microsoft.com/v1.0/organization?$select=displayName'
    $org = @(Invoke-AppExposureGraphRequest -Uri $uri -FollowPagination:$false)
    if ($org.Count -eq 0) { return $null }
    return [string](Get-AppExposurePropertyValue -Object $org[0] -Name 'displayName')
}

function Get-AppExposureApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$AppId
    )

    $select = 'id,appId,displayName,createdDateTime,signInAudience,publisherDomain,verifiedPublisher,isFallbackPublicClient,publicClient,spa,web,api,appRoles,identifierUris,optionalClaims,keyCredentials,passwordCredentials'
    if ($AppId) {
        $escaped = $AppId.Replace("'", "''")
        $uri = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$escaped'&`$select=$select"
    }
    else {
        $uri = "https://graph.microsoft.com/v1.0/applications?`$select=$select&`$top=999"
    }

    Write-Host '[Collector] Fetching application registrations...' -ForegroundColor Cyan
    $apps = @(Invoke-AppExposureGraphRequest -Uri $uri)
    $normalized = @($apps | ForEach-Object { ConvertTo-AppExposureApplicationRecord -Application $_ -SourceUri $uri })
    Write-Host "[Collector] Collected $($normalized.Count) application registration(s)." -ForegroundColor Green
    return @($normalized)
}

function Get-AppExposureServicePrincipals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId
    )

    $select = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,createdDateTime,tags,verifiedPublisher,appRoles'
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$select&`$top=999"
    Write-Host '[Collector] Fetching service principals...' -ForegroundColor Cyan
    $sps = @(Invoke-AppExposureGraphRequest -Uri $uri)
    $normalized = @($sps | ForEach-Object { ConvertTo-AppExposureServicePrincipalRecord -ServicePrincipal $_ -TenantId $TenantId })
    Write-Host "[Collector] Collected $($normalized.Count) service principal(s)." -ForegroundColor Green
    return @($normalized)
}

function Find-AppExposureServicePrincipal {
    <#
    .SYNOPSIS
        Resolves one service principal without first enumerating the tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $false)][string]$TargetAppId,
        [Parameter(Mandatory = $false)][string]$TargetDisplayName
    )

    if (-not $TargetAppId -and -not $TargetDisplayName) {
        throw 'Single scope requires -TargetAppId or -TargetDisplayName.'
    }

    $select = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,createdDateTime,tags,verifiedPublisher,appRoles'
    $matches = @()

    if ($TargetAppId) {
        try {
            $byObjectId = @(Invoke-AppExposureGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$TargetAppId`?`$select=$select" -FollowPagination:$false)
            if ($byObjectId.Count -eq 1) { $matches = @($byObjectId) }
        }
        catch {
            # The supplied GUID may be an application/client ID rather than the
            # service-principal object ID; fall through to the appId filter.
        }

        if ($matches.Count -eq 0) {
            $escaped = $TargetAppId.Replace("'", "''")
            $matches = @(Invoke-AppExposureGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$escaped'&`$select=$select")
        }
    }
    else {
        $escaped = $TargetDisplayName.Replace("'", "''")
        $matches = @(Invoke-AppExposureGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startsWith(displayName,'$escaped')&`$select=$select")
    }

    if ($matches.Count -eq 0) { throw 'No service principal matched the requested single-scope target.' }
    if ($matches.Count -gt 1) {
        $names = ($matches | ForEach-Object { "$(Get-AppExposurePropertyValue -Object $_ -Name 'displayName') [$((Get-AppExposurePropertyValue -Object $_ -Name 'appId'))]" }) -join '; '
        throw "Single-scope target is ambiguous. Matches: $names"
    }

    return ConvertTo-AppExposureServicePrincipalRecord -ServicePrincipal $matches[0] -TenantId $TenantId
}


<#
.SYNOPSIS
    Collects application permissions, delegated OAuth grants, owners, and
    application-registration credentials.

.DESCRIPTION
    Collection-only module. Tenant-wide orchestration uses Microsoft Graph JSON
    batching for independent read-only GETs and reuses the already collected
    application/service-principal inventory for credential and permission-name
    resolution. Each surface still returns an explicit CollectionState so
    downstream findings and drift fail closed on incomplete evidence.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppExposureConsentFailureState {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $responseProp = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($responseProp -and $responseProp.Value) {
        $statusProp = $responseProp.Value.PSObject.Properties['StatusCode']
        if ($statusProp -and $null -ne $statusProp.Value) {
            try {
                $status = [int]$statusProp.Value
                if ($status -in @(401, 403)) { return 'NotAuthorized' }
                if ($status -eq 404) { return 'NotFound' }
            }
            catch { }
        }
    }
    return 'Failed'
}

function New-AppExposureCollectionResult {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Items = @(),
        [Parameter(Mandatory = $false)][string]$SourceUri,
        [Parameter(Mandatory = $false)][string]$Error
    )

    return [PSCustomObject]@{
        CollectionState = $State
        SourceUri       = $SourceUri
        Error           = $Error
        Items           = @($Items)
    }
}

function New-AppExposureResourceServicePrincipalIndex {
    param([Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$ServicePrincipals = @())

    $index = @{}
    foreach ($sp in @($ServicePrincipals)) {
        $id = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $roleMap = @{}
        foreach ($role in @((Get-AppExposurePropertyValue -Object $sp -Name 'AppRoles'))) {
            if ($null -eq $role) { continue }
            $roleId = [string](Get-AppExposurePropertyValue -Object $role -Name 'id')
            if (-not $roleId) { $roleId = [string](Get-AppExposurePropertyValue -Object $role -Name 'Id') }
            $roleValue = [string](Get-AppExposurePropertyValue -Object $role -Name 'value')
            if (-not $roleValue) { $roleValue = [string](Get-AppExposurePropertyValue -Object $role -Name 'Value') }
            if ($roleId) { $roleMap[$roleId] = $roleValue }
        }
        $index[$id] = [PSCustomObject]@{
            AppId       = [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppId')
            DisplayName = [string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')
            RoleMap     = $roleMap
        }
    }
    return $index
}

function Get-AppExposureResourceRoleInfo {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [Parameter(Mandatory = $false)][string]$FallbackDisplayName,
        [Parameter(Mandatory = $true)][hashtable]$ResourceIndex,
        [Parameter(Mandatory = $true)][hashtable]$FallbackCache
    )

    if ($ResourceIndex.ContainsKey($ResourceId)) { return $ResourceIndex[$ResourceId] }
    if ($FallbackCache.ContainsKey($ResourceId)) { return $FallbackCache[$ResourceId] }

    try {
        $resourceUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceId`?`$select=id,appId,displayName,appRoles"
        $resourceResult = @(Invoke-AppExposureGraphRequest -Uri $resourceUri -FollowPagination:$false)
        $resource = $resourceResult[0]
        $roleMap = @{}
        foreach ($role in @((Get-AppExposurePropertyValue -Object $resource -Name 'appRoles'))) {
            if ($null -eq $role) { continue }
            $roleId = [string](Get-AppExposurePropertyValue -Object $role -Name 'id')
            if ($roleId) { $roleMap[$roleId] = [string](Get-AppExposurePropertyValue -Object $role -Name 'value') }
        }
        $info = [PSCustomObject]@{
            AppId       = [string](Get-AppExposurePropertyValue -Object $resource -Name 'appId')
            DisplayName = [string](Get-AppExposurePropertyValue -Object $resource -Name 'displayName')
            RoleMap     = $roleMap
        }
    }
    catch {
        $info = [PSCustomObject]@{ AppId = $null; DisplayName = $FallbackDisplayName; RoleMap = @{} }
    }
    $FallbackCache[$ResourceId] = $info
    return $info
}

function ConvertTo-AppExposureApplicationPermissionResult {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Assignments = @(),
        [Parameter(Mandatory = $true)][string]$SourceUri,
        [Parameter(Mandatory = $true)][hashtable]$ResourceIndex,
        [Parameter(Mandatory = $true)][hashtable]$FallbackCache
    )

    $resolved = New-Object System.Collections.Generic.List[object]
    $resolutionFailures = 0
    foreach ($assignment in @($Assignments)) {
        $resourceId = [string](Get-AppExposurePropertyValue -Object $assignment -Name 'resourceId')
        $appRoleId = [string](Get-AppExposurePropertyValue -Object $assignment -Name 'appRoleId')
        $resourceName = [string](Get-AppExposurePropertyValue -Object $assignment -Name 'resourceDisplayName')
        $permissionValue = $null
        $resourceAppId = $null

        if ($resourceId) {
            $resourceInfo = Get-AppExposureResourceRoleInfo -ResourceId $resourceId -FallbackDisplayName $resourceName -ResourceIndex $ResourceIndex -FallbackCache $FallbackCache
            $resourceAppId = [string](Get-AppExposurePropertyValue -Object $resourceInfo -Name 'AppId')
            if (-not $resourceName) { $resourceName = [string]$resourceInfo.DisplayName }
            if ($resourceInfo.RoleMap.ContainsKey($appRoleId)) { $permissionValue = [string]$resourceInfo.RoleMap[$appRoleId] }
        }

        $resolutionState = if ($permissionValue) { 'Complete' } else { 'Unresolved' }
        if ($resolutionState -ne 'Complete') { $resolutionFailures++ }
        $resolved.Add([PSCustomObject]@{
            AssignmentId        = [string](Get-AppExposurePropertyValue -Object $assignment -Name 'id')
            ResourceId          = $resourceId
            ResourceAppId       = $resourceAppId
            ResourceDisplayName = $resourceName
            AppRoleId           = $appRoleId
            PermissionValue     = $permissionValue
            ResolutionState     = $resolutionState
        })
    }

    $state = if ($resolutionFailures -gt 0) { 'Partial' } else { 'Complete' }
    $errorText = if ($resolutionFailures -gt 0) { "$resolutionFailures app-role value(s) could not be resolved from their resource service principal." } else { $null }
    return New-AppExposureCollectionResult -State $state -Items $resolved.ToArray() -SourceUri $SourceUri -Error $errorText
}

function ConvertTo-AppExposureDelegatedPermissionResult {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Grants = @(),
        [Parameter(Mandatory = $true)][string]$SourceUri,
        [Parameter(Mandatory = $true)][hashtable]$ResourceIndex,
        [Parameter(Mandatory = $true)][hashtable]$FallbackCache
    )

    $resolved = New-Object System.Collections.Generic.List[object]
    $resolutionFailures = 0
    foreach ($grant in @($Grants)) {
        $resourceId = [string](Get-AppExposurePropertyValue -Object $grant -Name 'resourceId')
        $resourceAppId = $null
        $resourceName = $null
        if ($resourceId) {
            $resourceInfo = Get-AppExposureResourceRoleInfo -ResourceId $resourceId -ResourceIndex $ResourceIndex -FallbackCache $FallbackCache
            $resourceAppId = [string](Get-AppExposurePropertyValue -Object $resourceInfo -Name 'AppId')
            $resourceName = [string]$resourceInfo.DisplayName
        }
        $resolutionState = if (-not [string]::IsNullOrWhiteSpace($resourceAppId)) { 'Complete' } else { 'Unresolved' }
        if ($resolutionState -ne 'Complete') { $resolutionFailures++ }
        $scopeText = [string](Get-AppExposurePropertyValue -Object $grant -Name 'scope')
        $scopes = if ([string]::IsNullOrWhiteSpace($scopeText)) { @() } else { @($scopeText.Trim() -split '\s+' | Where-Object { $_ }) }
        foreach ($scope in $scopes) {
            $resolved.Add([PSCustomObject]@{
                GrantId             = [string](Get-AppExposurePropertyValue -Object $grant -Name 'id')
                ResourceId          = $resourceId
                ResourceAppId       = $resourceAppId
                ResourceDisplayName = $resourceName
                ConsentType         = [string](Get-AppExposurePropertyValue -Object $grant -Name 'consentType')
                PrincipalId         = [string](Get-AppExposurePropertyValue -Object $grant -Name 'principalId')
                PermissionValue     = [string]$scope
                ResolutionState     = $resolutionState
            })
        }
    }
    $state = if ($resolutionFailures -gt 0) { 'Partial' } else { 'Complete' }
    $errorText = if ($resolutionFailures -gt 0) { "$resolutionFailures delegated grant resource(s) could not be resolved to a resource application ID." } else { $null }
    return New-AppExposureCollectionResult -State $state -Items $resolved.ToArray() -SourceUri $SourceUri -Error $errorText
}

function ConvertTo-AppExposureOwnerResult {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Owners = @(),
        [Parameter(Mandatory = $true)][string]$SourceUri
    )

    $normalized = @($Owners | ForEach-Object {
        [PSCustomObject]@{
            OwnerId        = [string](Get-AppExposurePropertyValue -Object $_ -Name 'id')
            DisplayName    = [string](Get-AppExposurePropertyValue -Object $_ -Name 'displayName')
            ObjectType     = [string](Get-AppExposurePropertyValue -Object $_ -Name '@odata.type')
            UserType       = Get-AppExposurePropertyValue -Object $_ -Name 'userType'
            AccountEnabled = Get-AppExposurePropertyValue -Object $_ -Name 'accountEnabled'
        }
    })
    return New-AppExposureCollectionResult -State 'Complete' -Items $normalized -SourceUri $SourceUri
}

function ConvertTo-AppExposureCredentialResult {
    param(
        [Parameter(Mandatory = $true)]$Application,
        [Parameter(Mandatory = $true)][string]$SourceUri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $keyCredentials = Get-AppExposurePropertyValue -Object $Application -Name 'KeyCredentials'
    if ($null -eq $keyCredentials) { $keyCredentials = Get-AppExposurePropertyValue -Object $Application -Name 'keyCredentials' }
    foreach ($cred in @($keyCredentials)) {
        if ($null -eq $cred) { continue }
        $items.Add([PSCustomObject]@{
            CredentialType = 'Certificate'
            KeyId          = [string](Get-AppExposurePropertyValue -Object $cred -Name 'keyId')
            DisplayName    = [string](Get-AppExposurePropertyValue -Object $cred -Name 'displayName')
            StartDateTime  = Get-AppExposurePropertyValue -Object $cred -Name 'startDateTime'
            EndDateTime    = Get-AppExposurePropertyValue -Object $cred -Name 'endDateTime'
        })
    }
    $passwordCredentials = Get-AppExposurePropertyValue -Object $Application -Name 'PasswordCredentials'
    if ($null -eq $passwordCredentials) { $passwordCredentials = Get-AppExposurePropertyValue -Object $Application -Name 'passwordCredentials' }
    foreach ($cred in @($passwordCredentials)) {
        if ($null -eq $cred) { continue }
        $items.Add([PSCustomObject]@{
            CredentialType = 'Secret'
            KeyId          = [string](Get-AppExposurePropertyValue -Object $cred -Name 'keyId')
            DisplayName    = [string](Get-AppExposurePropertyValue -Object $cred -Name 'displayName')
            StartDateTime  = Get-AppExposurePropertyValue -Object $cred -Name 'startDateTime'
            EndDateTime    = Get-AppExposurePropertyValue -Object $cred -Name 'endDateTime'
        })
    }
    return New-AppExposureCollectionResult -State 'Complete' -Items $items.ToArray() -SourceUri $SourceUri
}

function Get-AppExposurePermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServicePrincipalId)

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments?`$select=id,resourceId,resourceDisplayName,appRoleId&`$top=999"
    try { $assignments = @(Invoke-AppExposureGraphRequest -Uri $uri) }
    catch {
        $state = Get-AppExposureConsentFailureState -ErrorRecord $_
        Write-Warning "Could not read appRoleAssignments for service principal ${ServicePrincipalId}: $($_.Exception.Message)"
        return New-AppExposureCollectionResult -State $state -SourceUri $uri -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureApplicationPermissionResult -Assignments $assignments -SourceUri $uri -ResourceIndex @{} -FallbackCache @{}
}

function Get-AppExposurePermissionsBulk {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipals)

    $resultMap = @{}
    if (@($ServicePrincipals).Count -eq 0) { return $resultMap }
    $requests = @($ServicePrincipals | ForEach-Object {
        $id = [string]$_.ObjectId
        [PSCustomObject]@{ Id=$id; Uri="https://graph.microsoft.com/v1.0/servicePrincipals/$id/appRoleAssignments?`$select=id,resourceId,resourceDisplayName,appRoleId&`$top=999" }
    })
    $batchResults = @(Invoke-AppExposureGraphBatchRequest -Requests $requests -ApiVersion 'v1.0')
    $resourceIndex = New-AppExposureResourceServicePrincipalIndex -ServicePrincipals $ServicePrincipals
    $fallbackCache = @{}
    foreach ($batch in $batchResults) {
        $id = [string]$batch.Id
        if ([string]$batch.CollectionState -ne 'Complete') {
            $resultMap[$id] = New-AppExposureCollectionResult -State ([string]$batch.CollectionState) -SourceUri ([string]$batch.SourceUri) -Error ([string]$batch.Error)
        }
        else {
            $resultMap[$id] = ConvertTo-AppExposureApplicationPermissionResult -Assignments @($batch.Items) -SourceUri ([string]$batch.SourceUri) -ResourceIndex $resourceIndex -FallbackCache $fallbackCache
        }
    }
    return $resultMap
}

function Get-AppExposureDelegatedPermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServicePrincipalId)

    $encodedFilter = [uri]::EscapeDataString("clientId eq '$ServicePrincipalId'")
    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$encodedFilter"
    try { $grants = @(Invoke-AppExposureGraphRequest -Uri $uri) }
    catch {
        $state = Get-AppExposureConsentFailureState -ErrorRecord $_
        Write-Warning "Could not read oauth2PermissionGrants for service principal ${ServicePrincipalId}: $($_.Exception.Message)"
        return New-AppExposureCollectionResult -State $state -SourceUri $uri -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureDelegatedPermissionResult -Grants $grants -SourceUri $uri -ResourceIndex @{} -FallbackCache @{}
}

function Get-AppExposureDelegatedPermissionsBulk {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipals)

    $resultMap = @{}
    if (@($ServicePrincipals).Count -eq 0) { return $resultMap }
    $requests = @($ServicePrincipals | ForEach-Object {
        $id = [string]$_.ObjectId
        $encodedFilter = [uri]::EscapeDataString("clientId eq '$id'")
        [PSCustomObject]@{ Id=$id; Uri="https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$encodedFilter" }
    })
    $batchResults = @(Invoke-AppExposureGraphBatchRequest -Requests $requests -ApiVersion 'v1.0')
    $resourceIndex = New-AppExposureResourceServicePrincipalIndex -ServicePrincipals $ServicePrincipals
    $fallbackCache = @{}
    foreach ($batch in $batchResults) {
        $id = [string]$batch.Id
        if ([string]$batch.CollectionState -ne 'Complete') {
            $resultMap[$id] = New-AppExposureCollectionResult -State ([string]$batch.CollectionState) -SourceUri ([string]$batch.SourceUri) -Error ([string]$batch.Error)
        }
        else {
            $resultMap[$id] = ConvertTo-AppExposureDelegatedPermissionResult -Grants @($batch.Items) -SourceUri ([string]$batch.SourceUri) -ResourceIndex $resourceIndex -FallbackCache $fallbackCache
        }
    }
    return $resultMap
}

function Get-AppExposureOwners {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServicePrincipalId)

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/owners`?`$select=id,displayName,userType,accountEnabled"
    try { $owners = @(Invoke-AppExposureGraphRequest -Uri $uri) }
    catch {
        $state = Get-AppExposureConsentFailureState -ErrorRecord $_
        Write-Warning "Could not read owners for service principal ${ServicePrincipalId}: $($_.Exception.Message)"
        return New-AppExposureCollectionResult -State $state -SourceUri $uri -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureOwnerResult -Owners $owners -SourceUri $uri
}

function Get-AppExposureOwnersBulk {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipals)

    $resultMap = @{}
    if (@($ServicePrincipals).Count -eq 0) { return $resultMap }
    $requests = @($ServicePrincipals | ForEach-Object {
        $id = [string]$_.ObjectId
        [PSCustomObject]@{ Id=$id; Uri="https://graph.microsoft.com/v1.0/servicePrincipals/$id/owners`?`$select=id,displayName,userType,accountEnabled" }
    })
    foreach ($batch in @(Invoke-AppExposureGraphBatchRequest -Requests $requests -ApiVersion 'v1.0')) {
        $id = [string]$batch.Id
        if ([string]$batch.CollectionState -eq 'Complete') { $resultMap[$id] = ConvertTo-AppExposureOwnerResult -Owners @($batch.Items) -SourceUri ([string]$batch.SourceUri) }
        else { $resultMap[$id] = New-AppExposureCollectionResult -State ([string]$batch.CollectionState) -SourceUri ([string]$batch.SourceUri) -Error ([string]$batch.Error) }
    }
    return $resultMap
}

function Get-AppExposureApplicationOwners {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$AppRegistrationObjectId)

    $uri = "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId/owners`?`$select=id,displayName,userType,accountEnabled"
    try { $owners = @(Invoke-AppExposureGraphRequest -Uri $uri) }
    catch {
        $state = Get-AppExposureConsentFailureState -ErrorRecord $_
        Write-Warning "Could not read owners for application object ${AppRegistrationObjectId}: $($_.Exception.Message)"
        return New-AppExposureCollectionResult -State $state -SourceUri $uri -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureOwnerResult -Owners $owners -SourceUri $uri
}

function Get-AppExposureApplicationOwnersBulk {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Applications)

    $resultMap = @{}
    if (@($Applications).Count -eq 0) { return $resultMap }
    $requests = @($Applications | ForEach-Object {
        $id = [string]$_.ObjectId
        [PSCustomObject]@{ Id=$id; Uri="https://graph.microsoft.com/v1.0/applications/$id/owners`?`$select=id,displayName,userType,accountEnabled" }
    })
    foreach ($batch in @(Invoke-AppExposureGraphBatchRequest -Requests $requests -ApiVersion 'v1.0')) {
        $id = [string]$batch.Id
        if ([string]$batch.CollectionState -eq 'Complete') { $resultMap[$id] = ConvertTo-AppExposureOwnerResult -Owners @($batch.Items) -SourceUri ([string]$batch.SourceUri) }
        else { $resultMap[$id] = New-AppExposureCollectionResult -State ([string]$batch.CollectionState) -SourceUri ([string]$batch.SourceUri) -Error ([string]$batch.Error) }
    }
    return $resultMap
}

function Get-AppExposureCredentialsFromApplication {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Application)

    $sourceUri = [string](Get-AppExposurePropertyValue -Object $Application -Name 'CollectionSourceUri')
    if ([string]::IsNullOrWhiteSpace($sourceUri)) { $sourceUri = 'https://graph.microsoft.com/v1.0/applications' }
    return ConvertTo-AppExposureCredentialResult -Application $Application -SourceUri $sourceUri
}

function Get-AppExposureCredentials {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$AppRegistrationObjectId)

    $uri = "https://graph.microsoft.com/v1.0/applications/$AppRegistrationObjectId`?`$select=id,appId,keyCredentials,passwordCredentials"
    try {
        $result = @(Invoke-AppExposureGraphRequest -Uri $uri -FollowPagination:$false)
        $app = $result[0]
    }
    catch {
        $state = Get-AppExposureConsentFailureState -ErrorRecord $_
        Write-Warning "Could not read credentials for application object ${AppRegistrationObjectId}: $($_.Exception.Message)"
        return New-AppExposureCollectionResult -State $state -SourceUri $uri -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureCredentialResult -Application $app -SourceUri $uri
}


<#
.SYNOPSIS
    Optional sign-in activity collection for application identities.

.DESCRIPTION
    Activity is evidence only. A successful lookup with no activity inside the
    configured lookback window is not treated as proof that an application is
    globally inactive.

    Bulk collection prefers the Microsoft Graph beta
    /reports/servicePrincipalSignInActivities report so tenant-wide last-use
    context can be collected with pagination instead of one sign-in-log query per
    service principal. If that preview report is unavailable for a transient or
    compatibility reason, the previous batched auditLogs/signIns query path is
    retained as a fail-closed fallback. Authorization failures do not trigger the
    expensive fallback because both surfaces require audit-log read permission.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppExposureActivityPropertyValue {
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function ConvertTo-AppExposureActivityUtcTimestamp {
    param([Parameter(Mandatory = $false)][AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return ([datetimeoffset]::Parse([string]$Value).ToUniversalTime().ToString('o')) }
    catch { throw "Invalid activity timestamp '$Value'." }
}

function Get-AppExposureReportActivityTimestamp {
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Row,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )
    if ($null -eq $Row) { return $null }
    $activity = Get-AppExposureActivityPropertyValue -Object $Row -Name $PropertyName
    if ($null -eq $activity) { return $null }
    $raw = Get-AppExposureActivityPropertyValue -Object $activity -Name 'lastSignInDateTime'
    if (-not $raw) { return $null }
    return ConvertTo-AppExposureActivityUtcTimestamp -Value $raw
}

function Get-AppExposureActivityFailureState {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    $responseProp = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($responseProp -and $responseProp.Value) {
        $statusProp = $responseProp.Value.PSObject.Properties['StatusCode']
        if ($statusProp -and $null -ne $statusProp.Value) {
            try {
                $status = [int]$statusProp.Value
                if ($status -in @(401, 403)) { return 'NotAuthorized' }
            }
            catch { }
        }
    }
    return 'Failed'
}

function New-AppExposureActivityUri {
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $true)][int]$LookbackDays
    )

    $cutoff = [datetime]::UtcNow.AddDays(-1 * $LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $eventTypes = @('interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity')
    $typeFilter = ($eventTypes | ForEach-Object { "t eq '$_'" }) -join ' or '
    $filter = "createdDateTime ge $cutoff and appId eq '$AppId' and signInEventTypes/any(t: $typeFilter)"
    $encodedFilter = [uri]::EscapeDataString($filter)
    return "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$orderby=createdDateTime desc&`$top=1"
}

function New-AppExposureActivityReportUri {
    param([Parameter(Mandatory = $false)][string]$AppId)

    $baseUri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
    if ([string]::IsNullOrWhiteSpace($AppId)) { return "$baseUri`?`$top=999" }
    $escaped = $AppId.Replace("'", "''")
    $encodedFilter = [uri]::EscapeDataString("appId eq '$escaped'")
    return "$baseUri`?`$filter=$encodedFilter"
}

function Get-AppExposureReportLastSignInDateTime {
    param([Parameter(Mandatory = $false)][AllowNull()]$Row)
    return Get-AppExposureReportActivityTimestamp -Row $Row -PropertyName 'lastSignInActivity'
}

function ConvertTo-AppExposureActivityResult {
    param(
        [Parameter(Mandatory = $true)][string]$SourceUri,
        [Parameter(Mandatory = $true)][int]$LookbackDays,
        [Parameter(Mandatory = $true)][string]$CollectionState,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory = $false)][string]$Error
    )

    if ($CollectionState -ne 'Complete') {
        return [PSCustomObject]@{
            CollectionState    = $CollectionState
            SourceKind         = 'SignInLogsFallback'
            SourceUri          = $SourceUri
            LookbackDays       = $LookbackDays
            LastSignInDateTime = $null
            ApplicationAuthenticationClientLastSignInDateTime = $null
            ApplicationAuthenticationResourceLastSignInDateTime = $null
            DelegatedClientLastSignInDateTime = $null
            DelegatedResourceLastSignInDateTime = $null
            NoActivityObserved = $false
            Error              = $Error
        }
    }

    $lastSignIn = $null
    if (@($Rows).Count -gt 0) {
        $raw = Get-AppExposureActivityPropertyValue -Object $Rows[0] -Name 'createdDateTime'
        try { $lastSignIn = ConvertTo-AppExposureActivityUtcTimestamp -Value $raw }
        catch {
            return [PSCustomObject]@{
                CollectionState='Failed'; SourceKind='SignInLogsFallback'; SourceUri=$SourceUri; LookbackDays=$LookbackDays; LastSignInDateTime=$null
                ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null
                DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
                NoActivityObserved=$false; Error=$_.Exception.Message
            }
        }
    }
    return [PSCustomObject]@{
        CollectionState    = 'Complete'
        SourceKind         = 'SignInLogsFallback'
        SourceUri          = $SourceUri
        LookbackDays       = $LookbackDays
        LastSignInDateTime = $lastSignIn
        ApplicationAuthenticationClientLastSignInDateTime = $null
        ApplicationAuthenticationResourceLastSignInDateTime = $null
        DelegatedClientLastSignInDateTime = $null
        DelegatedResourceLastSignInDateTime = $null
        NoActivityObserved = [bool](@($Rows).Count -eq 0)
        Error              = $null
    }
}

function ConvertTo-AppExposureActivityReportResult {
    param(
        [Parameter(Mandatory = $true)][string]$SourceUri,
        [Parameter(Mandatory = $true)][int]$LookbackDays,
        [Parameter(Mandatory = $false)][AllowNull()]$Row
    )

    try {
        $lastSignIn = Get-AppExposureReportLastSignInDateTime -Row $Row
        $appClient = Get-AppExposureReportActivityTimestamp -Row $Row -PropertyName 'applicationAuthenticationClientSignInActivity'
        $appResource = Get-AppExposureReportActivityTimestamp -Row $Row -PropertyName 'applicationAuthenticationResourceSignInActivity'
        $delegatedClient = Get-AppExposureReportActivityTimestamp -Row $Row -PropertyName 'delegatedClientSignInActivity'
        $delegatedResource = Get-AppExposureReportActivityTimestamp -Row $Row -PropertyName 'delegatedResourceSignInActivity'
    }
    catch {
        return [PSCustomObject]@{
            CollectionState='Failed'; SourceKind='ServicePrincipalSignInActivities'; SourceUri=$SourceUri; LookbackDays=$LookbackDays; LastSignInDateTime=$null
            ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null
            DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
            NoActivityObserved=$false; Error=$_.Exception.Message
        }
    }

    $observedInsideWindow = $false
    if ($lastSignIn) {
        $parsed = [datetimeoffset]::Parse($lastSignIn).UtcDateTime
        $cutoff = [datetime]::UtcNow.AddDays(-1 * $LookbackDays)
        $observedInsideWindow = ($parsed -ge $cutoff)
    }

    return [PSCustomObject]@{
        CollectionState    = 'Complete'
        SourceKind         = 'ServicePrincipalSignInActivities'
        SourceUri          = $SourceUri
        LookbackDays       = $LookbackDays
        LastSignInDateTime = $lastSignIn
        ApplicationAuthenticationClientLastSignInDateTime = $appClient
        ApplicationAuthenticationResourceLastSignInDateTime = $appResource
        DelegatedClientLastSignInDateTime = $delegatedClient
        DelegatedResourceLastSignInDateTime = $delegatedResource
        NoActivityObserved = [bool](-not $observedInsideWindow)
        Error              = $null
    }
}

function Get-AppExposureLastSignInLegacy {
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $true)][int]$LookbackDays
    )

    $uri = New-AppExposureActivityUri -AppId $AppId -LookbackDays $LookbackDays
    try {
        $rows = @(Invoke-AppExposureGraphRequest -Uri $uri -FollowPagination:$false -ExtraHeaders @{ ConsistencyLevel = 'eventual' })
    }
    catch {
        $state = Get-AppExposureActivityFailureState -ErrorRecord $_
        Write-Warning "Sign-in lookup failed for appId ${AppId}: $($_.Exception.Message)"
        return ConvertTo-AppExposureActivityResult -SourceUri $uri -LookbackDays $LookbackDays -CollectionState $state -Error $_.Exception.Message
    }
    return ConvertTo-AppExposureActivityResult -SourceUri $uri -LookbackDays $LookbackDays -CollectionState 'Complete' -Rows $rows
}

function Get-AppExposureLastSignIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AppId,
        [Parameter(Mandatory = $false)][ValidateRange(1, 90)][int]$LookbackDays = 90
    )

    $reportUri = New-AppExposureActivityReportUri -AppId $AppId
    try {
        $rows = @(Invoke-AppExposureGraphRequest -Uri $reportUri -FollowPagination:$false)
        $row = if ($rows.Count -gt 0) { $rows[0] } else { $null }
        return ConvertTo-AppExposureActivityReportResult -SourceUri $reportUri -LookbackDays $LookbackDays -Row $row
    }
    catch {
        $state = Get-AppExposureActivityFailureState -ErrorRecord $_
        if ($state -eq 'NotAuthorized') {
            return [PSCustomObject]@{
                CollectionState='NotAuthorized'; SourceKind='ServicePrincipalSignInActivities'; SourceUri=$reportUri; LookbackDays=$LookbackDays; LastSignInDateTime=$null
                ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null; DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
                NoActivityObserved=$false; Error=$_.Exception.Message
            }
        }
        Write-Warning "Service-principal activity report lookup failed for appId ${AppId}; falling back to filtered sign-in logs. $($_.Exception.Message)"
        return Get-AppExposureLastSignInLegacy -AppId $AppId -LookbackDays $LookbackDays
    }
}

function Get-AppExposureLastSignInBulkLegacy {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipals,
        [Parameter(Mandatory = $true)][int]$LookbackDays
    )

    $resultMap = @{}
    $requests = New-Object System.Collections.Generic.List[object]
    foreach ($sp in @($ServicePrincipals)) {
        $objectId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'ObjectId')
        $appId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'AppId')
        if ([string]::IsNullOrWhiteSpace($objectId)) { continue }
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $resultMap[$objectId] = [PSCustomObject]@{
                CollectionState='Failed'; SourceKind='NotAvailable'; SourceUri=$null; LookbackDays=$LookbackDays; LastSignInDateTime=$null
                ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null; DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
                NoActivityObserved=$false; Error='Service principal has no AppId for sign-in correlation.'
            }
            continue
        }
        $requests.Add([PSCustomObject]@{
            Id               = $objectId
            Uri              = New-AppExposureActivityUri -AppId $appId -LookbackDays $LookbackDays
            Headers          = @{ ConsistencyLevel = 'eventual' }
            FollowPagination = $false
        })
    }

    if ($requests.Count -gt 0) {
        foreach ($batch in @(Invoke-AppExposureGraphBatchRequest -Requests $requests.ToArray() -ApiVersion 'beta')) {
            $id = [string]$batch.Id
            $resultMap[$id] = ConvertTo-AppExposureActivityResult `
                -SourceUri ([string]$batch.SourceUri) `
                -LookbackDays $LookbackDays `
                -CollectionState ([string]$batch.CollectionState) `
                -Rows @($batch.Items) `
                -Error ([string]$batch.Error)
        }
    }
    return $resultMap
}

function Get-AppExposureLastSignInBulk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ServicePrincipals,
        [Parameter(Mandatory = $false)][ValidateRange(1, 90)][int]$LookbackDays = 90
    )

    $resultMap = @{}
    $eligible = New-Object System.Collections.Generic.List[object]
    foreach ($sp in @($ServicePrincipals)) {
        $objectId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'ObjectId')
        $appId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'AppId')
        if ([string]::IsNullOrWhiteSpace($objectId)) { continue }
        if ([string]::IsNullOrWhiteSpace($appId)) {
            $resultMap[$objectId] = [PSCustomObject]@{
                CollectionState='Failed'; SourceKind='NotAvailable'; SourceUri=$null; LookbackDays=$LookbackDays; LastSignInDateTime=$null
                ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null; DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
                NoActivityObserved=$false; Error='Service principal has no AppId for sign-in correlation.'
            }
            continue
        }
        $eligible.Add($sp)
    }

    if ($eligible.Count -eq 0) { return $resultMap }

    $reportUri = if ($eligible.Count -eq 1) {
        $singleAppId = [string](Get-AppExposureActivityPropertyValue -Object $eligible[0] -Name 'AppId')
        New-AppExposureActivityReportUri -AppId $singleAppId
    } else {
        New-AppExposureActivityReportUri
    }
    try {
        $rows = @(Invoke-AppExposureGraphRequest -Uri $reportUri)
    }
    catch {
        $state = Get-AppExposureActivityFailureState -ErrorRecord $_
        if ($state -eq 'NotAuthorized') {
            foreach ($sp in $eligible) {
                $objectId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'ObjectId')
                $resultMap[$objectId] = [PSCustomObject]@{
                    CollectionState='NotAuthorized'; SourceKind='ServicePrincipalSignInActivities'; SourceUri=$reportUri; LookbackDays=$LookbackDays; LastSignInDateTime=$null
                    ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null
                    DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null
                    NoActivityObserved=$false; Error=$_.Exception.Message
                }
            }
            return $resultMap
        }

        Write-Warning "Tenant-wide service-principal activity report failed; falling back to batched filtered sign-in-log queries. $($_.Exception.Message)"
        $legacy = Get-AppExposureLastSignInBulkLegacy -ServicePrincipals ($eligible.ToArray()) -LookbackDays $LookbackDays
        foreach ($key in @($legacy.Keys)) { $resultMap[$key] = $legacy[$key] }
        return $resultMap
    }

    # Keep only the newest report row for each appId if the service returns a
    # duplicate. The API normally exposes one aggregate row per appId.
    $rowByAppId = @{}
    $rowDateByAppId = @{}
    foreach ($row in $rows) {
        $appId = [string](Get-AppExposureActivityPropertyValue -Object $row -Name 'appId')
        if ([string]::IsNullOrWhiteSpace($appId)) { continue }
        # Use the raw report timestamp only for duplicate-row ordering. Invalid
        # timestamps are handled per identity by ConvertTo-AppExposureActivityReportResult
        # rather than aborting the tenant-wide activity pass.
        $lastActivity = Get-AppExposureActivityPropertyValue -Object $row -Name 'lastSignInActivity'
        $rawDate = if ($lastActivity) { Get-AppExposureActivityPropertyValue -Object $lastActivity -Name 'lastSignInDateTime' } else { $null }
        $parsedDate = [datetime]::MinValue
        if ($rawDate) {
            try { $parsedDate = [datetimeoffset]::Parse([string]$rawDate).UtcDateTime }
            catch { $parsedDate = [datetime]::MinValue }
        }
        if (-not $rowByAppId.ContainsKey($appId) -or $parsedDate -gt $rowDateByAppId[$appId]) {
            $rowByAppId[$appId] = $row
            $rowDateByAppId[$appId] = $parsedDate
        }
    }

    foreach ($sp in $eligible) {
        $objectId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'ObjectId')
        $appId = [string](Get-AppExposureActivityPropertyValue -Object $sp -Name 'AppId')
        $row = if ($rowByAppId.ContainsKey($appId)) { $rowByAppId[$appId] } else { $null }
        $resultMap[$objectId] = ConvertTo-AppExposureActivityReportResult -SourceUri $reportUri -LookbackDays $LookbackDays -Row $row
    }

    return $resultMap
}

