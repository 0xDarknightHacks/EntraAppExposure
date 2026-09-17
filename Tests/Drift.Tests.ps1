#Requires -Modules Pester
Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force

InModuleScope EntraAppExposure {
BeforeAll {

    function New-TestAssessment {
        param(
            [object[]]$Permissions,
            [string]$PermissionState = 'Complete'
        )

        $empty = [PSCustomObject]@{
            CollectionState = 'Complete'
            SourceUri       = 'https://graph/test'
            Error           = $null
            Items           = @()
        }

        return [PSCustomObject]@{
            ObjectId                 = 'sp1'
            AppId                    = 'app1'
            DisplayName              = 'App One'
            Classification           = 'Local'
            ServicePrincipalType     = 'Application'
            AppOwnerOrganizationId   = 'tenant1'
            AccountEnabled           = $true
            CreatedDateTime          = '2026-01-01T00:00:00Z'
            VerifiedPublisher        = $null
            AppRegistrationObjectId  = 'appobj1'
            ApplicationPermissions   = [PSCustomObject]@{
                CollectionState = $PermissionState
                SourceUri       = 'https://graph/appRoleAssignments'
                Error           = $null
                Items           = @($Permissions)
            }
            DelegatedPermissions     = $empty
            Owners                   = $empty
            Credentials              = $empty
            Activity                 = [PSCustomObject]@{
                CollectionState    = 'Skipped'
                SourceUri          = $null
                LookbackDays       = 30
                LastSignInDateTime = $null
                NoActivityObserved = $false
            }
        }
    }
}

Describe 'Snapshot drift' {
    It 'detects a newly granted application permission' {
        $p1 = [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r1'; PermissionValue='Application.Read.All' }
        $p2 = [PSCustomObject]@{ AssignmentId='a2'; ResourceId='graph'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r2'; PermissionValue='Directory.ReadWrite.All' }
        $previous = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @($p1))) -CollectedAtUtc '2026-09-01T12:00:00Z'
        $current = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @($p1,$p2))) -CollectedAtUtc '2026-09-08T12:00:00Z'

        $changes = @(Compare-AppExposureSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current)
        @($changes | Where-Object { $_.Category -eq 'ApplicationPermission' -and $_.ChangeType -eq 'Added' }).Count | Should -Be 1
    }

    It 'does not infer removed permissions when current collection is incomplete' {
        $p1 = [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r1'; PermissionValue='Application.Read.All' }
        $previous = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @($p1))) -CollectedAtUtc '2026-09-01T12:00:00Z'
        $current = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @() -PermissionState 'Failed')) -CollectedAtUtc '2026-09-08T12:00:00Z'

        $changes = @(Compare-AppExposureSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current)
        @($changes | Where-Object { $_.Category -eq 'ApplicationPermission' -and $_.ChangeType -eq 'Removed' }).Count | Should -Be 0
    }

    It 'does not report drift when only permission display enrichment changes' {
        $unresolved = [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceDisplayName=$null; AppRoleId='r1'; PermissionValue=$null; ResolutionState='Unresolved' }
        $resolved = [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r1'; PermissionValue='Application.Read.All'; ResolutionState='Complete' }
        $previous = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @($unresolved))) -CollectedAtUtc '2026-09-01T12:00:00Z'
        $current = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @((New-TestAssessment -Permissions @($resolved))) -CollectedAtUtc '2026-09-08T12:00:00Z'

        $changes = @(Compare-AppExposureSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current)
        @($changes | Where-Object { $_.Category -eq 'ApplicationPermission' }).Count | Should -Be 0
    }


    It 'detects credential drift for an orphan application registration' {
        $owners = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appowners'; Error=$null; Items=@() }
        $oldCreds = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appcredentials'; Error=$null; Items=@() }
        $newCreds = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appcredentials'; Error=$null; Items=@(
            [PSCustomObject]@{ CredentialType='Secret'; KeyId='k1'; DisplayName='new'; StartDateTime='2026-09-01T00:00:00Z'; EndDateTime='2026-12-01T00:00:00Z' }
        ) }
        $appOld = [PSCustomObject]@{ ObjectId='appobj1'; AppId='app1'; DisplayName='Orphan'; CreatedDateTime='2026-01-01T00:00:00Z'; SignInAudience='AzureADMyOrg'; PublisherDomain='contoso.test'; VerifiedPublisher=$null; LinkedServicePrincipalIds=@(); Owners=$owners; Credentials=$oldCreds }
        $appNew = [PSCustomObject]@{ ObjectId='appobj1'; AppId='app1'; DisplayName='Orphan'; CreatedDateTime='2026-01-01T00:00:00Z'; SignInAudience='AzureADMyOrg'; PublisherDomain='contoso.test'; VerifiedPublisher=$null; LinkedServicePrincipalIds=@(); Owners=$owners; Credentials=$newCreds }
        $previous = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @($appOld) -ServicePrincipalAssessments @() -CollectedAtUtc '2026-09-01T12:00:00Z'
        $current = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @($appNew) -ServicePrincipalAssessments @() -CollectedAtUtc '2026-09-08T12:00:00Z'
        $changes = @(Compare-AppExposureSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current)
        @($changes | Where-Object { $_.Category -eq 'ApplicationCredential' -and $_.ChangeType -eq 'Added' }).Count | Should -Be 1
    }

}
}
