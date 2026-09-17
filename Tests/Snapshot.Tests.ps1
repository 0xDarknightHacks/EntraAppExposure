#Requires -Modules Pester
Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force

InModuleScope EntraAppExposure {
BeforeAll {

    function New-TestServicePrincipalAssessment {
        param([string]$PermissionState = 'Complete')
        $permissions = [PSCustomObject]@{ CollectionState=$PermissionState; SourceUri='https://graph/test'; Error=$null; Items=@() }
        $complete = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/test'; Error=$null; Items=@() }
        return [PSCustomObject]@{
            ObjectId='sp1'; AppId='app1'; DisplayName='App One'; Classification='Local'; ServicePrincipalType='Application';
            AppOwnerOrganizationId='tenant1'; AccountEnabled=$true; CreatedDateTime='2026-01-01T00:00:00Z'; VerifiedPublisher=$null;
            AppRegistrationObjectId='appobj1'; ApplicationPermissions=$permissions; DelegatedPermissions=$complete;
            Owners=$complete; Credentials=$complete;
            Activity=[PSCustomObject]@{ CollectionState='Skipped'; SourceUri=$null; LookbackDays=30; LastSignInDateTime=$null; NoActivityObserved=$false }
        }
    }

    function New-TestApplicationAssessment {
        param([string[]]$LinkedServicePrincipalIds=@('sp1'),[string]$OwnerState='Complete',[string]$CredentialState='Complete')
        return [PSCustomObject]@{
            ObjectId='appobj1'; AppId='app1'; DisplayName='App One'; CreatedDateTime='2026-01-01T00:00:00Z'; SignInAudience='AzureADMyOrg'; PublisherDomain='contoso.test'; VerifiedPublisher=$null;
            LinkedServicePrincipalIds=@($LinkedServicePrincipalIds);
            Owners=[PSCustomObject]@{ CollectionState=$OwnerState; SourceUri='https://graph/appowners'; Error=$null; Items=@() };
            Credentials=[PSCustomObject]@{ CollectionState=$CredentialState; SourceUri='https://graph/appcredentials'; Error=$null; Items=@() }
        }
    }
}

Describe 'Portable snapshot model' {
    It 'creates unique evidence observations and validates offline' {
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @((New-TestApplicationAssessment)) -ServicePrincipalAssessments @((New-TestServicePrincipalAssessment)) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $validation = Test-AppExposureSnapshot -Snapshot $snapshot
        $validation.Valid | Should -BeTrue
        $snapshot.Collection.CoreComplete | Should -BeTrue
        @($snapshot.Observations | Select-Object -ExpandProperty ObservationId -Unique).Count | Should -Be $snapshot.Observations.Count
    }


    It 'accepts an explicitly present empty incomplete-object list for a complete snapshot' {
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @((New-TestApplicationAssessment)) -ServicePrincipalAssessments @((New-TestServicePrincipalAssessment)) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $snapshot.Collection.PSObject.Properties.Name | Should -Contain 'IncompleteObjectIds'
        @($snapshot.Collection.IncompleteObjectIds).Count | Should -Be 0
        (Test-AppExposureSnapshot -Snapshot $snapshot).Valid | Should -BeTrue
    }

    It 'marks a snapshot incomplete when an application-permission surface is partial' {
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @((New-TestApplicationAssessment)) -ServicePrincipalAssessments @((New-TestServicePrincipalAssessment -PermissionState 'Partial')) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $snapshot.Collection.CoreComplete | Should -BeFalse
        $snapshot.Collection.IncompleteObjectIds | Should -Contain 'sp1'
    }

    It 'makes an orphan application registration a first-class evidence-bearing object' {
        $app = New-TestApplicationAssessment -LinkedServicePrincipalIds @()
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @($app) -ServicePrincipalAssessments @() -CollectedAtUtc '2026-09-08T12:00:00Z'
        $snapshot.Collection.ApplicationCount | Should -Be 1
        $snapshot.Collection.OrphanApplicationCount | Should -Be 1
        $snapshot.Applications[0].IsOrphan | Should -BeTrue
        @($snapshot.Observations | Where-Object { $_.ObjectId -eq 'appobj1' -and $_.Category -eq 'ApplicationRegistration' }).Count | Should -Be 1
        @($snapshot.Observations | Where-Object { $_.ObjectId -eq 'appobj1' -and $_.Category -eq 'ApplicationCollectionState' }).Count | Should -Be 2
        (Test-AppExposureSnapshot -Snapshot $snapshot).Valid | Should -BeTrue
    }

    It 'fails validation when canonical evidence is tampered after snapshot creation' {
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @((New-TestApplicationAssessment)) -ServicePrincipalAssessments @((New-TestServicePrincipalAssessment)) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $snapshot.Observations[0].Fingerprint = 'tampered'
        $validation = Test-AppExposureSnapshot -Snapshot $snapshot
        $validation.Valid | Should -BeFalse
        ($validation.Errors -join ' ') | Should -Match 'fingerprint'
    }

    It 'fails validation when global completeness does not reconcile with per-object state' {
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @((New-TestApplicationAssessment -OwnerState 'Failed')) -ServicePrincipalAssessments @((New-TestServicePrincipalAssessment)) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $snapshot.Collection.CoreComplete = $true
        $snapshot.Collection.IncompleteObjectIds = @()
        $validation = Test-AppExposureSnapshot -Snapshot $snapshot
        $validation.Valid | Should -BeFalse
        ($validation.Errors -join ' ') | Should -Match 'CoreComplete|IncompleteObjectIds'
    }
}
}
