#Requires -Modules Pester
Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force

InModuleScope EntraAppExposure {
BeforeAll { $script:RulePack = Import-AppExposureRulePack -Path (Join-Path $script:EntraAppExposureRoot 'Rules\Baseline.json') }

Describe 'External rule baseline contract' {
    It 'loads a versioned self-describing baseline with unique EAE rule IDs' {
        $definitions = @($script:RulePack.Definitions)
        $definitions.Count | Should -BeGreaterOrEqual 25
        @($definitions.Id | Sort-Object -Unique).Count | Should -Be $definitions.Count
        foreach ($rule in $definitions) {
            [string]$rule.Id | Should -Match '^EAE-[A-Z]+(?:-[A-Z]+)*-[0-9]{3}$'
            @($rule.RequiredEvidence).Count | Should -BeGreaterThan 0
            $null -ne $rule.References | Should -BeTrue
        }
    }
}

Describe 'Deterministic findings without scoring' {
    It 'links sensitive permissions and missing ownership to exact evidence' {
        $appPerm = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appRoleAssignments'; Error=$null; Items=@(
            [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceAppId='00000003-0000-0000-c000-000000000000'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r1'; PermissionValue='Directory.ReadWrite.All' }
        ) }
        $empty = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/test'; Error=$null; Items=@() }
        $assessment = [PSCustomObject]@{
            ObjectId='sp1'; AppId='app1'; DisplayName='Sensitive App'; Classification='Local'; ServicePrincipalType='Application';
            AppOwnerOrganizationId='tenant1'; AccountEnabled=$true; CreatedDateTime='2026-01-01T00:00:00Z'; VerifiedPublisher=$null;
            AppRegistrationObjectId='appobj1'; ApplicationPermissions=$appPerm; DelegatedPermissions=$empty; Owners=$empty; Credentials=$empty;
            Activity=[PSCustomObject]@{ CollectionState='Skipped'; SourceUri=$null; LookbackDays=30; LastSignInDateTime=$null; NoActivityObserved=$false }
        }
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @($assessment) -CollectedAtUtc '2026-09-08T12:00:00Z'
        $findings = @(Invoke-AppExposureRules -Snapshot $snapshot -RulePack $script:RulePack)

        @($findings | Where-Object RuleId -eq 'EAE-OAUTH-APP-001').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-SP-OWNER-001').Count | Should -Be 1
        @($findings | Where-Object { $_.PSObject.Properties['Score'] }).Count | Should -Be 0
        ($findings | Where-Object RuleId -eq 'EAE-OAUTH-APP-001').EvidenceIds.Count | Should -BeGreaterThan 0
        $observationIds = @($snapshot.Observations | Select-Object -ExpandProperty ObservationId)
        foreach ($finding in $findings) {
            foreach ($evidenceId in @($finding.EvidenceIds)) { $observationIds | Should -Contain $evidenceId }
        }
    }

    It 'evaluates orphan application ownership and credentials from first-class application evidence' {
        $owners = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appowners'; Error=$null; Items=@() }
        $credentials = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appcredentials'; Error=$null; Items=@(
            [PSCustomObject]@{ CredentialType='Secret'; KeyId='k1'; DisplayName='old'; StartDateTime='2025-01-01T00:00:00Z'; EndDateTime='2027-01-01T00:00:00Z' }
        ) }
        $app = [PSCustomObject]@{
            ObjectId='appobj1'; AppId='app1'; DisplayName='Orphan App'; CreatedDateTime='2025-01-01T00:00:00Z'; SignInAudience='AzureADMyOrg'; PublisherDomain='contoso.test'; VerifiedPublisher=$null;
            LinkedServicePrincipalIds=@(); Owners=$owners; Credentials=$credentials
        }
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @($app) -ServicePrincipalAssessments @() -CollectedAtUtc '2026-09-08T12:00:00Z'
        $findings = @(Invoke-AppExposureRules -Snapshot $snapshot -RulePack $script:RulePack)
        @($findings | Where-Object RuleId -eq 'EAE-APP-OWNER-001').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-APP-CRED-003').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-APP-ORPHAN-001').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-EXPOSURE-006').Count | Should -Be 1
        $observationIds = @($snapshot.Observations | Select-Object -ExpandProperty ObservationId)
        foreach ($finding in $findings) { foreach ($evidenceId in @($finding.EvidenceIds)) { $observationIds | Should -Contain $evidenceId } }
    }
}

Describe 'Application OAuth and authentication exposure rules' {
    It 'flags unsafe browser redirects, implicit issuance, fallback public-client behavior, and pre-authorized API clients' {
        $owners = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appowners'; Error=$null; Items=@([PSCustomObject]@{ OwnerId='u1'; DisplayName='Owner'; UserType='Member'; AccountEnabled=$true }) }
        $credentials = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appcredentials'; Error=$null; Items=@() }
        $app = [PSCustomObject]@{
            ObjectId='app-platform'; AppId='app-platform-id'; DisplayName='Platform App'; CreatedDateTime='2025-01-01T00:00:00Z'; SignInAudience='AzureADMyOrg'; PublisherDomain='contoso.test'; VerifiedPublisher=$null;
            LinkedServicePrincipalIds=@(); Owners=$owners; Credentials=$credentials;
            Authentication=[PSCustomObject]@{
                IsFallbackPublicClient=$true;
                PublicClientRedirectUris=@('http://localhost:8400');
                SpaRedirectUris=@('http://spa.contoso.test/callback');
                WebRedirectUris=@('https://app.contoso.test/callback');
                WebImplicitAccessTokenIssuanceEnabled=$true;
                WebImplicitIdTokenIssuanceEnabled=$false
            };
            ApiConfiguration=[PSCustomObject]@{
                PreAuthorizedApplications=@([PSCustomObject]@{ AppId='trusted-client'; DelegatedPermissionIds=@('scope1') });
                Oauth2PermissionScopes=@([PSCustomObject]@{ Id='scope1'; Value='access_as_user'; IsEnabled=$true });
                AppRoles=@(); IdentifierUris=@('api://app-platform-id'); OptionalClaims=$null
            }
        }
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @($app) -ServicePrincipalAssessments @() -CollectedAtUtc '2026-09-17T12:00:00Z'
        $findings = @(Invoke-AppExposureRules -Snapshot $snapshot -RulePack $script:RulePack)
        @($findings | Where-Object RuleId -eq 'EAE-APP-AUTH-001').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-APP-AUTH-002').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-APP-AUTH-003').Count | Should -Be 1
        @($findings | Where-Object RuleId -eq 'EAE-APP-API-001').Count | Should -Be 1
        ($findings | Where-Object RuleId -eq 'EAE-APP-AUTH-001').EvidenceSummary | Should -Contain 'http://spa.contoso.test/callback'
        ($findings | Where-Object RuleId -eq 'EAE-APP-AUTH-001').EvidenceSummary | Should -Not -Contain 'http://localhost:8400'
    }

    It 'treats HTTP loopback redirect URIs as development exceptions rather than unsafe browser redirects' {
        @(Get-AppExposureUnsafeBrowserRedirectUris -Authentication ([PSCustomObject]@{ WebRedirectUris=@('http://localhost:5000/callback','http://127.0.0.1:5001/callback'); SpaRedirectUris=@() })).Count | Should -Be 0
    }
}

Describe 'Rule precision and noise controls' {
    It 'qualifies sensitive permission matching by resource application ID' {
        $graphObservation = [PSCustomObject]@{ Value=[PSCustomObject]@{ ResourceAppId='00000003-0000-0000-c000-000000000000'; PermissionValue='Directory.ReadWrite.All' } }
        $otherObservation = [PSCustomObject]@{ Value=[PSCustomObject]@{ ResourceAppId='11111111-1111-1111-1111-111111111111'; PermissionValue='Directory.ReadWrite.All' } }
        $watchlist = @($script:RulePack.Policy.SensitiveApplicationPermissions)
        (Test-AppExposureSensitivePermissionObservation -Observation $graphObservation -Watchlist $watchlist) | Should -BeTrue
        (Test-AppExposureSensitivePermissionObservation -Observation $otherObservation -Watchlist $watchlist) | Should -BeFalse
    }

    It 'limits inactivity review candidates to mature non-Microsoft application identities' {
        $reference = [datetime]'2026-09-17T12:00:00Z'
        $activity = [PSCustomObject]@{ LookbackDays=90 }
        $policy = $script:RulePack.Policy.Activity
        $eligible = [PSCustomObject]@{ Classification='Local'; ServicePrincipalType='Application'; CreatedDateTime='2026-01-01T00:00:00Z' }
        $firstParty = [PSCustomObject]@{ Classification='MicrosoftFirstParty'; ServicePrincipalType='Application'; CreatedDateTime='2026-01-01T00:00:00Z' }
        $managedIdentity = [PSCustomObject]@{ Classification='Local'; ServicePrincipalType='ManagedIdentity'; CreatedDateTime='2026-01-01T00:00:00Z' }
        $newIdentity = [PSCustomObject]@{ Classification='Local'; ServicePrincipalType='Application'; CreatedDateTime='2026-09-01T00:00:00Z' }

        (Test-AppExposureActivityReviewCandidate -ServicePrincipal $eligible -ActivityValue $activity -ActivityPolicy $policy -ReferenceDate $reference) | Should -BeTrue
        (Test-AppExposureActivityReviewCandidate -ServicePrincipal $firstParty -ActivityValue $activity -ActivityPolicy $policy -ReferenceDate $reference) | Should -BeFalse
        (Test-AppExposureActivityReviewCandidate -ServicePrincipal $managedIdentity -ActivityValue $activity -ActivityPolicy $policy -ReferenceDate $reference) | Should -BeFalse
        (Test-AppExposureActivityReviewCandidate -ServicePrincipal $newIdentity -ActivityValue $activity -ActivityPolicy $policy -ReferenceDate $reference) | Should -BeFalse
    }

    It 'can exclude Microsoft first-party service principals from finding evaluation without removing snapshot evidence' {
        $appPerm = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/appRoleAssignments'; Error=$null; Items=@(
            [PSCustomObject]@{ AssignmentId='a1'; ResourceId='graph'; ResourceAppId='00000003-0000-0000-c000-000000000000'; ResourceDisplayName='Microsoft Graph'; AppRoleId='r1'; PermissionValue='Directory.ReadWrite.All' }
        ) }
        $empty = [PSCustomObject]@{ CollectionState='Complete'; SourceUri='https://graph/test'; Error=$null; Items=@() }
        $assessment = [PSCustomObject]@{
            ObjectId='sp-ms'; AppId='app-ms'; DisplayName='Microsoft-managed SP'; Classification='MicrosoftFirstParty'; ServicePrincipalType='Application';
            AppOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'; AccountEnabled=$true; CreatedDateTime='2025-01-01T00:00:00Z'; VerifiedPublisher=$null;
            AppRegistrationObjectId=$null; ApplicationPermissions=$appPerm; DelegatedPermissions=$empty;
            Owners=[PSCustomObject]@{ CollectionState='NotApplicable'; SourceUri=$null; Error=$null; Items=@() };
            Credentials=[PSCustomObject]@{ CollectionState='NotApplicable'; SourceUri=$null; Error=$null; Items=@() };
            Activity=[PSCustomObject]@{ CollectionState='Skipped'; SourceKind='NotCollected'; SourceUri=$null; LookbackDays=90; LastSignInDateTime=$null; NoActivityObserved=$false }
        }
        $snapshot = New-AppExposureSnapshot -TenantId 'tenant1' -Scope All -Applications @() -ServicePrincipalAssessments @($assessment) -CollectedAtUtc '2026-09-17T12:00:00Z'
        @($snapshot.ServicePrincipals | Where-Object ObjectId -eq 'sp-ms').Count | Should -Be 1
        @((Invoke-AppExposureRules -Snapshot $snapshot -RulePack $script:RulePack) | Where-Object ObjectId -eq 'sp-ms').Count | Should -BeGreaterThan 0
        @((Invoke-AppExposureRules -Snapshot $snapshot -RulePack $script:RulePack -ExcludeMicrosoftFirstParty) | Where-Object ObjectId -eq 'sp-ms').Count | Should -Be 0
    }
}

}
