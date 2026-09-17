#Requires -Modules Pester
BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force }

InModuleScope EntraAppExposure {
Describe 'Service principal classification' {
    It 'classifies the Microsoft services tenant as MicrosoftFirstParty' {
        Get-AppExposureSPClassification -AppOwnerOrganizationId 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -ScanningTenantId 'tenant-a' | Should -Be 'MicrosoftFirstParty'
    }
    It 'classifies a tenant-local service principal as Local' {
        Get-AppExposureSPClassification -AppOwnerOrganizationId 'tenant-a' -ScanningTenantId 'tenant-a' | Should -Be 'Local'
    }
    It 'classifies another tenant as ThirdParty' {
        Get-AppExposureSPClassification -AppOwnerOrganizationId 'tenant-b' -ScanningTenantId 'tenant-a' | Should -Be 'ThirdParty'
    }
}

Describe 'Graph transport context contract' {
    It 'Get-AppExposureOrganizationName does not accept a raw access token' {
        $parameters = (Get-Command 'Get-AppExposureOrganizationName').Parameters.Keys
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureApplications does not accept a raw access token' {
        $parameters = (Get-Command 'Get-AppExposureApplications').Parameters.Keys
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureServicePrincipals does not accept a raw access token' {
        $parameters = (Get-Command 'Get-AppExposureServicePrincipals').Parameters.Keys
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Find-AppExposureServicePrincipal does not accept a raw access token' {
        $parameters = (Get-Command 'Find-AppExposureServicePrincipal').Parameters.Keys
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }
}


Describe 'Tenant inventory reuse contract' {
    It 'collects application credential metadata and service-principal app roles in the discovery inventory' {
        $text = Get-Content -LiteralPath (Join-Path $script:EntraAppExposureRoot 'Private\Collection.ps1') -Raw
        $text | Should -Match 'keyCredentials,passwordCredentials'
        $text | Should -Match 'appRoles'
        $text | Should -Match 'KeyCredentials'
        $text | Should -Match 'PasswordCredentials'
        $text | Should -Match 'AppRoles'
    }
}

Describe 'Application registration OAuth and authentication evidence' {
    It 'normalizes platform, exposed API, app-role, and token configuration from the application object' {
        $raw = [PSCustomObject]@{
            id='appobj1'; appId='app1'; displayName='Example App'; createdDateTime='2026-01-01T00:00:00Z'; signInAudience='AzureADMyOrg';
            publisherDomain='contoso.test'; verifiedPublisher=$null; isFallbackPublicClient=$true;
            publicClient=[PSCustomObject]@{ redirectUris=@('http://localhost:8400') };
            spa=[PSCustomObject]@{ redirectUris=@('https://spa.contoso.test/callback') };
            web=[PSCustomObject]@{ redirectUris=@('https://app.contoso.test/callback'); implicitGrantSettings=[PSCustomObject]@{ enableAccessTokenIssuance=$true; enableIdTokenIssuance=$false } };
            api=[PSCustomObject]@{
                acceptMappedClaims=$false; requestedAccessTokenVersion=2; knownClientApplications=@('client-known');
                oauth2PermissionScopes=@([PSCustomObject]@{ id='scope1'; value='access_as_user'; type='User'; isEnabled=$true; adminConsentDisplayName='Access'; userConsentDisplayName='Access' });
                preAuthorizedApplications=@([PSCustomObject]@{ appId='client-preauth'; delegatedPermissionIds=@('scope1') })
            };
            appRoles=@([PSCustomObject]@{ id='role1'; value='Reader'; displayName='Reader'; description='Read'; isEnabled=$true; allowedMemberTypes=@('Application') });
            identifierUris=@('api://app1'); optionalClaims=[PSCustomObject]@{ idToken=@([PSCustomObject]@{ name='email' }) };
            keyCredentials=@(); passwordCredentials=@()
        }
        $result = ConvertTo-AppExposureApplicationRecord -Application $raw -SourceUri 'https://graph.microsoft.com/v1.0/applications'
        $result.SignInAudience | Should -Be 'AzureADMyOrg'
        $result.Authentication.IsFallbackPublicClient | Should -BeTrue
        $result.Authentication.WebImplicitAccessTokenIssuanceEnabled | Should -BeTrue
        $result.Authentication.WebRedirectUris | Should -Contain 'https://app.contoso.test/callback'
        $result.Authentication.SpaRedirectUris | Should -Contain 'https://spa.contoso.test/callback'
        $result.Authentication.PublicClientRedirectUris | Should -Contain 'http://localhost:8400'
        @($result.ApiConfiguration.Oauth2PermissionScopes).Count | Should -Be 1
        @($result.ApiConfiguration.PreAuthorizedApplications).Count | Should -Be 1
        @($result.ApiConfiguration.AppRoles).Count | Should -Be 1
        $result.ApiConfiguration.IdentifierUris | Should -Contain 'api://app1'
        $null -ne $result.ApiConfiguration.OptionalClaims | Should -BeTrue
    }
}

Describe 'Collection-only permission module contract' {
    It 'Get-AppExposurePermissions has no database or raw access-token parameter' {
        $parameters = (Get-Command 'Get-AppExposurePermissions').Parameters.Keys
        $parameters | Should -Not -Contain 'DatabasePath'
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureDelegatedPermissions has no database or raw access-token parameter' {
        $parameters = (Get-Command 'Get-AppExposureDelegatedPermissions').Parameters.Keys
        $parameters | Should -Not -Contain 'DatabasePath'
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureOwners has no database or raw access-token parameter' {
        $parameters = (Get-Command 'Get-AppExposureOwners').Parameters.Keys
        $parameters | Should -Not -Contain 'DatabasePath'
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureCredentials has no database or raw access-token parameter' {
        $parameters = (Get-Command 'Get-AppExposureCredentials').Parameters.Keys
        $parameters | Should -Not -Contain 'DatabasePath'
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'Get-AppExposureApplicationOwners has no database or raw access-token parameter' {
        $parameters = (Get-Command 'Get-AppExposureApplicationOwners').Parameters.Keys
        $parameters | Should -Not -Contain 'DatabasePath'
        $parameters | Should -Not -Contain 'AccessToken'
        $parameters | Should -Not -Contain 'Token'
    }

    It 'bulk collectors remain read-only and token-free' {
        foreach ($commandName in @(
            'Get-AppExposurePermissionsBulk',
            'Get-AppExposureDelegatedPermissionsBulk',
            'Get-AppExposureOwnersBulk',
            'Get-AppExposureApplicationOwnersBulk',
            'Get-AppExposureCredentialsFromApplication'
        )) {
            $parameters = (Get-Command $commandName).Parameters.Keys
            $parameters | Should -Not -Contain 'AccessToken'
            $parameters | Should -Not -Contain 'Token'
            $parameters | Should -Not -Contain 'Method'
            $parameters | Should -Not -Contain 'Body'
        }
    }

    It 'can build credential evidence from the already collected application inventory' {
        $app = [PSCustomObject]@{
            ObjectId='app1'; CollectionSourceUri='https://graph.microsoft.com/v1.0/applications'
            KeyCredentials=@([PSCustomObject]@{ keyId='cert1'; displayName='cert'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2027-01-01T00:00:00Z' })
            PasswordCredentials=@([PSCustomObject]@{ keyId='secret1'; displayName='secret'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2026-12-01T00:00:00Z' })
        }
        $result = Get-AppExposureCredentialsFromApplication -Application $app
        $result.CollectionState | Should -Be 'Complete'
        @($result.Items).Count | Should -Be 2
        @($result.Items | Where-Object CredentialType -eq 'Certificate').Count | Should -Be 1
        @($result.Items | Where-Object CredentialType -eq 'Secret').Count | Should -Be 1
    }

    It 'qualifies delegated permissions with the resource application ID and fails closed when it cannot be resolved' {
        $resourceIndex = @{
            'resource-sp' = [PSCustomObject]@{
                AppId='00000003-0000-0000-c000-000000000000'
                DisplayName='Microsoft Graph'
                RoleMap=@{}
            }
        }
        $grants = @(
            [PSCustomObject]@{ id='g1'; resourceId='resource-sp'; consentType='AllPrincipals'; principalId=$null; scope='Mail.Send Directory.ReadWrite.All' }
        )
        $result = ConvertTo-AppExposureDelegatedPermissionResult -Grants $grants -SourceUri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -ResourceIndex $resourceIndex -FallbackCache @{}
        $result.CollectionState | Should -Be 'Complete'
        @($result.Items).Count | Should -Be 2
        @($result.Items | Where-Object ResourceAppId -eq '00000003-0000-0000-c000-000000000000').Count | Should -Be 2

        $unresolved = ConvertTo-AppExposureDelegatedPermissionResult -Grants @([PSCustomObject]@{ id='g2'; resourceId=$null; consentType='AllPrincipals'; principalId=$null; scope='Mail.Send' }) -SourceUri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -ResourceIndex @{} -FallbackCache @{}
        $unresolved.CollectionState | Should -Be 'Partial'
        @($unresolved.Items)[0].ResolutionState | Should -Be 'Unresolved'
    }

}

Describe 'Optional activity collection contract' {
    It 'does not accept a raw access token' {
        foreach ($commandName in @('Get-AppExposureLastSignIn','Get-AppExposureLastSignInBulk')) {
            $parameters = (Get-Command $commandName).Parameters.Keys
            $parameters | Should -Not -Contain 'AccessToken'
            $parameters | Should -Not -Contain 'Token'
        }
    }
}

Describe 'Service-principal activity report normalization' {
    It 'keeps recent activity and normalizes it to UTC ISO-8601' {
        $date = [datetimeoffset]::UtcNow.AddDays(-1)
        $row = [PSCustomObject]@{
            lastSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.ToString('o') }
            applicationAuthenticationClientSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.AddHours(-1).ToString('o') }
            applicationAuthenticationResourceSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.AddHours(-2).ToString('o') }
            delegatedClientSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.AddHours(-3).ToString('o') }
            delegatedResourceSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.AddHours(-4).ToString('o') }
        }
        $result = ConvertTo-AppExposureActivityReportResult -SourceUri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -LookbackDays 90 -Row $row
        $result.CollectionState | Should -Be 'Complete'
        $result.SourceKind | Should -Be 'ServicePrincipalSignInActivities'
        ([datetimeoffset]::Parse($result.LastSignInDateTime)).UtcDateTime | Should -Be $date.UtcDateTime
        $result.ApplicationAuthenticationClientLastSignInDateTime | Should -Not -BeNullOrEmpty
        $result.ApplicationAuthenticationResourceLastSignInDateTime | Should -Not -BeNullOrEmpty
        $result.DelegatedClientLastSignInDateTime | Should -Not -BeNullOrEmpty
        $result.DelegatedResourceLastSignInDateTime | Should -Not -BeNullOrEmpty
        $result.NoActivityObserved | Should -BeFalse
    }

    It 'preserves older source evidence while marking no activity inside the lookback window' {
        $date = [datetimeoffset]::UtcNow.AddDays(-120)
        $row = [PSCustomObject]@{ lastSignInActivity=[PSCustomObject]@{ lastSignInDateTime=$date.ToString('o') } }
        $result = ConvertTo-AppExposureActivityReportResult -SourceUri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -LookbackDays 90 -Row $row
        $result.CollectionState | Should -Be 'Complete'
        ([datetimeoffset]::Parse($result.LastSignInDateTime)).UtcDateTime | Should -Be $date.UtcDateTime
        $result.NoActivityObserved | Should -BeTrue
    }

    It 'fails closed when the activity report returns an invalid timestamp' {
        $row = [PSCustomObject]@{ lastSignInActivity=[PSCustomObject]@{ lastSignInDateTime='not-a-date' } }
        $result = ConvertTo-AppExposureActivityReportResult -SourceUri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -LookbackDays 90 -Row $row
        $result.CollectionState | Should -Be 'Failed'
        $result.NoActivityObserved | Should -BeFalse
        $result.Error | Should -Match 'invalid.*timestamp|invalid lastSignInDateTime'
    }
}
}
