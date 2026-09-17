#Requires -Modules Pester
BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force }

InModuleScope EntraAppExposure {
Describe 'App-only client-secret authentication contract' {
    It 'exposes only config and SecretStore selectors for live connection' {
        $parameters = (Get-Command Connect-AppExposureGraph).Parameters.Keys
        $parameters | Should -Contain 'ConfigPath'
        $parameters | Should -Contain 'SecretVault'
        $parameters | Should -Contain 'SecretName'
        $parameters | Should -Not -Contain 'AuthMode'
        $parameters | Should -Not -Contain 'TenantId'
        $parameters | Should -Not -Contain 'ClientId'
        $parameters | Should -Not -Contain 'ClientSecret'
        $parameters | Should -Not -Contain 'CertificatePath'
        $parameters | Should -Not -Contain 'CertificatePassword'
        $parameters | Should -Not -Contain 'Interactive'
    }

    It 'rejects a missing config file before authentication' {
        $missing = Join-Path $TestDrive 'missing-config.json'
        { Get-AppExposureAuthConfiguration -ConfigPath $missing } | Should -Throw '*configuration was not found*'
    }

    It 'requires TenantId and ClientId GUIDs in config' {
        $path = Join-Path $TestDrive 'bad-config.json'
        @{ TenantId = 'not-a-guid'; ClientId = 'also-not-a-guid' } | ConvertTo-Json | Set-Content -LiteralPath $path
        { Get-AppExposureAuthConfiguration -ConfigPath $path } | Should -Throw '*must be a GUID*'
    }

    It 'stores a validated application token without exposing raw token input' {
        Mock -CommandName Assert-AppExposureModuleDependency -ModuleName EntraAppExposure -MockWith { [PSCustomObject]@{ Name = $Name; Version = $MinimumVersion } }
        Mock -CommandName Get-AppExposureAuthConfiguration -ModuleName EntraAppExposure -MockWith {
            [PSCustomObject]@{
                TenantId   = '11111111-1111-1111-1111-111111111111'
                ClientId   = '22222222-2222-2222-2222-222222222222'
                ConfigPath = 'config.json'
            }
        }
        Mock -CommandName Get-AppExposureStoredClientSecret -ModuleName EntraAppExposure -MockWith {
            ConvertTo-SecureString -String 'client-secret-value' -AsPlainText -Force
        }
        Mock -CommandName Request-AppExposureClientCredentialToken -ModuleName EntraAppExposure -MockWith {
            [PSCustomObject]@{ access_token = 'application-token'; expires_in = 3600 }
        }

        $result = Connect-AppExposureGraph

        $result.AuthType | Should -Be 'AppOnly'
        $result.Scopes | Should -Contain 'https://graph.microsoft.com/.default'
        Should -Invoke -CommandName Request-AppExposureClientCredentialToken -ModuleName EntraAppExposure -Times 1
    }

    It 'keeps identity-platform guidance when the client credential token request fails' {
        Mock -CommandName Assert-AppExposureModuleDependency -ModuleName EntraAppExposure -MockWith { [PSCustomObject]@{ Name = $Name; Version = $MinimumVersion } }
        Mock -CommandName Get-AppExposureAuthConfiguration -ModuleName EntraAppExposure -MockWith {
            [PSCustomObject]@{
                TenantId   = '11111111-1111-1111-1111-111111111111'
                ClientId   = '22222222-2222-2222-2222-222222222222'
                ConfigPath = 'config.json'
            }
        }
        Mock -CommandName Get-AppExposureStoredClientSecret -ModuleName EntraAppExposure -MockWith {
            ConvertTo-SecureString -String 'client-secret-value' -AsPlainText -Force
        }
        Mock -CommandName Request-AppExposureClientCredentialToken -ModuleName EntraAppExposure -MockWith {
            throw 'AADSTS7000215: Invalid client secret is provided.'
        }

        { Connect-AppExposureGraph } | Should -Throw '*client secret VALUE*'
    }
}

Describe 'Read-only Graph request boundary' {
    BeforeEach { Reset-AppExposureGraphTelemetry }

    It 'does not accept raw access tokens or write methods' {
        foreach ($commandName in @('Invoke-AppExposureGraphRequest','Invoke-AppExposureGraphBatchRequest')) {
            $parameters = (Get-Command $commandName).Parameters.Keys
            $parameters | Should -Not -Contain 'Token'
            $parameters | Should -Not -Contain 'AccessToken'
            $parameters | Should -Not -Contain 'Method'
            $parameters | Should -Not -Contain 'Body'
        }
    }

    It 'batches independent GET requests and records physical versus logical telemetry' {
        Mock -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -MockWith {
            param($ApiVersion, $Body)
            return [PSCustomObject]@{
                responses = @(
                    $Body.requests | ForEach-Object {
                        [PSCustomObject]@{
                            id = [string]$_.id
                            status = 200
                            headers = @{}
                            body = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = ('item-' + [string]$_.id) }) }
                        }
                    }
                )
            }
        }

        $requests = @(
            [PSCustomObject]@{ Id='one'; Uri='https://graph.microsoft.com/v1.0/servicePrincipals/one/owners' },
            [PSCustomObject]@{ Id='two'; Uri='https://graph.microsoft.com/v1.0/servicePrincipals/two/owners' }
        )
        $result = @(Invoke-AppExposureGraphBatchRequest -Requests $requests -ApiVersion v1.0)
        $result.Count | Should -Be 2
        @($result | Where-Object CollectionState -eq 'Complete').Count | Should -Be 2
        $telemetry = Get-AppExposureGraphTelemetry
        $telemetry.Requests | Should -Be 1
        $telemetry.BatchRequests | Should -Be 1
        $telemetry.BatchSubRequests | Should -Be 2
        $telemetry.Pages | Should -Be 2
        Should -Invoke -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -Times 1
    }

    It 'chunks more than 20 batch subrequests without dropping responses' {
        Mock -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -MockWith {
            param($ApiVersion, $Body)
            return [PSCustomObject]@{
                responses = @($Body.requests | ForEach-Object {
                    [PSCustomObject]@{ id=[string]$_.id; status=200; headers=@{}; body=[PSCustomObject]@{ value=@() } }
                })
            }
        }

        $requests = @(1..21 | ForEach-Object {
            [PSCustomObject]@{ Id=('r' + $_); Uri=('https://graph.microsoft.com/v1.0/servicePrincipals/sp' + $_ + '/owners') }
        })
        $result = @(Invoke-AppExposureGraphBatchRequest -Requests $requests)
        $result.Count | Should -Be 21
        @($result | Where-Object CollectionState -eq 'Complete').Count | Should -Be 21
        $telemetry = Get-AppExposureGraphTelemetry
        $telemetry.BatchRequests | Should -Be 2
        $telemetry.BatchSubRequests | Should -Be 21
        Should -Invoke -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -Times 2
    }

    It 'follows @odata.nextLink inside a batched subrequest' {
        $global:AppExposureBatchPageAttempt = 0
        Mock -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -MockWith {
            param($ApiVersion, $Body)
            $global:AppExposureBatchPageAttempt++
            if ($global:AppExposureBatchPageAttempt -eq 1) {
                return [PSCustomObject]@{ responses=@([PSCustomObject]@{
                    id='paged'; status=200; headers=@{}; body=[PSCustomObject]@{
                        value=@([PSCustomObject]@{ id='first' })
                        '@odata.nextLink'='https://graph.microsoft.com/v1.0/servicePrincipals/paged/owners?page=2'
                    }
                }) }
            }
            return [PSCustomObject]@{ responses=@([PSCustomObject]@{
                id='paged'; status=200; headers=@{}; body=[PSCustomObject]@{ value=@([PSCustomObject]@{ id='second' }) }
            }) }
        }

        $result = @(Invoke-AppExposureGraphBatchRequest -Requests @([PSCustomObject]@{
            Id='paged'; Uri='https://graph.microsoft.com/v1.0/servicePrincipals/paged/owners'
        }))
        $result.Count | Should -Be 1
        @($result[0].Items).Count | Should -Be 2
        $result[0].Items[0].id | Should -Be 'first'
        $result[0].Items[1].id | Should -Be 'second'
        (Get-AppExposureGraphTelemetry).Pages | Should -Be 2
        Should -Invoke -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -Times 2
    }

    It 'retries a transient batch subresponse without failing the logical collection' {
        $global:AppExposureBatchRetryAttempt = 0
        Mock -CommandName Start-Sleep -ModuleName EntraAppExposure -MockWith { }
        Mock -CommandName Invoke-AppExposureHttpBatchRequest -ModuleName EntraAppExposure -MockWith {
            param($ApiVersion, $Body)
            $global:AppExposureBatchRetryAttempt++
            if ($global:AppExposureBatchRetryAttempt -eq 1) {
                return [PSCustomObject]@{ responses=@([PSCustomObject]@{
                    id='retry'; status=503; headers=@{ 'Retry-After'='1' }; body=[PSCustomObject]@{ error=[PSCustomObject]@{ message='Busy' } }
                }) }
            }
            return [PSCustomObject]@{ responses=@([PSCustomObject]@{
                id='retry'; status=200; headers=@{}; body=[PSCustomObject]@{ value=@([PSCustomObject]@{ id='ok' }) }
            }) }
        }

        $result = @(Invoke-AppExposureGraphBatchRequest -Requests @([PSCustomObject]@{
            Id='retry'; Uri='https://graph.microsoft.com/v1.0/servicePrincipals/retry/owners'
        }) -MaxRetryCount 2)
        $result[0].CollectionState | Should -Be 'Complete'
        $result[0].Items[0].id | Should -Be 'ok'
        $telemetry = Get-AppExposureGraphTelemetry
        $telemetry.Retries | Should -Be 1
        $telemetry.ServiceUnavailable | Should -Be 1
        $telemetry.BatchRequests | Should -Be 2
    }

    It 'follows @odata.nextLink and combines pages' {
        Mock -CommandName Invoke-AppExposureHttpRequest -ModuleName EntraAppExposure -MockWith {
            if ($Uri -like '*page=2') { return [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'sp3' }) } }
            return [PSCustomObject]@{
                value = @([PSCustomObject]@{ id = 'sp1' }, [PSCustomObject]@{ id = 'sp2' })
                '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals?page=2'
            }
        }

        $result = Invoke-AppExposureGraphRequest -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals'
        $result.Count | Should -Be 3
        (Get-AppExposureGraphTelemetry).Pages | Should -Be 2
        Should -Invoke -CommandName Invoke-AppExposureHttpRequest -ModuleName EntraAppExposure -Times 2
    }

    It 'wraps a single-object response' {
        Mock -CommandName Invoke-AppExposureHttpRequest -ModuleName EntraAppExposure -MockWith { [PSCustomObject]@{ id = 'one'; displayName = 'One' } }
        $result = @(Invoke-AppExposureGraphRequest -Uri 'https://graph.microsoft.com/v1.0/applications/one')
        $result.Count | Should -Be 1
        $result[0].id | Should -Be 'one'
    }

    It 'retries a transient 503 and records telemetry' {
        $global:AppExposureAuthTestAttempt = 0
        Mock -CommandName Start-Sleep -ModuleName EntraAppExposure -MockWith { }
        Mock -CommandName Invoke-AppExposureHttpRequest -ModuleName EntraAppExposure -MockWith {
            $global:AppExposureAuthTestAttempt++
            if ($global:AppExposureAuthTestAttempt -eq 1) {
                $ex = New-Object System.Exception('Service unavailable')
                $response = [PSCustomObject]@{ StatusCode = 503; Headers = @{} }
                Add-Member -InputObject $ex -MemberType NoteProperty -Name Response -Value $response
                throw $ex
            }
            return [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'ok' }) }
        }

        $result = @(Invoke-AppExposureGraphRequest -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -MaxRetryCount 2)
        $result[0].id | Should -Be 'ok'
        $telemetry = Get-AppExposureGraphTelemetry
        $telemetry.Retries | Should -Be 1
        $telemetry.ServiceUnavailable | Should -Be 1
    }
}
}
