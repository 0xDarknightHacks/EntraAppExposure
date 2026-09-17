<#
.SYNOPSIS
    App-only authentication and local credential configuration.
.DESCRIPTION
    Authentication is intentionally separate from Microsoft Graph transport.
    Raw Graph API requests live only under Private/Graph.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefaultConfigDirectory = Join-Path $HOME '.entra-app-exposure'
$script:DefaultConfigPath = Join-Path $script:DefaultConfigDirectory 'config.json'
$script:DefaultSecretVault = 'AppExposureVault'
$script:DefaultSecretName = 'AppExposureGraphClientSecret'

function Get-AppExposureDefaultConfigPath {
    [CmdletBinding()]
    param()
    if (Test-Path -LiteralPath $script:DefaultConfigPath -PathType Leaf) { return $script:DefaultConfigPath }
    return $script:DefaultConfigPath
}

function Assert-AppExposureModuleDependency {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][version]$MinimumVersion,
        [Parameter(Mandatory = $false)][switch]$Import
    )

    $module = Get-Module -ListAvailable -Name $Name |
        Where-Object { $_.Version -ge $MinimumVersion } |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $module) {
        throw "Required module '$Name' version $MinimumVersion or later is not installed."
    }

    if ($Import) {
        Import-Module $Name -MinimumVersion $MinimumVersion -ErrorAction Stop
    }

    return $module
}

function Get-AppExposureAuthConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath = (Get-AppExposureDefaultConfigPath)
    )

    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Entra App Exposure configuration was not found at '$ConfigPath'."
    }

    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Entra App Exposure configuration at '$ConfigPath' is not valid JSON: $($_.Exception.Message)"
    }

    foreach ($name in @('TenantId', 'ClientId')) {
        $prop = $config.PSObject.Properties[$name]
        if (-not $prop -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            throw "Entra App Exposure configuration at '$ConfigPath' must contain '$name'."
        }

        $parsedGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$prop.Value, [ref]$parsedGuid)) {
            throw "Entra App Exposure configuration value '$name' must be a GUID."
        }
    }

    return [PSCustomObject]@{
        TenantId   = [string]$config.TenantId
        ClientId   = [string]$config.ClientId
        ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
    }
}

function Get-AppExposureStoredClientSecret {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'SecretManagement can return a string from the vault; convert that retrieved value to SecureString without logging or persisting it.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$SecretName
    )

    Assert-AppExposureModuleDependency -Name 'Microsoft.PowerShell.SecretManagement' -MinimumVersion ([version]'1.1.2') -Import | Out-Null
    Assert-AppExposureModuleDependency -Name 'Microsoft.PowerShell.SecretStore' -MinimumVersion ([version]'1.0.6') | Out-Null

    try {
        $vault = Get-SecretVault -Name $VaultName -ErrorAction Stop
    }
    catch {
        throw "Secret vault '$VaultName' is not registered. Register it with Microsoft.PowerShell.SecretStore before running a live assessment."
    }

    if (-not $vault) {
        throw "Secret vault '$VaultName' is not registered."
    }

    try {
        $secret = Get-Secret -Name $SecretName -Vault $VaultName -ErrorAction Stop
    }
    catch {
        $message = [string]$_.Exception.Message
        if ($message -match '(?i)SecretStore.*(password|unlock)|valid password is required') {
            throw "Secret vault '$VaultName' is locked. Run Unlock-SecretStore, then retry the assessment."
        }
        throw "Could not retrieve client secret '$SecretName' from vault '$VaultName': $message"
    }

    if ($null -eq $secret) {
        throw "Client secret '$SecretName' was not found in vault '$VaultName'."
    }

    if ($secret -is [securestring]) {
        return $secret
    }

    if ($secret -is [string]) {
        return ConvertTo-SecureString -String $secret -AsPlainText -Force
    }

    throw "Secret '$SecretName' in vault '$VaultName' must be stored as a string or SecureString."
}

function Get-AppExposureExceptionDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    $messages = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $current = $Exception

    while ($null -ne $current) {
        $identity = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($current)
        if (-not $seen.Add($identity)) { break }

        $message = [string]$current.Message
        if (-not [string]::IsNullOrWhiteSpace($message)) {
            $trimmed = $message.Trim()
            if (-not $messages.Contains($trimmed)) { $messages.Add($trimmed) }
        }

        $current = $current.InnerException
    }

    if ($messages.Count -eq 0) { return $Exception.GetType().FullName }
    return ($messages -join ' --> ')
}

function Assert-AppExposureClientSecretShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [securestring]$SecureSecret,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [Parameter(Mandatory = $true)]
        [string]$VaultName
    )

    $credential = [pscredential]::new('secret-validation', $SecureSecret)
    $plainSecret = $null
    try {
        $plainSecret = $credential.GetNetworkCredential().Password
        if ([string]::IsNullOrWhiteSpace($plainSecret)) {
            throw "Client secret '$SecretName' in vault '$VaultName' is empty."
        }

        $secretId = [guid]::Empty
        if ([guid]::TryParse($plainSecret, [ref]$secretId)) {
            throw "Client secret '$SecretName' in vault '$VaultName' looks like a client secret ID (GUID), not the client secret VALUE. Store the secret Value shown once when the Entra client secret is created, then retry."
        }
    }
    finally {
        $plainSecret = $null
        Remove-Variable credential -ErrorAction SilentlyContinue
    }
}

function Request-AppExposureClientCredentialToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][securestring]$SecureSecret
    )

    $credential = [pscredential]::new($ClientId, $SecureSecret)
    $plainSecret = $null
    try {
        $plainSecret = $credential.GetNetworkCredential().Password
        $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            client_id     = $ClientId
            client_secret = $plainSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        }
        catch {
            $detail = Get-AppExposureExceptionDetail -Exception $_.Exception
            if ($_.ErrorDetails -and -not [string]::IsNullOrWhiteSpace([string]$_.ErrorDetails.Message)) {
                $errorDetails = [string]$_.ErrorDetails.Message
                try {
                    $parsed = $errorDetails | ConvertFrom-Json -ErrorAction Stop
                    if ($parsed.error_description) { $detail = [string]$parsed.error_description }
                    elseif ($parsed.error) { $detail = [string]$parsed.error }
                }
                catch {
                    if ($errorDetails -notmatch '^\s*<') { $detail = "$detail --> $errorDetails" }
                }
            }
            throw "Microsoft identity platform rejected the configured client credential: $detail"
        }

        if (-not $response -or [string]::IsNullOrWhiteSpace([string]$response.access_token)) {
            throw 'Microsoft identity platform token validation returned no access token.'
        }

        return $response
    }
    finally {
        $plainSecret = $null
        Remove-Variable credential -ErrorAction SilentlyContinue
    }
}

function Connect-AppExposureGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using the analyzer's only supported live
        authentication flow: app-only client-secret credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath = (Get-AppExposureDefaultConfigPath),

        [Parameter(Mandatory = $false)]
        [string]$SecretVault = $script:DefaultSecretVault,

        [Parameter(Mandatory = $false)]
        [string]$SecretName = $script:DefaultSecretName
    )

    $config = Get-AppExposureAuthConfiguration -ConfigPath $ConfigPath
    $secureSecret = Get-AppExposureStoredClientSecret -VaultName $SecretVault -SecretName $SecretName
    Assert-AppExposureClientSecretShape -SecureSecret $secureSecret -SecretName $SecretName -VaultName $SecretVault

    Write-Host '[Auth] Requesting Microsoft Graph application token with app-only client-secret authentication...' -ForegroundColor Cyan
    try {
        $tokenResponse = Request-AppExposureClientCredentialToken `
            -TenantId $config.TenantId `
            -ClientId $config.ClientId `
            -SecureSecret $secureSecret
    }
    catch {
        $detail = Get-AppExposureExceptionDetail -Exception $_.Exception
        $hint = $null

        if ($detail -match '(?i)AADSTS7000215|invalid client secret') {
            $hint = " Verify that SecretStore contains the client secret VALUE (not the Secret ID), and that the secret has not expired."
        }
        elseif ($detail -match '(?i)AADSTS700016|application.*not found|unauthorized_client') {
            $hint = " Verify that config.json contains the Application (client) ID of the app registration and the correct tenant ID."
        }
        elseif ($detail -match '(?i)AADSTS7000222|expired client secret|client secret.*expired') {
            $hint = " Create a new client secret in Entra ID and replace the stored SecretStore value."
        }
        elseif ($detail -match '(?i)AADSTS90002|tenant.*not found') {
            $hint = " Verify the configured TenantId."
        }
        else {
            $hint = " Verify TenantId, ClientId, the stored client secret VALUE, secret validity, and outbound access to login.microsoftonline.com. Graph API permissions are evaluated only after token acquisition succeeds."
        }

        throw "Microsoft Graph app-only authentication failed. $detail$hint"
    }

    if (-not $tokenResponse -or [string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
        throw 'Microsoft identity platform token validation returned no access token.'
    }

    $script:GraphApplicationAccessToken = [string]$tokenResponse.access_token
    Write-Host "[Auth] Validated app-only application token for tenant $($config.TenantId)." -ForegroundColor Green
    return [PSCustomObject]@{
        TenantId    = $config.TenantId
        ClientId    = $config.ClientId
        AuthType    = 'AppOnly'
        ConfigPath  = $config.ConfigPath
        SecretVault = $SecretVault
        SecretName  = $SecretName
        Scopes      = @('https://graph.microsoft.com/.default')
    }
}

function Disconnect-AppExposureGraph {
    [CmdletBinding()]
    param()

    $script:GraphApplicationAccessToken = $null
}
