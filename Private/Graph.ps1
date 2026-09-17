<#
.SYNOPSIS
    Single raw Microsoft Graph read-only transport boundary.
.DESCRIPTION
    Owns authenticated GET transport, pagination, JSON batching, retry behavior
    and Graph telemetry. No findings, snapshot, comparison or reporting code
    calls Graph.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppExposureGraphAuthorizationHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$ExtraHeaders = @{}
    )

    if ([string]::IsNullOrWhiteSpace([string]$script:GraphApplicationAccessToken)) {
        throw 'Microsoft Graph application token is not available. Call Connect-AppExposureGraph before issuing Graph requests.'
    }

    $headers = @{
        Authorization = "Bearer $script:GraphApplicationAccessToken"
    }

    foreach ($key in @($ExtraHeaders.Keys)) {
        if ([string]$key -ieq 'Authorization') {
            throw 'Authorization header is managed by the Graph transport boundary.'
        }
        $headers[$key] = $ExtraHeaders[$key]
    }

    return $headers
}

function Invoke-AppExposureHttpRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][hashtable]$Headers = @{}
    )

    $invokeParams = @{
        Method      = 'GET'
        Uri         = $Uri
        Headers     = Get-AppExposureGraphAuthorizationHeaders -ExtraHeaders $Headers
        ErrorAction = 'Stop'
    }

    return Invoke-RestMethod @invokeParams
}
function Get-AppExposureHttpStatusCode {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $responseProp = $ErrorRecord.Exception.PSObject.Properties['Response']
    if (-not $responseProp -or -not $responseProp.Value) { return $null }
    $statusProp = $responseProp.Value.PSObject.Properties['StatusCode']
    if (-not $statusProp -or $null -eq $statusProp.Value) { return $null }
    try { return [int]$statusProp.Value } catch { return $null }
}
function Get-AppExposureRetryAfterSeconds {
    param(
        [Parameter(Mandatory = $true)]$ErrorRecord,
        [Parameter(Mandatory = $true)][int]$Attempt
    )

    $fallback = [int][Math]::Min([Math]::Pow(2, [Math]::Max($Attempt, 1)), 60)
    $responseProp = $ErrorRecord.Exception.PSObject.Properties['Response']
    if (-not $responseProp -or -not $responseProp.Value) { return $fallback }
    $headersProp = $responseProp.Value.PSObject.Properties['Headers']
    if (-not $headersProp -or -not $headersProp.Value) { return $fallback }

    $retryAfter = $null
    try { $retryAfter = $headersProp.Value['Retry-After'] } catch { }
    if (-not $retryAfter) {
        $retryProp = $headersProp.Value.PSObject.Properties['RetryAfter']
        if ($retryProp) { $retryAfter = $retryProp.Value }
    }
    if (-not $retryAfter) { return $fallback }

    $seconds = 0
    if ([int]::TryParse([string]$retryAfter, [ref]$seconds)) {
        return [Math]::Max($seconds, 1)
    }

    $retryDate = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$retryAfter, [ref]$retryDate)) {
        $delta = [Math]::Ceiling(($retryDate.UtcDateTime - [datetime]::UtcNow).TotalSeconds)
        return [int][Math]::Max($delta, 1)
    }

    return $fallback
}
function Invoke-AppExposureGraphRequest {
    <#
    .SYNOPSIS
        Executes a read-only Microsoft Graph request through the authenticated
        analyzer application-token context.

    .DESCRIPTION
        Only GET is supported. The function follows @odata.nextLink by default,
        keeps explicit request/page/retry telemetry, and surfaces non-transient
        failures so collection modules can record completeness rather than fail
        open.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [switch]$FollowPagination = $true,

        [Parameter(Mandatory = $false)]
        [hashtable]$ExtraHeaders = @{},

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetryCount = 5
    )

    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri

    while ($nextUri) {
        $attempt = 0
        $response = $null

        while ($attempt -le $MaxRetryCount) {
            try {
                $script:GraphTelemetry.Requests++
                $script:GraphTelemetry.LastRequestUtc = [datetime]::UtcNow.ToString('o')
                $response = Invoke-AppExposureHttpRequest -Uri $nextUri -Headers $ExtraHeaders
                break
            }
            catch {
                $statusCode = Get-AppExposureHttpStatusCode -ErrorRecord $_
                $retryableStatus = $statusCode -in @(429, 500, 502, 503, 504)

                if ($retryableStatus -and $attempt -lt $MaxRetryCount) {
                    $attempt++
                    $script:GraphTelemetry.Retries++
                    if ($statusCode -eq 429) { $script:GraphTelemetry.Throttles++ }
                    if ($statusCode -eq 503) { $script:GraphTelemetry.ServiceUnavailable++ }
                    $waitSeconds = Get-AppExposureRetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
                    Write-Host "[Graph] HTTP $statusCode. Retry $attempt/$MaxRetryCount after $waitSeconds s." -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitSeconds
                    continue
                }

                $isTimeout = ($_.Exception.GetType().Name -eq 'TaskCanceledException') -or ($_.Exception.Message -match 'timed?\s*out')
                $isTransport = $isTimeout `
                    -or ($_.Exception -is [System.IO.IOException]) `
                    -or ($_.Exception.InnerException -is [System.IO.IOException]) `
                    -or ($_.Exception -is [System.Net.Sockets.SocketException]) `
                    -or ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) `
                    -or ($_.Exception.Message -match 'forcibly closed|connection was closed|connection reset|error occurred while sending')

                if ($isTransport -and $attempt -lt $MaxRetryCount) {
                    $attempt++
                    $script:GraphTelemetry.Retries++
                    $script:GraphTelemetry.TransportFailures++
                    $waitSeconds = [int][Math]::Min([Math]::Pow(2, $attempt), 60)
                    Write-Host "[Graph] Transient transport failure. Retry $attempt/$MaxRetryCount after $waitSeconds s." -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitSeconds
                    continue
                }

                throw
            }
        }

        if ($null -eq $response) {
            throw "Request to $nextUri failed after $MaxRetryCount retries."
        }

        $script:GraphTelemetry.Pages++
        $valueProp = $response.PSObject.Properties['value']
        if ($valueProp) { $results.AddRange(@($valueProp.Value)) }
        else { $results.Add($response) }

        $nextLinkProp = $response.PSObject.Properties['@odata.nextLink']
        $nextUri = if ($FollowPagination -and $nextLinkProp -and $nextLinkProp.Value) { [string]$nextLinkProp.Value } else { $null }
    }

    return @($results.ToArray())
}
function Get-AppExposureBatchPropertyValue {
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}
function Test-AppExposureBatchPropertyExists {
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return [bool]$Object.Contains($Name) }
    return [bool]($null -ne $Object.PSObject.Properties[$Name])
}
function ConvertTo-AppExposureBatchRelativeUri {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][ValidateSet('v1.0','beta')][string]$ApiVersion
    )

    $prefix = "https://graph.microsoft.com/$ApiVersion"
    if (-not $Uri.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Batch request URI must target $prefix. Received '$Uri'."
    }
    $relative = $Uri.Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($relative)) { return '/' }
    if (-not $relative.StartsWith('/')) { $relative = '/' + $relative }
    return $relative
}
function Invoke-AppExposureHttpBatchRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('v1.0','beta')][string]$ApiVersion,
        [Parameter(Mandatory = $true)]$Body
    )

    $uri = "https://graph.microsoft.com/$ApiVersion/`$batch"
    $json = ConvertTo-Json -InputObject $Body -Depth 30 -Compress
    return Invoke-RestMethod -Method POST -Uri $uri -Headers (Get-AppExposureGraphAuthorizationHeaders) -Body $json -ContentType 'application/json' -ErrorAction Stop
}
function Get-AppExposureBatchRetryAfterSeconds {
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Headers,
        [Parameter(Mandatory = $true)][int]$Attempt
    )

    $fallback = [int][Math]::Min([Math]::Pow(2, [Math]::Max($Attempt, 1)), 60)
    if ($null -eq $Headers) { return $fallback }

    $retryAfter = $null
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in @($Headers.Keys)) {
            if ([string]$key -ieq 'Retry-After') { $retryAfter = $Headers[$key]; break }
        }
    }
    else {
        $prop = $Headers.PSObject.Properties | Where-Object { $_.Name -ieq 'Retry-After' } | Select-Object -First 1
        if ($prop) { $retryAfter = $prop.Value }
    }
    if (-not $retryAfter) { return $fallback }

    $seconds = 0
    if ([int]::TryParse([string]$retryAfter, [ref]$seconds)) { return [Math]::Max($seconds, 1) }
    $retryDate = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$retryAfter, [ref]$retryDate)) {
        return [int][Math]::Max([Math]::Ceiling(($retryDate.UtcDateTime - [datetime]::UtcNow).TotalSeconds), 1)
    }
    return $fallback
}
function Invoke-AppExposureGraphBatchRequest {
    <#
    .SYNOPSIS
        Executes many independent read-only Microsoft Graph GET requests through
        Graph JSON batching while preserving per-request completeness and pagination.

    .DESCRIPTION
        The outer Graph call is POST to the documented $batch endpoint, but every
        subrequest is generated internally as GET. Callers cannot supply a method or
        request body. Up to 20 GETs are placed in each batch. Individual 429/5xx
        responses are retried and @odata.nextLink pages are resubmitted through later
        batches, so batching never truncates collection evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Requests,
        [Parameter(Mandatory = $false)][ValidateSet('v1.0','beta')][string]$ApiVersion = 'v1.0',
        [Parameter(Mandatory = $false)][ValidateRange(0,10)][int]$MaxRetryCount = 5
    )

    if (@($Requests).Count -eq 0) { return @() }

    $seenIds = @{}
    $pending = New-Object System.Collections.Generic.List[object]
    $requestOrder = New-Object System.Collections.Generic.List[string]
    foreach ($request in @($Requests)) {
        $id = [string](Get-AppExposureBatchPropertyValue -Object $request -Name 'Id')
        $uri = [string](Get-AppExposureBatchPropertyValue -Object $request -Name 'Uri')
        if ([string]::IsNullOrWhiteSpace($id)) { throw 'Every batch request requires a non-empty Id.' }
        if ($seenIds.ContainsKey($id)) { throw "Duplicate batch request Id '$id'." }
        if ([string]::IsNullOrWhiteSpace($uri)) { throw "Batch request '$id' requires Uri." }
        [void](ConvertTo-AppExposureBatchRelativeUri -Uri $uri -ApiVersion $ApiVersion)
        $seenIds[$id] = $true
        $requestOrder.Add($id)
        $headers = Get-AppExposureBatchPropertyValue -Object $request -Name 'Headers'
        if ($null -eq $headers) { $headers = @{} }
        $follow = $true
        if (Test-AppExposureBatchPropertyExists -Object $request -Name 'FollowPagination') {
            $follow = [bool](Get-AppExposureBatchPropertyValue -Object $request -Name 'FollowPagination')
        }
        $pending.Add([PSCustomObject]@{
            Id               = $id
            OriginalUri      = $uri
            Uri              = $uri
            Headers          = $headers
            FollowPagination = $follow
            Attempt          = 0
            Items            = (New-Object System.Collections.Generic.List[object])
        })
    }

    $resultById = @{}
    while ($pending.Count -gt 0) {
        $take = [Math]::Min(20, $pending.Count)
        $chunk = @($pending.GetRange(0, $take).ToArray())
        $pending.RemoveRange(0, $take)

        $subRequests = @(
            foreach ($work in $chunk) {
                $entry = [ordered]@{
                    id     = [string]$work.Id
                    method = 'GET'
                    url    = ConvertTo-AppExposureBatchRelativeUri -Uri ([string]$work.Uri) -ApiVersion $ApiVersion
                }
                if ($work.Headers -and $work.Headers.Count -gt 0) { $entry.headers = $work.Headers }
                [PSCustomObject]$entry
            }
        )

        $batchBody = [PSCustomObject]@{ requests = $subRequests }
        $batchAttempt = 0
        $batchResponse = $null
        while ($batchAttempt -le $MaxRetryCount) {
            try {
                $script:GraphTelemetry.Requests++
                $script:GraphTelemetry.BatchRequests++
                $script:GraphTelemetry.BatchSubRequests += $subRequests.Count
                $script:GraphTelemetry.LastRequestUtc = [datetime]::UtcNow.ToString('o')
                $batchResponse = Invoke-AppExposureHttpBatchRequest -ApiVersion $ApiVersion -Body $batchBody
                break
            }
            catch {
                $statusCode = Get-AppExposureHttpStatusCode -ErrorRecord $_
                $retryable = ($statusCode -in @(429,500,502,503,504)) -or ($_.Exception.Message -match 'timed?\s*out|forcibly closed|connection was closed|connection reset|error occurred while sending')
                if ($retryable -and $batchAttempt -lt $MaxRetryCount) {
                    $batchAttempt++
                    $script:GraphTelemetry.Retries++
                    if ($statusCode -eq 429) { $script:GraphTelemetry.Throttles++ }
                    if ($statusCode -eq 503) { $script:GraphTelemetry.ServiceUnavailable++ }
                    if (-not $statusCode) { $script:GraphTelemetry.TransportFailures++ }
                    $waitSeconds = Get-AppExposureRetryAfterSeconds -ErrorRecord $_ -Attempt $batchAttempt
                    Write-Host "[Graph] Batch HTTP $statusCode. Retry $batchAttempt/$MaxRetryCount after $waitSeconds s." -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitSeconds
                    continue
                }
                throw
            }
        }
        if ($null -eq $batchResponse) { throw 'Microsoft Graph batch request failed without a response.' }

        $responses = @((Get-AppExposureBatchPropertyValue -Object $batchResponse -Name 'responses'))
        $responseById = @{}
        foreach ($response in $responses) {
            $responseId = [string](Get-AppExposureBatchPropertyValue -Object $response -Name 'id')
            if (-not [string]::IsNullOrWhiteSpace($responseId)) { $responseById[$responseId] = $response }
        }

        $maxRetryWait = 0
        foreach ($work in $chunk) {
            $id = [string]$work.Id
            if (-not $responseById.ContainsKey($id)) {
                $resultById[$id] = [PSCustomObject]@{
                    Id = $id; SourceUri = [string]$work.OriginalUri; CollectionState = 'Failed'; StatusCode = 0
                    Error = 'Graph batch response did not contain the requested response id.'; Items = @($work.Items.ToArray())
                }
                continue
            }

            $response = $responseById[$id]
            $statusCode = [int](Get-AppExposureBatchPropertyValue -Object $response -Name 'status')
            $body = Get-AppExposureBatchPropertyValue -Object $response -Name 'body'
            $headers = Get-AppExposureBatchPropertyValue -Object $response -Name 'headers'

            if ($statusCode -ge 200 -and $statusCode -lt 300) {
                $script:GraphTelemetry.Pages++
                if (Test-AppExposureBatchPropertyExists -Object $body -Name 'value') {
                    foreach ($item in @((Get-AppExposureBatchPropertyValue -Object $body -Name 'value'))) {
                        if ($null -ne $item) { $work.Items.Add($item) }
                    }
                }
                elseif ($null -ne $body) {
                    $work.Items.Add($body)
                }

                $nextLink = [string](Get-AppExposureBatchPropertyValue -Object $body -Name '@odata.nextLink')
                if ($work.FollowPagination -and -not [string]::IsNullOrWhiteSpace($nextLink)) {
                    $work.Uri = $nextLink
                    $work.Attempt = 0
                    $pending.Add($work)
                }
                else {
                    $resultById[$id] = [PSCustomObject]@{
                        Id = $id; SourceUri = [string]$work.OriginalUri; CollectionState = 'Complete'; StatusCode = $statusCode
                        Error = $null; Items = @($work.Items.ToArray())
                    }
                }
                continue
            }

            $retryableStatus = $statusCode -in @(429,500,502,503,504)
            if ($retryableStatus -and [int]$work.Attempt -lt $MaxRetryCount) {
                $work.Attempt = [int]$work.Attempt + 1
                $script:GraphTelemetry.Retries++
                if ($statusCode -eq 429) { $script:GraphTelemetry.Throttles++ }
                if ($statusCode -eq 503) { $script:GraphTelemetry.ServiceUnavailable++ }
                $waitSeconds = Get-AppExposureBatchRetryAfterSeconds -Headers $headers -Attempt ([int]$work.Attempt)
                $maxRetryWait = [Math]::Max($maxRetryWait, $waitSeconds)
                $pending.Add($work)
                continue
            }

            $errorObject = Get-AppExposureBatchPropertyValue -Object $body -Name 'error'
            $message = [string](Get-AppExposureBatchPropertyValue -Object $errorObject -Name 'message')
            if ([string]::IsNullOrWhiteSpace($message)) { $message = "Microsoft Graph subrequest returned HTTP $statusCode." }
            $state = if ($statusCode -in @(401,403)) { 'NotAuthorized' } elseif ($statusCode -eq 404) { 'NotFound' } else { 'Failed' }
            $resultById[$id] = [PSCustomObject]@{
                Id = $id; SourceUri = [string]$work.OriginalUri; CollectionState = $state; StatusCode = $statusCode
                Error = $message; Items = @($work.Items.ToArray())
            }
        }

        if ($maxRetryWait -gt 0) {
            Write-Host "[Graph] Retrying throttled/transient batch subrequest(s) after $maxRetryWait s." -ForegroundColor Yellow
            Start-Sleep -Seconds $maxRetryWait
        }
    }

    return @($requestOrder | ForEach-Object { $resultById[[string]$_] })
}
