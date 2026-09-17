<# Console presentation helpers for Entra App Exposure. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Test-AppExposureInteractiveConsole {
    if (-not [Environment]::UserInteractive) { return $false }
    try { return -not [Console]::IsOutputRedirected }
    catch { return $true }
}

function Test-AppExposureColorEnabled {
    if (-not (Test-AppExposureInteractiveConsole)) { return $false }
    if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('NO_COLOR'))) { return $false }
    if ([string]::Equals([Environment]::GetEnvironmentVariable('TERM'), 'dumb', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    return $true
}

function Write-AppExposureBanner {
    if (-not (Test-AppExposureInteractiveConsole)) { return }

    $banner = @'               
                                        
                -***=--*                
               *****=----               
             *******=------             
           *********--::::::.           
         **********#=:::::::::.         
        *********#%%*+-:::::::::        
      **********#%%%***+::::::::::      
    **********#%%%%%*****=:::::::::.    
  **********#%%%%%%%*******=:::::::::.  
  **********#%%%%%%%******+=::::::::::  
  ************##%%%%***+=:::::::::::::  
   ***************##+-::::::::::::::.   
      ***********+=::::::::::::::.      
         *++===-::::::::::::::.         
            ::::::::::::::::            
                ::::::::            

  _____       _                  _                  _____                                     
 | ____|_ __ | |_ _ __ __ _     / \   _ __  _ __   | ____|_  ___ __   ___  ___ _   _ _ __ ___ 
 |  _| | '_ \| __| '__/ _` |   / _ \ | '_ \| '_ \  |  _| \ \/ / '_ \ / _ \/ __| | | | '__/ _ \
 | |___| | | | |_| | | (_| |  / ___ \| |_) | |_) | | |___ >  <| |_) | (_) \__ \ |_| | | |  __/
 |_____|_| |_|\__|_|  \__,_| /_/   \_\ .__/| .__/  |_____/_/\_\ .__/ \___/|___/\__,_|_|  \___|
                                     |_|   |_|                |_|                             
'@

    if (Test-AppExposureColorEnabled) {
        Write-Host $banner -ForegroundColor Cyan
        Write-Host '  Entra App Exposure' -ForegroundColor White
        Write-Host '  Evidence-driven Microsoft Entra application identity assessment' -ForegroundColor DarkGray
        Write-Host '  Snapshot-first · deterministic rules · offline-compatible reporting' -ForegroundColor DarkGray
    }
    else {
        Write-Host $banner
        Write-Host '  Entra App Exposure'
        Write-Host '  Evidence-driven Microsoft Entra application identity assessment'
        Write-Host '  Snapshot-first · deterministic rules · offline-compatible reporting'
    }
    Write-Host ''
}

function Write-AppExposureStage {
    param(
        [Parameter(Mandatory = $true)][ValidateRange(1,7)][int]$Step,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $message = "[$Step/7] $Name"
    if (Test-AppExposureInteractiveConsole) {
        Write-Progress -Id 1 -Activity 'Entra App Exposure' -Status $message -PercentComplete ([math]::Min(100, [math]::Round(($Step / 7) * 100)))
    }
    Write-Information $message -InformationAction Continue
}

function Write-AppExposureItemProgress {
    param(
        [Parameter(Mandatory = $true)][string]$Activity,
        [Parameter(Mandatory = $true)][int]$Current,
        [Parameter(Mandatory = $true)][int]$Total,
        [Parameter(Mandatory = $false)][string]$Status
    )
    if (-not (Test-AppExposureInteractiveConsole) -or $Total -le 0) { return }
    $percent = [math]::Min(100, [math]::Round(($Current / [double]$Total) * 100))
    Write-Progress -Id 2 -ParentId 1 -Activity $Activity -Status $Status -PercentComplete $percent
}

function ConvertTo-AppExposureDuration {
    param([AllowNull()][object]$Milliseconds)
    if ($null -eq $Milliseconds) { return 'n/a' }
    $value = [double]$Milliseconds
    if ($value -ge 60000) { return ('{0:N1}m' -f ($value / 60000.0)) }
    if ($value -ge 1000) { return ('{0:N1}s' -f ($value / 1000.0)) }
    return ('{0:N0}ms' -f $value)
}

function Write-AppExposureCompletion {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$PhaseTimings,
        [Parameter(Mandatory = $true)][timespan]$Elapsed,
        [Parameter(Mandatory = $true)][bool]$OfflineMode,
        [Parameter(Mandatory = $true)][bool]$ActivityIncluded,
        [Parameter(Mandatory = $true)][int]$ActivityLookbackDays,
        [Parameter(Mandatory = $false)][bool]$MicrosoftFirstPartyExcluded = $false
    )

    if (-not (Test-AppExposureInteractiveConsole)) { return }

    $collection = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Collection'
    $graphTelemetry = Get-AppExposurePropertyValue -Object $collection -Name 'GraphTelemetry'
    $applications = @(Get-AppExposurePropertyValue -Object $Snapshot -Name 'Applications')
    $servicePrincipals = @(Get-AppExposurePropertyValue -Object $Snapshot -Name 'ServicePrincipals')
    $scopeValue = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Scope')
    if ([string]::IsNullOrWhiteSpace($scopeValue)) { $scopeValue = 'Unknown' }
    $requests = Get-AppExposurePropertyValue -Object $graphTelemetry -Name 'Requests'
    if ($null -eq $requests) { $requests = 0 }
    $batchRequests = Get-AppExposurePropertyValue -Object $graphTelemetry -Name 'BatchRequests'
    if ($null -eq $batchRequests) { $batchRequests = 0 }
    $batchSubRequests = Get-AppExposurePropertyValue -Object $graphTelemetry -Name 'BatchSubRequests'
    if ($null -eq $batchSubRequests) { $batchSubRequests = 0 }
    $retries = Get-AppExposurePropertyValue -Object $graphTelemetry -Name 'Retries'
    if ($null -eq $retries) { $retries = 0 }
    $throttles = Get-AppExposurePropertyValue -Object $graphTelemetry -Name 'Throttles'
    if ($null -eq $throttles) { $throttles = 0 }
    $logicalRequests = [Math]::Max(0, ([int]$requests - [int]$batchRequests + [int]$batchSubRequests))
    $coreComplete = [bool](Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete')
    $status = if ($coreComplete) { 'Assessment complete' } else { 'Assessment complete with incomplete evidence' }
    $marker = if ($coreComplete) { 'OK' } else { '!' }
    $statusColor = if ($coreComplete) { 'Green' } else { 'Yellow' }
    $reportPath = Get-AppExposurePropertyValue -Object $Result.Artifacts -Name 'HtmlReport'
    $mode = if ($OfflineMode) { 'Offline snapshot' } else { 'Live Graph' }
    $featureParts = [System.Collections.Generic.List[string]]::new()
    if ($ActivityIncluded -and -not $OfflineMode) { $featureParts.Add("Activity: $ActivityLookbackDays days") }
    if ($MicrosoftFirstPartyExcluded) { $featureParts.Add('Microsoft first-party findings: excluded') }
    if ($Result.DriftStatus -eq 'Compared') { $featureParts.Add("Drift: $($Result.DriftCount) change(s)") }
    else { $featureParts.Add('Drift: not compared') }

    Write-Host ''
    if (Test-AppExposureColorEnabled) {
        Write-Host ("[{0}] {1}" -f $marker, $status) -ForegroundColor $statusColor
        Write-Host ("     Mode     : {0} | Scope: {1}" -f $mode, $scopeValue) -ForegroundColor DarkGray
        Write-Host ("     Inventory: {0} application(s) | {1} service principal(s)" -f $applications.Count, $servicePrincipals.Count) -ForegroundColor DarkGray
        Write-Host ("     Results  : {0} finding(s) | {1}" -f $Result.FindingsCount, ($featureParts -join ' | ')) -ForegroundColor DarkGray
        Write-Host ("     Graph    : {0} logical / {1} HTTP | retries: {2} | throttles: {3}" -f $logicalRequests, $requests, $retries, $throttles) -ForegroundColor DarkGray
        Write-Host ("     Boundary : {0} Graph call(s) after snapshot" -f $Result.GraphCallsAfterSnapshot) -ForegroundColor DarkGray
        Write-Host ("     Runtime  : {0}" -f (ConvertTo-AppExposureDuration $Elapsed.TotalMilliseconds)) -ForegroundColor DarkGray
        Write-Host ("     Export   : {0}" -f $Result.OutputDirectory) -ForegroundColor DarkGray
        Write-Host ("     Report   : {0}" -f $reportPath) -ForegroundColor DarkGray
    }
    else {
        Write-Host ("[{0}] {1}" -f $marker, $status)
        Write-Host ("     Mode     : {0} | Scope: {1}" -f $mode, $scopeValue)
        Write-Host ("     Inventory: {0} application(s) | {1} service principal(s)" -f $applications.Count, $servicePrincipals.Count)
        Write-Host ("     Results  : {0} finding(s) | {1}" -f $Result.FindingsCount, ($featureParts -join ' | '))
        Write-Host ("     Graph    : {0} logical / {1} HTTP | retries: {2} | throttles: {3}" -f $logicalRequests, $requests, $retries, $throttles)
        Write-Host ("     Boundary : {0} Graph call(s) after snapshot" -f $Result.GraphCallsAfterSnapshot)
        Write-Host ("     Runtime  : {0}" -f (ConvertTo-AppExposureDuration $Elapsed.TotalMilliseconds))
        Write-Host ("     Export   : {0}" -f $Result.OutputDirectory)
        Write-Host ("     Report   : {0}" -f $reportPath)
    }
}


<#
.SYNOPSIS
    Internal assessment orchestration pipeline.
.DESCRIPTION
    Coordinates collection, snapshot creation, offline rule evaluation, drift and
    export while preserving the post-snapshot zero-Graph boundary.
#>
function Invoke-AppExposurePipeline {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = (Get-AppExposureDefaultConfigPath),

    [Parameter(Mandatory = $false)]
    [string]$SecretVault = 'AppExposureVault',

    [Parameter(Mandatory = $false)]
    [string]$SecretName = 'AppExposureGraphClientSecret',

    [Parameter(Mandatory = $false)][string]$OutputDirectory = '.\Reports',
    [Parameter(Mandatory = $false)][string]$ClientName,
    [Parameter(Mandatory = $false)][string]$ConsultantName,
    [Parameter(Mandatory = $false)][string]$TenantName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Single')]
    [string]$Scope = 'All',

    [Parameter(Mandatory = $false)][string]$TargetAppId,
    [Parameter(Mandatory = $false)][string]$TargetDisplayName,

    [Parameter(Mandatory = $false)][switch]$IncludeActivity,
    [Parameter(Mandatory = $false)][ValidateRange(1, 90)][int]$ActivityLookbackDays = 90,
    [Parameter(Mandatory = $false)][switch]$ExcludeMicrosoftFirstParty,

    [Parameter(Mandatory = $false)][string]$BaselineSnapshotPath,
    [Parameter(Mandatory = $false)][string]$OfflineSnapshotPath,
    [Parameter(Mandatory = $false)][string]$RulePackPath

    )

$root = $script:EntraAppExposureRoot

if (-not $RulePackPath) { $RulePackPath = Join-Path $root 'Rules\Baseline.json' }
$rulePack = Import-AppExposureRulePack -Path $RulePackPath

$snapshot = $null
$authContext = $null
$tenantId = $null
$clientId = $null
$runOutputDirectory = $null
$transcriptStarted = $false
$graphConnected = $false
$snapshotGraphRequestCount = 0
$driftStatus = 'NotCompared'
$baselineSnapshotId = $null
$baselineCollectedAtUtc = $null
$graphCallsAfterSnapshot = 0
$runStartedAtUtc = [datetime]::UtcNow
$runStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$phaseTimings = [ordered]@{}
$finalResult = $null
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$bootstrapOutputDirectory = Join-Path (Join-Path $OutputDirectory '_bootstrap') $runStamp
$bootstrapTranscriptPath = Join-Path $bootstrapOutputDirectory 'run.log'

# Start the transcript before stage 1 so authentication/bootstrap diagnostics are
# retained. On successful initialization the transcript is moved into the normal
# client run directory and continued there with -Append.
New-Item -ItemType Directory -Path $bootstrapOutputDirectory -Force | Out-Null
Start-Transcript -Path $bootstrapTranscriptPath -Force | Out-Null
$transcriptStarted = $true

# CLI decoration is best-effort and must never affect assessment execution.
try { Write-AppExposureBanner } catch { }

try {
    Write-AppExposureStage -Step 1 -Name $(if ($OfflineSnapshotPath) { 'Importing portable snapshot' } else { 'Authenticating to Microsoft Graph' })
    if ($OfflineSnapshotPath) {
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $snapshot = Import-AppExposureSnapshot -Path $OfflineSnapshotPath
        Complete-AppExposurePhase -Name 'SnapshotImport' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
        $snapshotAssessment = Get-AppExposurePropertyValue -Object $snapshot -Name 'Assessment'
        $snapshotClient = [string](Get-AppExposurePropertyValue -Object $snapshotAssessment -Name 'ClientName')
        if (-not $ClientName) { $ClientName = $snapshotClient }
        if (-not $ClientName) { $ClientName = 'Offline_Assessment' }
    }
    else {
        if ($Scope -eq 'Single' -and -not $TargetAppId -and -not $TargetDisplayName) {
            throw 'Single scope requires -TargetAppId or -TargetDisplayName. Interactive target prompting is intentionally not supported.'
        }

        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Reset-AppExposureGraphTelemetry
        $authContext = Connect-AppExposureGraph -ConfigPath $ConfigPath -SecretVault $SecretVault -SecretName $SecretName
        $graphConnected = $true
        $tenantId = [string]$authContext.TenantId
        $clientId = [string]$authContext.ClientId

        if (-not $TenantName) {
            try { $TenantName = Get-AppExposureOrganizationName }
            catch { Write-Warning 'Tenant display name could not be resolved; tenant ID remains authoritative.' }
        }

        if (-not $ClientName) {
            try {
                $authApp = @(Get-AppExposureApplications -AppId $clientId)
                if ($authApp.Count -eq 1) { $ClientName = [string]$authApp[0].DisplayName }
            }
            catch { }
            if (-not $ClientName) { $ClientName = $clientId }
        }
        Complete-AppExposurePhase -Name 'Authentication' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
    }

    $safeClientName = ConvertTo-AppExposureSafePathName -Name $ClientName
    $runOutputDirectory = Join-Path (Join-Path $OutputDirectory $safeClientName) $runStamp
    New-Item -ItemType Directory -Path $runOutputDirectory -Force | Out-Null

    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
        $transcriptStarted = $false
    }
    $runLogPath = Join-Path $runOutputDirectory 'run.log'
    if (Test-Path -LiteralPath $bootstrapTranscriptPath -PathType Leaf) {
        Move-Item -LiteralPath $bootstrapTranscriptPath -Destination $runLogPath -Force
    }
    if (Test-Path -LiteralPath $bootstrapOutputDirectory -PathType Container) {
        Remove-Item -LiteralPath $bootstrapOutputDirectory -Force -ErrorAction SilentlyContinue
        $bootstrapParent = Split-Path -Parent $bootstrapOutputDirectory
        if ((Test-Path -LiteralPath $bootstrapParent -PathType Container) -and @(Get-ChildItem -LiteralPath $bootstrapParent -Force -ErrorAction SilentlyContinue).Count -eq 0) {
            Remove-Item -LiteralPath $bootstrapParent -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Transcript -Path $runLogPath -Append -Force | Out-Null
    $transcriptStarted = $true

    if ($snapshot) {
        Write-AppExposureStage -Step 2 -Name 'Using inventory contained in portable snapshot'
        Write-AppExposureStage -Step 3 -Name 'Using evidence contained in portable snapshot'
    }

    if (-not $snapshot) {
        Write-AppExposureStage -Step 2 -Name "Discovering application identity inventory ($Scope scope)"
        $servicePrincipals = @()
        $applications = @()

        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        if ($Scope -eq 'Single') {
            $target = Find-AppExposureServicePrincipal -TenantId $tenantId -TargetAppId $TargetAppId -TargetDisplayName $TargetDisplayName
            $servicePrincipals = @($target)
            if ($target.AppId) { $applications = @(Get-AppExposureApplications -AppId $target.AppId) }
        }
        else {
            $applications = @(Get-AppExposureApplications)
            $servicePrincipals = @(Get-AppExposureServicePrincipals -TenantId $tenantId)
        }
        Complete-AppExposurePhase -Name 'Discovery' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $appByAppId = @{}
        foreach ($app in $applications) {
            if ($app.AppId) { $appByAppId[[string]$app.AppId] = $app }
        }
        $spIdsByAppId = @{}
        foreach ($sp in $servicePrincipals) {
            $key = [string]$sp.AppId
            if ([string]::IsNullOrWhiteSpace($key)) { continue }
            if (-not $spIdsByAppId.ContainsKey($key)) { $spIdsByAppId[$key] = New-Object System.Collections.Generic.List[string] }
            $spIdsByAppId[$key].Add([string]$sp.ObjectId)
        }

        Write-AppExposureStage -Step 3 -Name "Collecting owners, permissions, credentials and activity evidence"
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $applicationOwnerMap = Get-AppExposureApplicationOwnersBulk -Applications $applications
        Complete-AppExposurePhase -Name 'ApplicationOwners' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $applicationPermissionMap = Get-AppExposurePermissionsBulk -ServicePrincipals $servicePrincipals
        Complete-AppExposurePhase -Name 'ApplicationPermissions' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $delegatedPermissionMap = Get-AppExposureDelegatedPermissionsBulk -ServicePrincipals $servicePrincipals
        Complete-AppExposurePhase -Name 'DelegatedPermissions' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $ownerCandidates = @($servicePrincipals | Where-Object { $_.Classification -ne 'MicrosoftFirstParty' })
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $servicePrincipalOwnerMap = Get-AppExposureOwnersBulk -ServicePrincipals $ownerCandidates
        Complete-AppExposurePhase -Name 'ServicePrincipalOwners' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $activityMap = @{}
        if ($IncludeActivity) {
            Write-Host "[Run] Collecting optional sign-in context from the service-principal activity report (with compatibility fallback)..." -ForegroundColor Cyan
            $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $activityMap = Get-AppExposureLastSignInBulk -ServicePrincipals $servicePrincipals -LookbackDays $ActivityLookbackDays
            Complete-AppExposurePhase -Name 'Activity' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
        }

        # Application registrations remain first-class evidence objects. Credential
        # metadata is reused from the application inventory, avoiding one GET per app.
        Write-AppExposureStage -Step 4 -Name "Assembling evidence and writing portable snapshot"
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $applicationAssessments = New-Object System.Collections.Generic.List[object]
        $applicationCredentialsByObjectId = @{}
        $appIndex = 0
        foreach ($app in $applications) {
            $appIndex++
            Write-AppExposureItemProgress -Activity 'Assembling application registrations' -Current $appIndex -Total $applications.Count -Status $app.DisplayName
            $appObjectId = [string]$app.ObjectId
            $appOwners = if ($applicationOwnerMap.ContainsKey($appObjectId)) { $applicationOwnerMap[$appObjectId] } else { New-AppExposureLocalCollectionResult -State 'Failed' -Error 'Application-owner batch result was missing.' }
            $appCredentials = Get-AppExposureCredentialsFromApplication -Application $app
            $applicationCredentialsByObjectId[$appObjectId] = $appCredentials
            $linkedIds = if ($app.AppId -and $spIdsByAppId.ContainsKey([string]$app.AppId)) { @($spIdsByAppId[[string]$app.AppId].ToArray()) } else { @() }

            $applicationAssessments.Add([PSCustomObject]@{
                ObjectId                  = $app.ObjectId
                AppId                     = $app.AppId
                DisplayName               = $app.DisplayName
                CreatedDateTime           = $app.CreatedDateTime
                SignInAudience            = $app.SignInAudience
                PublisherDomain           = $app.PublisherDomain
                VerifiedPublisher         = $app.VerifiedPublisher
                Authentication            = $app.Authentication
                ApiConfiguration          = $app.ApiConfiguration
                LinkedServicePrincipalIds = $linkedIds
                Owners                    = $appOwners
                Credentials               = $appCredentials
            })
        }

        $assessments = New-Object System.Collections.Generic.List[object]
        $index = 0
        foreach ($sp in $servicePrincipals) {
            $index++
            Write-AppExposureItemProgress -Activity 'Assembling service principals' -Current $index -Total $servicePrincipals.Count -Status $sp.DisplayName
            $spObjectId = [string]$sp.ObjectId
            $appPermissions = if ($applicationPermissionMap.ContainsKey($spObjectId)) { $applicationPermissionMap[$spObjectId] } else { New-AppExposureLocalCollectionResult -State 'Failed' -Error 'Application-permission batch result was missing.' }
            $delegatedPermissions = if ($delegatedPermissionMap.ContainsKey($spObjectId)) { $delegatedPermissionMap[$spObjectId] } else { New-AppExposureLocalCollectionResult -State 'Failed' -Error 'Delegated-permission batch result was missing.' }

            if ($sp.Classification -eq 'MicrosoftFirstParty') {
                $owners = New-AppExposureLocalCollectionResult -State 'NotApplicable' -Error 'Ownership finding is not evaluated for Microsoft first-party service principals.'
            }
            elseif ($servicePrincipalOwnerMap.ContainsKey($spObjectId)) {
                $owners = $servicePrincipalOwnerMap[$spObjectId]
            }
            else {
                $owners = New-AppExposureLocalCollectionResult -State 'Failed' -Error 'Service-principal owner batch result was missing.'
            }

            $appRegistration = $null
            if ($sp.AppId -and $appByAppId.ContainsKey([string]$sp.AppId)) { $appRegistration = $appByAppId[[string]$sp.AppId] }
            $appRegistrationObjectId = if ($appRegistration) { $appRegistration.ObjectId } else { $null }
            if ($appRegistrationObjectId -and $applicationCredentialsByObjectId.ContainsKey([string]$appRegistrationObjectId)) {
                $credentials = $applicationCredentialsByObjectId[[string]$appRegistrationObjectId]
            }
            elseif ($sp.ServicePrincipalType -in @('ManagedIdentity', 'Legacy')) {
                $credentials = New-AppExposureLocalCollectionResult -State 'NotApplicable' -Error "Service principal type '$($sp.ServicePrincipalType)' does not have an associated application registration for this credential surface."
            }
            elseif ($sp.Classification -eq 'Local') {
                $credentials = New-AppExposureLocalCollectionResult -State 'Unresolved' -Error 'Local application service principal did not resolve to its expected application registration.'
            }
            else {
                $credentials = New-AppExposureLocalCollectionResult -State 'NotApplicable' -Error 'Application-registration credentials are not tenant-visible/applicable for this service principal.'
            }

            if ($IncludeActivity) {
                $activity = if ($activityMap.ContainsKey($spObjectId)) { $activityMap[$spObjectId] } else {
                    [PSCustomObject]@{ CollectionState='Failed'; SourceKind='NotAvailable'; SourceUri=$null; LookbackDays=$ActivityLookbackDays; LastSignInDateTime=$null; ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null; DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null; NoActivityObserved=$false; Error='Activity collection result was missing.' }
                }
            }
            else {
                $activity = [PSCustomObject]@{ CollectionState='Skipped'; SourceKind='NotCollected'; SourceUri=$null; LookbackDays=$ActivityLookbackDays; LastSignInDateTime=$null; ApplicationAuthenticationClientLastSignInDateTime=$null; ApplicationAuthenticationResourceLastSignInDateTime=$null; DelegatedClientLastSignInDateTime=$null; DelegatedResourceLastSignInDateTime=$null; NoActivityObserved=$false; Error=$null }
            }

            $assessments.Add([PSCustomObject]@{
                ObjectId                = $sp.ObjectId
                AppId                   = $sp.AppId
                DisplayName             = $sp.DisplayName
                Classification          = $sp.Classification
                ServicePrincipalType    = $sp.ServicePrincipalType
                AppOwnerOrganizationId  = $sp.AppOwnerOrganizationId
                AccountEnabled          = $sp.AccountEnabled
                CreatedDateTime         = $sp.CreatedDateTime
                VerifiedPublisher       = $sp.VerifiedPublisher
                AppRegistrationObjectId = $appRegistrationObjectId
                ApplicationPermissions  = $appPermissions
                DelegatedPermissions    = $delegatedPermissions
                Owners                  = $owners
                Credentials             = $credentials
                Activity                = $activity
            })
        }
        if (Test-AppExposureInteractiveConsole) { Write-Progress -Id 2 -Activity 'Assessment object assembly' -Completed }
        Complete-AppExposurePhase -Name 'AssessmentAssembly' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings

        $scopeTarget = if ($Scope -eq 'Single' -and $servicePrincipals.Count -eq 1) { [string]$servicePrincipals[0].ObjectId } else { $null }
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $snapshot = New-AppExposureSnapshot `
            -TenantId $tenantId `
            -TenantName $TenantName `
            -ClientName $ClientName `
            -ConsultantName $ConsultantName `
            -Scope $Scope `
            -ScopeTarget $scopeTarget `
            -Applications $applicationAssessments.ToArray() `
            -ServicePrincipalAssessments $assessments.ToArray() `
            -GraphTelemetry (Get-AppExposureGraphTelemetry)

        Save-AppExposureSnapshot -Snapshot $snapshot -Path (Join-Path $runOutputDirectory 'snapshot.json') | Out-Null
        Complete-AppExposurePhase -Name 'SnapshotWrite' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
        $snapshotTelemetry = Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $snapshot -Name 'Collection') -Name 'GraphTelemetry'
        $snapshotGraphRequestCount = [int](Get-AppExposurePropertyValue -Object $snapshotTelemetry -Name 'Requests')
    }
    else {
        Write-AppExposureStage -Step 4 -Name 'Preparing portable snapshot for offline re-analysis'
        # Preserve the imported source snapshot unchanged inside the re-analysis run.
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Save-AppExposureSnapshot -Snapshot $snapshot -Path (Join-Path $runOutputDirectory 'snapshot.json') | Out-Null
        Complete-AppExposurePhase -Name 'SnapshotWrite' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
    }

    # Snapshot boundary: no Graph calls occur below this line.
    Write-AppExposureStage -Step 5 -Name 'Evaluating deterministic exposure rules'
    $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @(Invoke-AppExposureRules -Snapshot $snapshot -RulePack $rulePack -ExcludeMicrosoftFirstParty:$ExcludeMicrosoftFirstParty)
    Complete-AppExposurePhase -Name 'Findings' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
    $drift = @()
    Write-AppExposureStage -Step 6 -Name $(if ($BaselineSnapshotPath) { 'Comparing against baseline snapshot' } else { 'Skipping drift comparison (no baseline supplied)' })
    if ($BaselineSnapshotPath) {
        $phaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $baseline = Import-AppExposureSnapshot -Path $BaselineSnapshotPath
        $baselineSnapshotId = [string](Get-AppExposurePropertyValue -Object $baseline -Name 'SnapshotId')
        $baselineCollectedAtUtc = [string](Get-AppExposurePropertyValue -Object $baseline -Name 'CollectedAtUtc')
        $drift = @(Compare-AppExposureSnapshots -PreviousSnapshot $baseline -CurrentSnapshot $snapshot)
        $driftStatus = 'Compared'
        Complete-AppExposurePhase -Name 'Drift' -Stopwatch $phaseStopwatch -PhaseTimings $phaseTimings
    }

    if ($graphConnected) {
        $telemetryAfterSnapshot = Get-AppExposureGraphTelemetry
        $graphCallsAfterSnapshot = [int]$telemetryAfterSnapshot.Requests - [int]$snapshotGraphRequestCount
        if ($graphCallsAfterSnapshot -ne 0) {
            throw "Release-integrity boundary violated: GraphCallsAfterSnapshot=$graphCallsAfterSnapshot. Offline analysis/reporting must not call Microsoft Graph."
        }
    }
    else {
        $graphCallsAfterSnapshot = 0
    }

    Write-AppExposureStage -Step 7 -Name 'Exporting assessment artifacts and HTML report'
    $artifacts = Export-AppExposureAssessment -Snapshot $snapshot -Findings $findings -Drift $drift -DriftStatus $driftStatus -BaselineSnapshotId $baselineSnapshotId -BaselineCollectedAtUtc $baselineCollectedAtUtc -GraphCallsAfterSnapshot $graphCallsAfterSnapshot -OutputDirectory $runOutputDirectory -RulePackPath $RulePackPath -RunStartedAtUtc $runStartedAtUtc -PhaseTimingsMs $phaseTimings -ExcludeMicrosoftFirstParty:$ExcludeMicrosoftFirstParty

    # Re-check after reporting so the sentinel covers the entire post-snapshot
    # pipeline, not only rule/drift evaluation.
    if ($graphConnected) {
        $telemetryAfterArtifacts = Get-AppExposureGraphTelemetry
        $graphCallsAfterSnapshot = [int]$telemetryAfterArtifacts.Requests - [int]$snapshotGraphRequestCount
        if ($graphCallsAfterSnapshot -ne 0) {
            throw "Release-integrity boundary violated after artifact export: GraphCallsAfterSnapshot=$graphCallsAfterSnapshot."
        }
    }

    $finalResult = [PSCustomObject]@{
        OutputDirectory = $runOutputDirectory
        SnapshotPath    = (Join-Path $runOutputDirectory 'snapshot.json')
        FindingsCount   = $findings.Count
        ExcludeMicrosoftFirstParty = [bool]$ExcludeMicrosoftFirstParty
        DriftCount      = $drift.Count
        DriftStatus     = $driftStatus
        BaselineSnapshotId = $baselineSnapshotId
        GraphCallsAfterSnapshot = $graphCallsAfterSnapshot
        RunTelemetry    = $artifacts.RunTelemetry
        CoreComplete    = (Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $snapshot -Name 'Collection') -Name 'CoreComplete')
        Artifacts       = $artifacts
    }

    if ($runStopwatch.IsRunning) { $runStopwatch.Stop() }
    try { Write-AppExposureCompletion -Result $finalResult -Snapshot $snapshot -PhaseTimings $phaseTimings -Elapsed $runStopwatch.Elapsed -OfflineMode ([bool]$OfflineSnapshotPath) -ActivityIncluded ([bool]$IncludeActivity) -ActivityLookbackDays $ActivityLookbackDays -MicrosoftFirstPartyExcluded ([bool]$ExcludeMicrosoftFirstParty) } catch { }
    $finalResult
}
finally {
    if ($runStopwatch.IsRunning) { $runStopwatch.Stop() }
    if (Test-AppExposureInteractiveConsole) {
        Write-Progress -Id 2 -Activity 'Assessment object assembly' -Completed -ErrorAction SilentlyContinue
        Write-Progress -Id 1 -Activity 'Entra App Exposure' -Completed
    }
    if ($null -eq $finalResult) { Write-Verbose ("Total elapsed: {0:n2} s" -f $runStopwatch.Elapsed.TotalSeconds) }
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
    if ($graphConnected) {
        Disconnect-AppExposureGraph
    }
}
}

