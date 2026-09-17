<# Shared reporting helpers. Offline only; no Graph access. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-AppExposureSeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 5 }
        'High' { return 4 }
        'Medium' { return 3 }
        'Low' { return 2 }
        'Informational' { return 1 }
        default { return 0 }
    }
}

function Get-AppExposurePriorityRank {
    param([string]$Priority)
    switch ($Priority) {
        'P0' { return 4 }
        'P1' { return 3 }
        'P2' { return 2 }
        'P3' { return 1 }
        default { return 0 }
    }
}

function New-AppExposureIdentityPriorities {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Applications = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$ServicePrincipals = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Findings = @(),
        [Parameter(Mandatory = $false)][hashtable]$ObjectTypeById = @{},
        [Parameter(Mandatory = $false)][hashtable]$ObjectPortalUrlById = @{}
    )

    $actionable = @($Findings | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity') -ne 'Informational' })
    $byObject = @{}
    foreach ($finding in $actionable) {
        $id = [string](Get-AppExposurePropertyValue -Object $finding -Name 'ObjectId')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if (-not $byObject.ContainsKey($id)) { $byObject[$id] = [System.Collections.Generic.List[object]]::new() }
        $byObject[$id].Add($finding)
    }

    $appsByObjectId = @{}
    $linkedAppIds = @{}
    foreach ($app in @($Applications)) {
        $appObjectId = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        if ($appObjectId) { $appsByObjectId[$appObjectId] = $app }
    }
    foreach ($sp in @($ServicePrincipals)) {
        $appObjectId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId')
        if ($appObjectId) { $linkedAppIds[$appObjectId] = $true }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $addPriority = {
        param($ObjectId,$ObjectName,$Target,$Portal,$Items,$RelatedAppId)
        $itemsArray = @($Items | Where-Object { $null -ne $_ })
        if ($itemsArray.Count -eq 0) { return }
        $ruleIds = @($itemsArray | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'RuleId') } | Sort-Object -Unique)
        $categories = @($itemsArray | ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Category') } | Where-Object { $_ } | Sort-Object -Unique)
        $highest = @($itemsArray | Sort-Object @{Expression={ Get-AppExposureSeverityRank -Severity ([string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity')) };Descending=$true}, RuleId)[0]
        $highestSeverity = [string](Get-AppExposurePropertyValue -Object $highest -Name 'Severity')

        $hasSensitive = @($ruleIds | Where-Object { $_ -in @('EAE-OAUTH-APP-001','EAE-OAUTH-DEL-001','EAE-OAUTH-DEL-002') }).Count -gt 0
        $hasWeakOwnership = @($ruleIds | Where-Object { $_ -in @('EAE-EXPOSURE-002','EAE-EXPOSURE-003','EAE-EXPOSURE-007','EAE-SP-OWNER-001','EAE-APP-OWNER-001') }).Count -gt 0
        $hasCredentialExposure = @($ruleIds | Where-Object { $_ -in @('EAE-EXPOSURE-001','EAE-EXPOSURE-006','EAE-APP-CRED-003','EAE-APP-CRED-004','EAE-APP-ORPHAN-001') }).Count -gt 0
        $hasTrustExposure = $ruleIds -contains 'EAE-EXPOSURE-005'
        $hasStateExposure = @($ruleIds | Where-Object { $_ -in @('EAE-SP-STATE-001','EAE-SP-STATE-002') }).Count -gt 0
        $hasAuthExposure = @($ruleIds | Where-Object { $_ -in @('EAE-APP-AUTH-001','EAE-APP-AUTH-002','EAE-APP-AUTH-003','EAE-APP-API-001') }).Count -gt 0

        $priority = 'P3'
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($hasSensitive -and $hasWeakOwnership -and $hasCredentialExposure) {
            $priority = 'P0'
            $reasons.Add('sensitive OAuth access')
            $reasons.Add('weak ownership/accountability')
            $reasons.Add('credential exposure')
        }
        elseif (($hasSensitive -and ($hasWeakOwnership -or $hasCredentialExposure -or $hasTrustExposure -or $hasStateExposure -or $hasAuthExposure)) -or ($ruleIds -contains 'EAE-EXPOSURE-006')) {
            $priority = 'P1'
            if ($hasSensitive) { $reasons.Add('sensitive OAuth access') }
            if ($hasWeakOwnership) { $reasons.Add('weak ownership/accountability') }
            if ($hasCredentialExposure) { $reasons.Add('credential exposure') }
            if ($hasTrustExposure) { $reasons.Add('unverified third-party trust') }
            if ($hasStateExposure) { $reasons.Add('identity-state exposure') }
            if ($hasAuthExposure) { $reasons.Add('authentication/API configuration exposure') }
        }
        elseif ((Get-AppExposureSeverityRank -Severity $highestSeverity) -ge (Get-AppExposureSeverityRank -Severity 'Medium') -or $itemsArray.Count -gt 1) {
            $priority = 'P2'
            $reasons.Add('actionable findings require planned review')
        }
        else {
            $priority = 'P3'
            $reasons.Add('lower-severity actionable exposure')
        }
        if ($reasons.Count -eq 0) { $reasons.Add('actionable exposure correlation') }

        $rows.Add([PSCustomObject]@{
            Priority          = $priority
            PriorityRank      = Get-AppExposurePriorityRank -Priority $priority
            ObjectId          = $ObjectId
            ObjectDisplayName = $ObjectName
            Target            = $Target
            Portal            = $Portal
            RelatedApplicationObjectId = $RelatedAppId
            HighestSeverity   = $highestSeverity
            SeverityRank      = Get-AppExposureSeverityRank -Severity $highestSeverity
            FindingCount      = $itemsArray.Count
            CategoryText      = ($categories -join ', ')
            Reason            = ($reasons -join ' + ')
            FindingId         = [string](Get-AppExposurePropertyValue -Object $highest -Name 'FindingId')
            RuleIds           = $ruleIds
        })
    }

    foreach ($sp in @($ServicePrincipals)) {
        $spId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'ObjectId')
        if (-not $spId) { continue }
        $family = [System.Collections.Generic.List[object]]::new()
        if ($byObject.ContainsKey($spId)) { foreach ($item in $byObject[$spId]) { $family.Add($item) } }
        $appObjectId = [string](Get-AppExposurePropertyValue -Object $sp -Name 'AppRegistrationObjectId')
        if ($appObjectId -and $byObject.ContainsKey($appObjectId)) { foreach ($item in $byObject[$appObjectId]) { $family.Add($item) } }
        $name = [string](Get-AppExposurePropertyValue -Object $sp -Name 'DisplayName')
        $target = if ($ObjectTypeById.ContainsKey($spId)) { [string]$ObjectTypeById[$spId] } else { 'Service principal' }
        $portal = if ($ObjectPortalUrlById.ContainsKey($spId)) { [string]$ObjectPortalUrlById[$spId] } else { $null }
        & $addPriority $spId $name $target $portal $family.ToArray() $appObjectId
    }

    foreach ($app in @($Applications)) {
        $appId = [string](Get-AppExposurePropertyValue -Object $app -Name 'ObjectId')
        if (-not $appId -or $linkedAppIds.ContainsKey($appId) -or -not $byObject.ContainsKey($appId)) { continue }
        $name = [string](Get-AppExposurePropertyValue -Object $app -Name 'DisplayName')
        $target = if ($ObjectTypeById.ContainsKey($appId)) { [string]$ObjectTypeById[$appId] } else { 'App registration' }
        $portal = if ($ObjectPortalUrlById.ContainsKey($appId)) { [string]$ObjectPortalUrlById[$appId] } else { $null }
        & $addPriority $appId $name $target $portal $byObject[$appId].ToArray() $null
    }

    return @($rows.ToArray() | Sort-Object @{Expression='PriorityRank';Descending=$true}, @{Expression='SeverityRank';Descending=$true}, @{Expression='FindingCount';Descending=$true}, ObjectDisplayName)
}

function New-AppExposureFindingGroups {
    param([Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Findings = @())

    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($bucket in @(@($Findings) | Group-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'RuleId') })) {
        $items = @($bucket.Group)
        # A grouped finding is useful only when a rule has multiple concrete instances.
        if ($items.Count -lt 2) { continue }

        $first = $items[0]
        $ruleId = [string](Get-AppExposurePropertyValue -Object $first -Name 'RuleId')
        $affected = [System.Collections.Generic.List[object]]::new()

        foreach ($objectBucket in @($items | Group-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') })) {
            $objectItems = @($objectBucket.Group)
            if ($objectItems.Count -eq 0) { continue }
            $objectId = [string](Get-AppExposurePropertyValue -Object $objectItems[0] -Name 'ObjectId')
            if ([string]::IsNullOrWhiteSpace($objectId)) { continue }

            $objectFindingIds = @(
                $objectItems |
                ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'FindingId') } |
                Where-Object { $_ } |
                Sort-Object -Unique
            )
            $objectEvidenceIds = @(
                $objectItems |
                ForEach-Object { @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceIds')) } |
                ForEach-Object { [string]$_ } |
                Where-Object { $_ } |
                Sort-Object -Unique
            )
            $objectEvidenceSummary = @(
                $objectItems |
                ForEach-Object { @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceSummary')) } |
                ForEach-Object { [string]$_ } |
                Where-Object { $_ } |
                Sort-Object -Unique
            )
            $affected.Add([PSCustomObject]@{
                ObjectId          = $objectId
                ObjectDisplayName = [string](Get-AppExposurePropertyValue -Object $objectItems[0] -Name 'ObjectDisplayName')
                FindingId         = if ($objectFindingIds.Count -gt 0) { $objectFindingIds[0] } else { $null }
                FindingIds        = $objectFindingIds
                EvidenceIds       = $objectEvidenceIds
                EvidenceSummary   = $objectEvidenceSummary
            })
        }

        $evidenceIds = @(
            $items |
            ForEach-Object { @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceIds')) } |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ } |
            Sort-Object -Unique
        )
        $evidenceSummary = @(
            $items |
            ForEach-Object { @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceSummary')) } |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ } |
            Sort-Object -Unique
        )
        $findingIds = @(
            $items |
            ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'FindingId') } |
            Where-Object { $_ } |
            Sort-Object -Unique
        )
        $groupHash = Get-AppExposureSha256 -Text $ruleId
        $groups.Add([PSCustomObject]@{
            FindingGroupId      = "GRP-$($groupHash.Substring(0, 16))"
            RuleId              = $ruleId
            Severity            = [string](Get-AppExposurePropertyValue -Object $first -Name 'Severity')
            Category            = [string](Get-AppExposurePropertyValue -Object $first -Name 'Category')
            Title               = [string](Get-AppExposurePropertyValue -Object $first -Name 'Title')
            FindingCount        = $items.Count
            AffectedObjectCount = $affected.Count
            AffectedObjects     = @($affected.ToArray())
            FindingIds          = $findingIds
            EvidenceIds         = $evidenceIds
            EvidenceSummary     = $evidenceSummary
            WhyItMatters        = [string](Get-AppExposurePropertyValue -Object $first -Name 'WhyItMatters')
            Recommendation      = [string](Get-AppExposurePropertyValue -Object $first -Name 'Recommendation')
            References          = @((Get-AppExposurePropertyValue -Object $first -Name 'References'))
        })
    }

    return @(
        $groups.ToArray() |
        Sort-Object @{Expression={ Get-AppExposureSeverityRank -Severity ([string]$_.Severity) };Descending=$true},
                    @{Expression='FindingCount';Descending=$true},
                    RuleId
    )
}

function New-AppExposureFindingGroupHtml {
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $false)][string]$EvidenceFileName = 'evidence.html',
        [Parameter(Mandatory = $false)][hashtable]$ObjectPortalUrlById = @{},
        [Parameter(Mandatory = $false)][hashtable]$ObjectSpClassificationById = @{}
    )

    $groupId = [string](Get-AppExposurePropertyValue -Object $Group -Name 'FindingGroupId')
    $ruleId = [string](Get-AppExposurePropertyValue -Object $Group -Name 'RuleId')
    $severity = [string](Get-AppExposurePropertyValue -Object $Group -Name 'Severity')
    $category = [string](Get-AppExposurePropertyValue -Object $Group -Name 'Category')
    $title = [string](Get-AppExposurePropertyValue -Object $Group -Name 'Title')
    $findingCount = [int](Get-AppExposurePropertyValue -Object $Group -Name 'FindingCount')
    $affected = @((Get-AppExposurePropertyValue -Object $Group -Name 'AffectedObjects'))
    $why = [string](Get-AppExposurePropertyValue -Object $Group -Name 'WhyItMatters')
    $recommendation = [string](Get-AppExposurePropertyValue -Object $Group -Name 'Recommendation')
    $references = @((Get-AppExposurePropertyValue -Object $Group -Name 'References'))
    $evidenceIds = @((Get-AppExposurePropertyValue -Object $Group -Name 'EvidenceIds'))
    $evidenceSummary = @((Get-AppExposurePropertyValue -Object $Group -Name 'EvidenceSummary'))
    $severityClass = Get-AppExposureReportSeverityClass -Severity $severity

    $spClassifications = @(
        $affected |
        ForEach-Object {
            $id = [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId')
            if ($ObjectSpClassificationById.ContainsKey($id)) {
                @(([string]$ObjectSpClassificationById[$id]) -split '\|')
            }
        } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

    $what = "This rule matched $findingCount finding(s) across $($affected.Count) distinct assessed identity/identities."
    $search = ConvertTo-AppExposureReportSearchAttribute -Values @(
        $groupId,$ruleId,$severity,$category,$title,$what,$why,$recommendation,
        $affected.ObjectDisplayName,$affected.ObjectId,$evidenceSummary,$evidenceIds,$spClassifications
    )

    $affectedPreview = @(
        $affected | Select-Object -First 25 | ForEach-Object {
            $objectId = [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId')
            $objectName = [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectDisplayName')
            $findingId = [string](Get-AppExposurePropertyValue -Object $_ -Name 'FindingId')
            $objectEvidenceIds = @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceIds'))
            $portal = if ($ObjectPortalUrlById.ContainsKey($objectId)) { [string]$ObjectPortalUrlById[$objectId] } else { $null }
            $portalLink = if ($portal) { ' · <a href="' + (ConvertTo-AppExposureReportHtml $portal) + '" target="_blank" rel="noopener noreferrer">Open in Entra</a>' } else { '' }
            $findingLink = if ($findingId) { '<a href="#finding-' + (ConvertTo-AppExposureReportHtml $findingId) + '">' + (ConvertTo-AppExposureReportHtml $objectName) + '</a>' } else { ConvertTo-AppExposureReportHtml $objectName }
            '<li>' + $findingLink + ' · <code>' + (ConvertTo-AppExposureReportHtml $objectId) + '</code>' + $portalLink + ' <span class="pill status-default">' + $objectEvidenceIds.Count + ' evidence ref(s)</span></li>'
        }
    ) -join ''
    $remaining = [Math]::Max(0, $affected.Count - 25)
    $more = if ($remaining -gt 0) {
        '<p class="muted">+' + $remaining + ' additional affected identities. Use the Individual entry filter for the complete per-identity list.</p>'
    } else { '' }

    $summaryPreview = @($evidenceSummary | Select-Object -First 20)
    $summaryItems = if ($summaryPreview.Count -gt 0) {
        @($summaryPreview | ForEach-Object { '<li>' + (ConvertTo-AppExposureReportHtml $_) + '</li>' }) -join ''
    } else {
        '<li>No additional evidence summary was supplied.</li>'
    }
    $remainingSummary = [Math]::Max(0, $evidenceSummary.Count - $summaryPreview.Count)
    $summaryMore = if ($remainingSummary -gt 0) {
        '<p class="muted">+' + $remainingSummary + ' additional evidence summary item(s); open an individual finding for full identity-specific context.</p>'
    } else { '' }

    $evidencePreviewIds = @($evidenceIds | Select-Object -First 30)
    $evidenceLinks = @(
        $evidencePreviewIds | ForEach-Object {
            $evidenceId = [string]$_
            '<a class="pill status-default" href="' + (ConvertTo-AppExposureReportHtml $EvidenceFileName) + '#evidence-' + (ConvertTo-AppExposureReportHtml $evidenceId) + '">' + (ConvertTo-AppExposureReportHtml $evidenceId) + '</a>'
        }
    ) -join ''
    if ([string]::IsNullOrWhiteSpace($evidenceLinks)) {
        $evidenceLinks = '<span class="pill status-default">No ObservationIds</span>'
    }
    $remainingEvidence = [Math]::Max(0, $evidenceIds.Count - $evidencePreviewIds.Count)
    $evidenceMore = if ($remainingEvidence -gt 0) {
        '<span class="muted">+' + $remainingEvidence + ' additional observation reference(s); open an individual finding for the complete identity-specific evidence set.</span>'
    } else { '' }

    $referenceLinks = if ($references.Count -gt 0) {
        @($references | Where-Object { $_ } | ForEach-Object {
            '<a href="' + (ConvertTo-AppExposureReportHtml $_) + '" target="_blank" rel="noopener noreferrer">Microsoft Learn</a>'
        }) -join ' · '
    } else { '' }

    return @"
<article id="$(ConvertTo-AppExposureReportHtml $groupId)" class="finding-card finding-group-card" data-severity="$(ConvertTo-AppExposureReportHtml $severity)" data-category="$(ConvertTo-AppExposureReportHtml $category)" data-kind="Grouped" data-sp-classifications="$(ConvertTo-AppExposureReportHtml ($spClassifications -join '|'))" data-search="$search">
  <div class="finding-top">
    <div>
      <div class="finding-category">$(ConvertTo-AppExposureReportHtml $category) · Grouped finding</div>
      <div class="finding-title">$(ConvertTo-AppExposureReportHtml $title)</div>
      <div class="object-line">$($affected.Count) affected identity/identities · $findingCount underlying finding(s)</div>
    </div>
    <div class="pill-row"><span class="pill $severityClass">$(ConvertTo-AppExposureReportHtml $severity)</span><span class="pill grouped-tag">Grouped</span><span class="pill status-default">$(ConvertTo-AppExposureReportHtml $ruleId)</span></div>
  </div>
  <div class="finding-summary-grid">
    <div class="finding-summary-item"><span class="field-label">What happened</span><span class="field-value">$(ConvertTo-AppExposureReportHtml $what)</span></div>
    <div class="finding-summary-item"><span class="field-label">Why it matters</span><span class="field-value">$(ConvertTo-AppExposureReportHtml $why)</span></div>
  </div>
  <div class="finding-action"><strong>Recommended action:</strong> $(ConvertTo-AppExposureReportHtml $recommendation)</div>
  $(if ($referenceLinks) { '<div class="object-line"><strong>Rule reference:</strong> ' + $referenceLinks + '</div>' } else { '' })
  <details class="finding-technical evidence">
    <summary>Evidence · $($evidenceIds.Count) observation reference(s) across $($affected.Count) affected identity/identities</summary>
    <span class="field-label grouped-evidence-label">Evidence summary</span>
    <ul class="evidence-list">$summaryItems</ul>
    $summaryMore
    <span class="field-label grouped-evidence-label">Affected identities</span>
    <ul class="evidence-list compact-list">$affectedPreview</ul>
    $more
    <span class="field-label grouped-evidence-label">Observation references</span>
    <div class="evidence-links">$evidenceLinks</div>
    $evidenceMore
    <div class="finding-meta"><span class="pill status-default">Finding group ID: $(ConvertTo-AppExposureReportHtml $groupId)</span><span class="pill status-default">$findingCount underlying finding(s)</span></div>
  </details>
</article>
"@
}

function New-AppExposureFindingSankeyHtml {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Findings = @(),
        [Parameter(Mandatory = $false)][hashtable]$ObjectTypeById = @{}
    )
    $actionable = @($Findings | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity') -ne 'Informational' })
    if ($actionable.Count -eq 0) { return '<p class="empty-state">No actionable findings are available for the finding flow.</p>' }

    $flowMap = @{}
    foreach ($finding in $actionable) {
        $severity = [string](Get-AppExposurePropertyValue -Object $finding -Name 'Severity')
        $category = [string](Get-AppExposurePropertyValue -Object $finding -Name 'Category')
        $objectId = [string](Get-AppExposurePropertyValue -Object $finding -Name 'ObjectId')
        $target = if ($ObjectTypeById.ContainsKey($objectId)) { [string]$ObjectTypeById[$objectId] } else { 'Unknown identity' }
        if ([string]::IsNullOrWhiteSpace($category)) { $category = 'Other' }
        $key = "$severity|$category|$target"
        if (-not $flowMap.ContainsKey($key)) { $flowMap[$key] = [PSCustomObject]@{ Severity=$severity; Category=$category; Target=$target; Count=0 } }
        $flowMap[$key].Count++
    }
    $flows = @($flowMap.Values | Sort-Object @{Expression='Count';Descending=$true}, Severity, Category, Target)
    if ($flows.Count -eq 0) { return '<p class="empty-state">No actionable finding flow is available.</p>' }

    # Node counts must represent findings, not the number of distinct flow buckets.
    $left = @($flows | Group-Object Severity | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Count=[int](($_.Group | Measure-Object Count -Sum).Sum) }
    } | Sort-Object @{Expression={ Get-AppExposureSeverityRank -Severity $_.Name };Descending=$true})
    $middle = @($flows | Group-Object Category | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Count=[int](($_.Group | Measure-Object Count -Sum).Sum) }
    } | Sort-Object @{Expression='Count';Descending=$true}, Name)
    $right = @($flows | Group-Object Target | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Count=[int](($_.Group | Measure-Object Count -Sum).Sum) }
    } | Sort-Object @{Expression='Count';Descending=$true}, Name)
    $positions = @{}
    $nodeHeight = 28
    $gap = 8
    $maxNodeCount = [Math]::Max($left.Count, [Math]::Max($middle.Count, $right.Count))
    $height = [Math]::Max(360, (($maxNodeCount * ($nodeHeight + $gap)) + 24))
    $columns = @(
        [PSCustomObject]@{ Prefix='L'; X=18; Items=$left },
        [PSCustomObject]@{ Prefix='M'; X=415; Items=$middle },
        [PSCustomObject]@{ Prefix='R'; X=812; Items=$right }
    )
    foreach ($column in $columns) {
        $items = @($column.Items)
        $totalHeight = ($items.Count * $nodeHeight) + ([Math]::Max(0,$items.Count-1) * $gap)
        $y = [Math]::Max(12, [int](($height - $totalHeight) / 2))
        foreach ($item in $items) {
            $positions["$($column.Prefix):$($item.Name)"] = [PSCustomObject]@{ X=[int]$column.X; Y=[int]$y; W=150; H=$nodeHeight; Count=[int]$item.Count }
            $y += $nodeHeight + $gap
        }
    }
    $maxFlow = [Math]::Max(1, [int](($flows | Measure-Object Count -Maximum).Maximum))
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($flow in $flows) {
        $a=$positions["L:$($flow.Severity)"]; $m=$positions["M:$($flow.Category)"]; $b=$positions["R:$($flow.Target)"]
        $width=[int][Math]::Max(2,[Math]::Min(16,[Math]::Round(2 + (14 * ([double]$flow.Count / $maxFlow)))))
        $severityClass = 'sankey-' + ([string]$flow.Severity).ToLowerInvariant()
        $y1=$a.Y+[int]($a.H/2); $ym=$m.Y+[int]($m.H/2); $y2=$b.Y+[int]($b.H/2)
        $c1=[int](($a.X+$a.W+$m.X)/2); $c2=[int](($m.X+$m.W+$b.X)/2)
        $title = ConvertTo-AppExposureReportHtml ("$($flow.Severity) → $($flow.Category) → $($flow.Target): $($flow.Count)")
        $parts.Add('<path class="sankey-link ' + $severityClass + '" d="M ' + ($a.X+$a.W) + ' ' + $y1 + ' C ' + $c1 + ' ' + $y1 + ', ' + $c1 + ' ' + $ym + ', ' + $m.X + ' ' + $ym + '" stroke-width="' + $width + '"><title>' + $title + '</title></path>')
        $parts.Add('<path class="sankey-link ' + $severityClass + '" d="M ' + ($m.X+$m.W) + ' ' + $ym + ' C ' + $c2 + ' ' + $ym + ', ' + $c2 + ' ' + $y2 + ', ' + $b.X + ' ' + $y2 + '" stroke-width="' + $width + '"><title>' + $title + '</title></path>')
    }
    foreach ($key in @($positions.Keys | Sort-Object)) {
        $pos=$positions[$key]; $label=$key.Substring(2); $display=$label; if ($display.Length -gt 23) { $display=$display.Substring(0,22)+'…' }
        $parts.Add('<g class="sankey-node"><rect x="' + $pos.X + '" y="' + $pos.Y + '" width="' + $pos.W + '" height="' + $pos.H + '"></rect><text x="' + ($pos.X+7) + '" y="' + ($pos.Y+18) + '">' + (ConvertTo-AppExposureReportHtml $display) + '</text><text class="sankey-count" x="' + ($pos.X+$pos.W-7) + '" y="' + ($pos.Y+18) + '" text-anchor="end">' + $pos.Count + '</text><title>' + (ConvertTo-AppExposureReportHtml $label) + ': ' + $pos.Count + '</title></g>')
    }
    return '<div class="sankey-wrap"><svg class="finding-sankey" viewBox="0 0 980 ' + $height + '" style="height:' + $height + 'px" role="img" aria-label="Actionable finding flow from severity to category to identity type">' + ($parts -join '') + '</svg></div>'
}

function Get-AppExposureFileSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}


<#
.SYNOPSIS
    Versioned internal HTML presentation primitives for the Entra App Exposure.

.DESCRIPTION
    Contains only reusable presentation concerns: safe HTML encoding, Fluent-inspired
    report styling, status/severity classes, finding/evidence filtering behavior, and
    the self-contained document shell. It contains no external service calls,
    assessment rules, artifact export logic, or product-specific assessment data model.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AppExposureReportUiVersion = '1.4.1'

function Get-AppExposureReportUiVersion { return $script:AppExposureReportUiVersion }

function ConvertTo-AppExposureReportHtml {
    param([Parameter(Mandatory = $false)]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-AppExposureReportSearchAttribute {
    param([Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Values = @())
    $text = @($Values | ForEach-Object { if ($null -ne $_) { [string]$_ } } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
    return ConvertTo-AppExposureReportHtml ($text.ToLowerInvariant())
}

function ConvertTo-AppExposureReportEvidenceJson {
    param([Parameter(Mandatory = $false)]$Value)
    if ($null -eq $Value) { return '' }
    try { return ConvertTo-AppExposureReportHtml (ConvertTo-Json -InputObject $Value -Depth 15) }
    catch { return ConvertTo-AppExposureReportHtml ([string]$Value) }
}

function Get-AppExposureReportSeverityClass {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 'severity-critical' }
        'High' { return 'severity-high' }
        'Medium' { return 'severity-medium' }
        'Low' { return 'severity-low' }
        'Informational' { return 'severity-info' }
        default { return 'status-default' }
    }
}

function Get-AppExposureReportStatusClass {
    param([AllowNull()]$Value)
    $text = [string]$Value
    switch -Regex ($text) {
        '^(True|Complete|Success)$' { return 'status-success' }
        '^(False|Failed|Incomplete|Partial|Error)$' { return 'status-danger' }
        '^(Unknown|Unavailable|NotCollected)$' { return 'status-warning' }
        default { return 'status-default' }
    }
}

function Get-AppExposureReportCss {
    return @'
:root {
  color-scheme: light;
  --font: "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,BlinkMacSystemFont,Arial,sans-serif;
  --radius: 8px;
  --radius-sm: 4px;
  --bg: #f5f5f5;
  --panel: #ffffff;
  --panel-soft: #fafafa;
  --panel-strong: #f0f0f0;
  --text: #242424;
  --muted: #616161;
  --faint: #707070;
  --line: #d1d1d1;
  --line-soft: #e0e0e0;
  --brand: #0f6cbd;
  --brand-hover: #115ea3;
  --brand-pressed: #0c3b5e;
  --brand-soft: #ebf3fc;
  --critical: #a4262c;
  --high: #c50f1f;
  --medium: #8a4b08;
  --low: #0f6cbd;
  --info: #0078d4;
  --success: #107c10;
  --critical-bg: #fdf3f4;
  --high-bg: #fdf3f4;
  --medium-bg: #fff8f0;
  --low-bg: #f0f6fc;
  --info-bg: #f0f6fc;
  --success-bg: #f1faf1;
  --highlight-bg: #fff4ce;
  --highlight-text: #242424;
  --highlight-border: #c19c00;
  --shadow: 0 1.6px 3.6px rgba(0,0,0,.132), 0 .3px .9px rgba(0,0,0,.108);
}
[data-theme="dark"] {
  color-scheme: dark;
  --bg: #1f1f1f;
  --panel: #292929;
  --panel-soft: #242424;
  --panel-strong: #333333;
  --text: #ffffff;
  --muted: #d6d6d6;
  --faint: #adadad;
  --line: #666666;
  --line-soft: #424242;
  --brand: #479ef5;
  --brand-hover: #62abf5;
  --brand-pressed: #77b7f7;
  --brand-soft: #0e4775;
  --critical: #ff99a4;
  --high: #ff99a4;
  --medium: #fce100;
  --low: #62abf5;
  --info: #62abf5;
  --success: #54b054;
  --critical-bg: #442726;
  --high-bg: #442726;
  --medium-bg: #4a3d16;
  --low-bg: #0e4775;
  --info-bg: #0e4775;
  --success-bg: #163b16;
  --highlight-bg: #8a6a00;
  --highlight-text: #ffffff;
  --highlight-border: #fce100;
  --shadow: 0 2px 8px rgba(0,0,0,.45);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: 14px;
  line-height: 1.5;
  background: var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}
a { color: var(--brand); text-underline-offset: 2px; }
a:hover { color: var(--brand-hover); }
a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}
code, pre { font-family: Consolas,"Cascadia Code",monospace; }
.shell { max-width: 1180px; margin: 0 auto; padding: 24px 24px 72px; }
.hero { background: var(--panel); border-bottom: 1px solid var(--line-soft); }
.hero-grid {
  max-width: 1180px;
  margin: 0 auto;
  padding: 20px 24px 18px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 20px;
  align-items: start;
}
.brand-lockup { display:flex; align-items:center; gap:10px; }
.project-mark { width:24px; height:24px; display:inline-flex; align-items:center; justify-content:center; border:1px solid var(--line); border-radius:6px; background:var(--panel-soft); color:var(--brand); font-size:9px; font-weight:800; letter-spacing:.3px; flex:0 0 auto; }
.brand-accent { width:4px; height:28px; border-radius:2px; background:var(--brand); flex:0 0 auto; }
.brand { color: var(--muted); font-size: 12px; font-weight: 600; letter-spacing: .15px; }
.product-label { color: var(--text); font-size: 13px; font-weight: 600; }
h1 { margin: 5px 0 6px; font-size: 24px; line-height: 1.25; font-weight: 600; letter-spacing: -.2px; }
h2 { margin: 0 0 12px; font-size: 20px; line-height: 1.3; font-weight: 600; }
h3 { margin: 0; font-size: 15px; line-height: 1.35; font-weight: 600; }
.hero p, .subtitle { margin: 6px 0 0; max-width: 760px; color: var(--muted); }
.hero-meta, .finding-meta, .pill-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
.pill-row { margin-top: 0; }
.toolbar { display: flex; flex-wrap: wrap; gap: 6px; justify-content: end; }
button, .filter-button, .open-btn, .nav-button {
  min-height: 32px;
  border: 1px solid var(--line);
  background: var(--panel);
  color: var(--text);
  border-radius: var(--radius-sm);
  padding: 5px 10px;
  font: inherit;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
}
button:hover, .filter-button:hover, .filter-button.is-active, .open-btn:hover, .nav-button:hover {
  border-color: var(--brand);
  color: var(--brand-hover);
  background: var(--brand-soft);
}
.primary-link { background:var(--brand); border-color:var(--brand); color:#fff; }
.primary-link:hover { background:var(--brand-hover); border-color:var(--brand-hover); color:#fff; }
#themeToggle { white-space: nowrap; }
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 3px 8px;
  font-size: 11.5px;
  font-weight: 600;
  border: 1px solid var(--line);
  white-space: nowrap;
}
.severity-critical { background: var(--critical-bg); color: var(--critical); border-color: var(--critical); }
.severity-high, .status-danger { background: var(--high-bg); color: var(--high); border-color: var(--high); }
.severity-medium, .status-warning { background: var(--medium-bg); color: var(--medium); border-color: var(--medium); }
.severity-low, .status-info { background: var(--low-bg); color: var(--low); border-color: var(--low); }
.severity-info { background: var(--info-bg); color: var(--info); border-color: var(--info); }
.status-success { background: var(--success-bg); color: var(--success); border-color: var(--success); }
.status-default { background: var(--panel-strong); color: var(--muted); }
.metric-grid, .metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:10px; margin:14px 0 0; }
.metric, .metric-card, .finding-card, .context-panel, .technical-panel, .category-card, .trust-box, .card, .evidence-card {
  background: var(--panel);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.metric, .metric-card { padding: 12px 14px; border-top: 3px solid var(--line-soft); }
.metric.severity-critical, .metric-card.severity-critical { border-top-color:var(--critical); }
.metric.severity-high, .metric-card.severity-high { border-top-color:var(--high); }
.metric.severity-medium, .metric-card.severity-medium { border-top-color:var(--medium); }
.metric.severity-low, .metric-card.severity-low, .metric.status-info, .metric-card.status-info { border-top-color:var(--low); }
.metric.status-success, .metric-card.status-success { border-top-color:var(--success); }
.metric-label { color: var(--muted); font-size: 11.5px; font-weight: 600; }
.metric-value { margin-top: 2px; font-size: 22px; font-weight: 600; }
.metric-hint { margin-top: 4px; color: var(--faint); font-size: 12px; }
.section { margin: 0 0 30px; }
.section-header { display:flex; justify-content:space-between; gap:12px; align-items:baseline; margin-bottom:10px; }
.section-intro { margin:-4px 0 12px; color:var(--muted); max-width:850px; }
.muted { color: var(--muted); }
.faint { color: var(--faint); }
.empty, .empty-state { margin:0; padding:14px; color:var(--muted); background:var(--panel); border:1px dashed var(--line); border-radius:var(--radius); }
.report-section > details { background:var(--panel); border:1px solid var(--line-soft); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; }
.section-summary { display:flex; justify-content:space-between; gap:16px; align-items:center; cursor:pointer; padding:14px 16px; font-weight:600; }
.section-summary::marker { color:var(--brand); }
.summary-hint { color:var(--muted); font-size:12px; font-weight:400; }
.section-body { padding:0 16px 16px; border-top:1px solid var(--line-soft); }
.filter-row { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px; }
.investigation-bar, .filters { display:grid; grid-template-columns:minmax(280px,1fr) minmax(160px,.35fr) auto; gap:8px; margin-bottom:10px; }
.investigation-bar input, .investigation-bar select, .filters input, .filters select, .filter {
  min-height:34px;
  border:1px solid var(--line);
  border-radius:var(--radius-sm);
  background:var(--panel);
  color:var(--text);
  padding:6px 9px;
  font:inherit;
}
.filter { margin:0 0 14px; width:100%; }
.finding-list { display:grid; gap:12px; }
.finding-card { padding:16px 18px; border-left:4px solid var(--line); }
.finding-card[data-severity="Critical"] { border-left-color:var(--critical); }
.finding-card[data-severity="High"] { border-left-color:var(--high); }
.finding-card[data-severity="Medium"] { border-left-color:var(--medium); }
.finding-card[data-severity="Low"] { border-left-color:var(--low); }
.finding-card[data-severity="Informational"] { border-left-color:var(--info); }
.finding-card[hidden], .evidence-card[hidden] { display:none; }
.finding-top { display:flex; justify-content:space-between; gap:12px; align-items:start; }
.finding-category { color:var(--muted); font-size:12px; }
.finding-title { margin:10px 0 12px; font-size:17px; font-weight:600; }
.object-line { color:var(--muted); font-size:12.5px; word-break:break-word; }
.finding-summary-grid, .explain-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin:0 0 12px; }
.finding-summary-item, .explain { padding:10px 12px; background:var(--panel-soft); border:1px solid var(--line-soft); border-radius:var(--radius-sm); }
.field-label, .explain strong { display:block; margin-bottom:3px; color:var(--muted); font-size:11.5px; font-weight:600; }
.field-value { color:var(--text); font-size:13px; }
.finding-action { margin-top:12px; padding:11px 12px; background:var(--brand-soft); border-left:3px solid var(--brand); border-radius:var(--radius-sm); font-size:13px; }
.finding-technical { margin-top:12px; border-top:1px solid var(--line-soft); padding-top:10px; }
.finding-technical > summary, details.evidence > summary, .finding-card details > summary { cursor:pointer; color:var(--brand); font-weight:600; font-size:12.5px; }
details.evidence { margin-top:10px; }
.evidence-list, .evidence-summary { margin:9px 0 0; padding:10px 12px 10px 26px; color:var(--muted); font-size:12.5px; background:var(--panel-soft); border:1px solid var(--line-soft); border-radius:var(--radius-sm); }
.evidence-links { display:flex; flex-wrap:wrap; gap:6px; margin-top:9px; }
.evidence-links a { text-decoration:none; }
.context-grid, .trust-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px; }
.context-panel, .trust-box { padding:14px 16px; }
.context-panel h3, .trust-box h3 { margin-bottom:4px; }
.context-count { font-size:24px; font-weight:600; color:var(--brand); }
.context-copy { margin:2px 0 10px; color:var(--muted); font-size:12.5px; }
.context-list { margin-top:12px; }
.technical-links { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 14px; }
.posture-banner { display:flex; justify-content:space-between; gap:16px; align-items:center; padding:14px 16px; margin-bottom:12px; background:var(--panel); border:1px solid var(--line-soft); border-left:4px solid var(--brand); border-radius:var(--radius); box-shadow:var(--shadow); }
.posture-banner.critical { border-left-color:var(--critical); }
.posture-banner.high { border-left-color:var(--high); }
.posture-banner.medium { border-left-color:var(--medium); }
.posture-banner.low { border-left-color:var(--low); }
.posture-label { font-size:16px; font-weight:600; }
.posture-text { color:var(--muted); margin-top:2px; font-size:12.5px; }
.card { padding:14px 16px; margin:0 0 12px; }
.data-table { width:100%; border-collapse:collapse; font-size:12.5px; }
.table-wrap { overflow-x:auto; border:1px solid var(--line-soft); border-radius:var(--radius-sm); }
th, td { text-align:left; border-bottom:1px solid var(--line-soft); padding:8px 9px; vertical-align:top; }
th { color:var(--muted); background:var(--panel-strong); font-weight:600; }
tbody tr:last-child td { border-bottom:0; }
tbody tr:hover { background:var(--panel-soft); }
.evidence-index { display:grid; gap:10px; }
.evidence-card { padding:14px 16px; }
.evidence-card:target { outline:2px solid var(--brand); outline-offset:2px; }
.evidence-card h3 { margin-bottom:5px; }
.evidence-meta { display:flex; flex-wrap:wrap; gap:7px; margin-bottom:8px; }
.raw-evidence { margin:10px 0 0; padding:10px 12px; background:var(--panel-soft); border:1px solid var(--line-soft); border-radius:var(--radius-sm); white-space:pre-wrap; word-break:break-word; overflow:auto; font-size:12px; max-height:330px; }
.footer { color:var(--muted); text-align:center; font-size:12px; padding:20px 24px 28px; }
.report-nav { display:flex; flex-wrap:wrap; gap:6px; align-items:center; justify-content:flex-end; }
.report-nav .pill { text-decoration:none; border-radius:var(--radius-sm); padding:5px 9px; }
.report-nav .is-active { border-color:var(--brand); color:var(--brand); background:var(--brand-soft); }
.visual-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.viz-card { background:var(--panel); border:1px solid var(--line-soft); border-radius:var(--radius); box-shadow:var(--shadow); padding:14px 16px; }
.viz-card h3 { margin-bottom:3px; }
.viz-subtitle { margin:0 0 12px; color:var(--muted); font-size:12px; }
.bar-chart { display:grid; gap:10px; }
.bar-row { min-width:0; }
.bar-meta { display:flex; justify-content:space-between; gap:12px; margin-bottom:4px; font-size:12px; }
.bar-meta span { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--muted); }
.bar-meta strong { flex:0 0 auto; }
.bar-track { height:7px; overflow:hidden; background:var(--panel-strong); border-radius:999px; }
.bar-fill { display:block; height:100%; min-width:2px; border-radius:999px; background:var(--brand); }
.bar-fill.bar-critical { background:var(--critical); }
.bar-fill.bar-high { background:var(--high); }
.bar-fill.bar-medium { background:var(--medium); }
.bar-fill.bar-low, .bar-fill.bar-info, .bar-fill.bar-brand { background:var(--brand); }
.bar-fill.bar-success { background:var(--success); }
.pagination-controls { display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:space-between; margin-top:14px; padding-top:12px; border-top:1px solid var(--line-soft); }
.pagination-main, .pagination-size { display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
.pagination-pages { display:flex; flex-wrap:wrap; gap:4px; }
.pagination-pages button { min-width:32px; padding-left:8px; padding-right:8px; }
.pagination-pages button.is-active { background:var(--brand); border-color:var(--brand); color:#fff; }
.pagination-summary { color:var(--muted); font-size:12px; }
.pagination-size label { color:var(--muted); font-size:12px; }
.pagination-size select { min-height:32px; border:1px solid var(--line); border-radius:var(--radius-sm); background:var(--panel); color:var(--text); padding:4px 7px; }
.finding-filter-panel { margin-bottom:12px; padding:10px; background:var(--panel-soft); border:1px solid var(--line-soft); border-radius:var(--radius); }
.finding-filter-panel .filter-row { margin-bottom:8px; }
.finding-filter-panel .investigation-bar { margin-bottom:0; grid-template-columns:minmax(260px,1fr) repeat(3,minmax(145px,.32fr)) auto; }
.finding-filter-panel .filter-label { align-self:center; color:var(--muted); font-size:11.5px; font-weight:600; margin-right:2px; }
.finding-group-card { /* grouped entries intentionally use the same card contract as individual findings */ }
.grouped-evidence-label { margin-top:10px; }
.compact-list { margin:10px 0 0; padding-left:20px; }
.compact-list li { margin:4px 0; }
.sankey-wrap { overflow:auto; min-height:360px; }
.finding-sankey { display:block; width:100%; min-width:760px; height:360px; }
.sankey-link { fill:none; stroke-opacity:.30; transition:stroke-opacity .14s ease; }
.sankey-link:hover { stroke-opacity:.72; }
.sankey-high, .sankey-critical { stroke:var(--high); }
.sankey-medium { stroke:var(--medium); }
.sankey-low { stroke:var(--low); }
.sankey-informational { stroke:var(--info); }
.sankey-node rect { fill:var(--panel-strong); stroke:var(--line); stroke-width:1; rx:4; }
.sankey-node text { fill:var(--text); font-family:var(--font); font-size:10.5px; font-weight:600; }
.sankey-count { fill:var(--muted) !important; font-size:9.5px !important; }
.analyst-focus { border-left:4px solid var(--brand); }
.priority-p0 { background:var(--high-bg); border-color:var(--high); color:var(--high); }
.priority-p1 { background:var(--medium-bg); border-color:var(--medium); color:var(--medium); }
.priority-p2 { background:var(--low-bg); border-color:var(--low); color:var(--low); }
.priority-p3 { background:var(--panel-strong); border-color:var(--line); color:var(--muted); }
.grouped-tag { background:var(--brand-soft); border-color:var(--brand); color:var(--brand); }
.focus-filter-row { margin:8px 0 12px; }
.focus-row[hidden] { display:none; }

mark.search-hit { background:var(--highlight-bg); color:var(--highlight-text); border:1px solid var(--highlight-border); border-radius:2px; padding:0 1px; font-weight:600; }
@media (max-width: 760px) {
  .hero-grid { grid-template-columns:1fr; }
  .toolbar, .report-nav { justify-content:start; }
  .finding-filter-panel .investigation-bar, .investigation-bar, .filters, .finding-summary-grid, .explain-grid, .visual-grid { grid-template-columns:1fr; }
  .shell { padding:16px; }
  .finding-top { display:block; }
  .finding-top > .pill-row { margin-top:8px; }
}
@media print {
  :root, [data-theme="dark"] {
    --bg:#ffffff; --panel:#ffffff; --panel-soft:#fafafa; --panel-strong:#f5f5f5; --text:#111111; --muted:#444444; --faint:#666666; --line:#c8c8c8; --line-soft:#e3e3e3; --shadow:none;
  }
  .toolbar, .finding-filter-panel, .filter-row, .investigation-bar, .filters, .pagination-controls { display:none !important; }
  .hero, .section, .metric, .metric-card, .finding-card, .context-panel, .technical-panel, .trust-box, .evidence-card { box-shadow:none; break-inside:avoid; }
  details:not([open]) > * { display:block; }
  mark.search-hit { border:1px solid #8a6a00; background:#fff4ce; color:#111111; }
}
'@
}

function Get-AppExposureReportClientScript {
    return @'
(function(){
  var printOpenedDetails=[];
  var printHiddenCards=[];
  var filterDebounce=null;
  var findingPage=1;
  function normalize(value){return (value||'').toLowerCase().trim();}
  function allFindingCards(){return Array.prototype.slice.call(document.querySelectorAll('.finding-card'));}
  function getPageSize(){var el=document.getElementById('findingPageSize');if(!el||el.value==='all')return Infinity;var n=parseInt(el.value,10);return Number.isFinite(n)&&n>0?n:20;}
  function getSeverityFilter(){var active=document.querySelector('[data-filter-severity].is-active');if(active)return active.getAttribute('data-filter-severity')||'All';return 'All';}
  function matchingCards(){
    var q=normalize((document.getElementById('findingSearch')||{}).value);
    var severity=getSeverityFilter();
    var category=(document.getElementById('categoryFilter')||{}).value||'';
    var classification=(document.getElementById('spClassificationFilter')||{}).value||'';
    var kind=(document.getElementById('kindFilter')||{}).value||'All';
    return allFindingCards().filter(function(card){
      var matchText=!q||normalize(card.getAttribute('data-search')).indexOf(q)!==-1;
      var matchSeverity=severity==='All'||!severity||card.getAttribute('data-severity')===severity;
      var matchCategory=!category||card.getAttribute('data-category')===category;
      var classifications=(card.getAttribute('data-sp-classifications')||'').split('|').filter(Boolean);
      var matchClassification=!classification||classifications.indexOf(classification)!==-1;
      var matchKind=kind==='All'||!kind||card.getAttribute('data-kind')===kind;
      return matchText&&matchSeverity&&matchCategory&&matchClassification&&matchKind;
    });
  }
  function clearSearchHighlights(){document.querySelectorAll('mark.search-hit').forEach(function(mark){mark.replaceWith(document.createTextNode(mark.textContent||''));});}
  function highlightTextNode(node,pattern){
    var text=node.nodeValue||'';var lower=text.toLowerCase();var index=lower.indexOf(pattern);if(index<0)return;
    var fragment=document.createDocumentFragment();var cursor=0;
    while(index>=0){if(index>cursor)fragment.appendChild(document.createTextNode(text.slice(cursor,index)));var mark=document.createElement('mark');mark.className='search-hit';mark.textContent=text.slice(index,index+pattern.length);fragment.appendChild(mark);cursor=index+pattern.length;index=lower.indexOf(pattern,cursor);}
    if(cursor<text.length)fragment.appendChild(document.createTextNode(text.slice(cursor)));node.parentNode.replaceChild(fragment,node);
  }
  function highlightSearchMatches(pattern){
    clearSearchHighlights();if(!pattern||pattern.length<2)return;
    document.querySelectorAll('.finding-card:not([hidden])').forEach(function(card){var walker=document.createTreeWalker(card,NodeFilter.SHOW_TEXT,{acceptNode:function(node){var parent=node.parentNode;if(!parent)return NodeFilter.FILTER_REJECT;var tag=(parent.nodeName||'').toLowerCase();return tag==='mark'||tag==='script'||tag==='style'?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT;}});var nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);nodes.forEach(function(node){highlightTextNode(node,pattern);});});
  }
  function setTheme(theme){document.documentElement.setAttribute('data-theme',theme);try{localStorage.setItem('entra-app-exposure-report-theme',theme)}catch(e){}}
  function renderPageButtons(totalPages){
    var host=document.getElementById('findingPageButtons');if(!host)return;host.replaceChildren();if(totalPages<=1)return;
    var pages=[];
    if(totalPages<=7){for(var i=1;i<=totalPages;i++)pages.push(i);}else{pages=[1];var start=Math.max(2,findingPage-1),end=Math.min(totalPages-1,findingPage+1);if(start>2)pages.push('…');for(var p=start;p<=end;p++)pages.push(p);if(end<totalPages-1)pages.push('…');pages.push(totalPages);}
    pages.forEach(function(value){if(value==='…'){var span=document.createElement('span');span.className='pagination-summary';span.textContent='…';host.appendChild(span);return;}var button=document.createElement('button');button.type='button';button.textContent=String(value);button.setAttribute('aria-label','Go to findings page '+value);if(value===findingPage){button.className='is-active';button.setAttribute('aria-current','page');}button.addEventListener('click',function(){findingPage=value;applyFilters(false,true);});host.appendChild(button);});
  }
  function applyFilters(resetPage,scrollToFindings){
    if(resetPage!==false)findingPage=1;
    var cards=allFindingCards(),matches=matchingCards(),pageSize=getPageSize();
    var totalPages=pageSize===Infinity?1:Math.max(1,Math.ceil(matches.length/pageSize));findingPage=Math.max(1,Math.min(findingPage,totalPages));
    cards.forEach(function(card){card.hidden=true;});
    var start=pageSize===Infinity?0:(findingPage-1)*pageSize;var end=pageSize===Infinity?matches.length:Math.min(matches.length,start+pageSize);
    matches.slice(start,end).forEach(function(card){card.hidden=false;});
    var count=document.getElementById('findingResultCount');if(count){count.textContent=matches.length===0?'0 matching · '+cards.length+' total':'Showing '+(start+1)+'–'+end+' of '+matches.length+(matches.length!==cards.length?' matching · '+cards.length+' total':' entries');}
    var summary=document.getElementById('findingPageSummary');if(summary){summary.textContent=matches.length===0?'No matching entries':(start+1)+'–'+end+' of '+matches.length;}
    var empty=document.getElementById('noFindingResults');if(empty)empty.hidden=matches.length!==0;
    var controls=document.getElementById('findingPagination');if(controls)controls.hidden=matches.length===0;
    var prev=document.getElementById('findingPrevPage'),next=document.getElementById('findingNextPage');if(prev)prev.disabled=findingPage<=1;if(next)next.disabled=findingPage>=totalPages;
    renderPageButtons(totalPages);highlightSearchMatches(normalize((document.getElementById('findingSearch')||{}).value));
    if(scrollToFindings){var section=document.getElementById('findings');if(section)try{section.scrollIntoView({block:'start'})}catch(e){}}
  }
  function scheduleFilters(){window.clearTimeout(filterDebounce);filterDebounce=window.setTimeout(function(){applyFilters(true,false);},125);}
  function setSeverityFilter(value){document.querySelectorAll('[data-filter-severity]').forEach(function(button){button.classList.toggle('is-active',(button.getAttribute('data-filter-severity')||'All')===value);});applyFilters(true,false);}
  function resetFindingFilters(){var search=document.getElementById('findingSearch'),cat=document.getElementById('categoryFilter'),sp=document.getElementById('spClassificationFilter'),kind=document.getElementById('kindFilter');if(search)search.value='';if(cat)cat.value='';if(sp)sp.value='';if(kind)kind.value='All';document.querySelectorAll('[data-filter-severity]').forEach(function(button){button.classList.toggle('is-active',(button.getAttribute('data-filter-severity')||'All')==='All');});findingPage=1;}
  function revealHash(){
    if(!location.hash)return;var id=decodeURIComponent(location.hash.slice(1));var node=document.getElementById(id);if(!node)return;
    if(node.classList&&node.classList.contains('finding-card')){resetFindingFilters();var cards=matchingCards(),index=cards.indexOf(node),size=getPageSize();findingPage=(size===Infinity||index<0)?1:Math.floor(index/size)+1;applyFilters(false,false);}
    var p=node;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}try{node.scrollIntoView({block:'start'})}catch(e){}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var saved='light';try{saved=localStorage.getItem('entra-app-exposure-report-theme')||'light'}catch(e){}setTheme(saved);
    var toggle=document.getElementById('themeToggle');if(toggle)toggle.addEventListener('click',function(){setTheme(document.documentElement.getAttribute('data-theme')==='light'?'dark':'light')});
    document.querySelectorAll('[data-filter-severity]').forEach(function(button){button.addEventListener('click',function(){setSeverityFilter(button.getAttribute('data-filter-severity')||'All');});});
    var search=document.getElementById('findingSearch');if(search)search.addEventListener('input',scheduleFilters);
    var category=document.getElementById('categoryFilter');if(category)category.addEventListener('change',function(){applyFilters(true,false);});
    var spClass=document.getElementById('spClassificationFilter');if(spClass)spClass.addEventListener('change',function(){applyFilters(true,false);});
    var kind=document.getElementById('kindFilter');if(kind)kind.addEventListener('change',function(){applyFilters(true,false);});
    document.querySelectorAll('[data-focus-priority]').forEach(function(button){button.addEventListener('click',function(){var value=button.getAttribute('data-focus-priority')||'P0';document.querySelectorAll('[data-focus-priority]').forEach(function(b){b.classList.toggle('is-active',(b.getAttribute('data-focus-priority')||'P0')===value);});var visible=0;document.querySelectorAll('.focus-row').forEach(function(row){row.hidden=row.getAttribute('data-priority')!==value;if(!row.hidden)visible++;});var empty=document.getElementById('focusEmpty');if(empty)empty.hidden=visible!==0;});});
    var pageSize=document.getElementById('findingPageSize');if(pageSize)pageSize.addEventListener('change',function(){applyFilters(true,false);});
    var prev=document.getElementById('findingPrevPage');if(prev)prev.addEventListener('click',function(){if(findingPage>1){findingPage--;applyFilters(false,true);}});
    var next=document.getElementById('findingNextPage');if(next)next.addEventListener('click',function(){findingPage++;applyFilters(false,true);});
    var reset=document.getElementById('resetFilters');if(reset)reset.addEventListener('click',function(){resetFindingFilters();applyFilters(true,false);});
    var sidecar=document.getElementById('sidecarSearch');if(sidecar)sidecar.addEventListener('input',function(){var q=normalize(sidecar.value);document.querySelectorAll('[data-sidecar-search]').forEach(function(card){card.hidden=!!q&&normalize(card.getAttribute('data-search')).indexOf(q)===-1});});
    document.addEventListener('keydown',function(event){if(event.key!=='/'||event.ctrlKey||event.metaKey||event.altKey)return;var target=event.target;var tag=target&&target.tagName?target.tagName.toLowerCase():'';if(tag==='input'||tag==='textarea'||tag==='select'||tag==='button'||(target&&target.isContentEditable))return;var searchBox=document.getElementById('findingSearch')||document.getElementById('sidecarSearch');if(searchBox){event.preventDefault();searchBox.focus();}});
    window.addEventListener('beforeprint',function(){printOpenedDetails=[];printHiddenCards=[];document.querySelectorAll('details').forEach(function(details){if(!details.open){printOpenedDetails.push(details);details.open=true;}});allFindingCards().forEach(function(card){if(card.hidden){printHiddenCards.push(card);card.hidden=false;}});});
    window.addEventListener('afterprint',function(){printOpenedDetails.forEach(function(details){details.open=false;});printOpenedDetails=[];printHiddenCards=[];applyFilters(false,false);});
    var focusDefault=document.querySelector('[data-focus-priority="P0"]');if(focusDefault)focusDefault.click();
    applyFilters(true,false);revealHash();
  });
  window.addEventListener('hashchange',revealHash);
})();
'@
}

function New-AppExposureReportUiDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Subtitle,
        [Parameter(Mandatory = $true)][string]$Body,
        [Parameter(Mandatory = $true)][string]$Brand,
        [Parameter(Mandatory = $true)][string]$Footer,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Navigation,
        [Parameter(Mandatory = $true)][string]$ActiveView,
        [Parameter(Mandatory = $false)][string]$HeroMeta = '',
        [Parameter(Mandatory = $false)][string]$Script = '',
        [Parameter(Mandatory = $false)][hashtable]$HtmlAttributes = @{}
    )

    $css = Get-AppExposureReportCss
    $navHtml = @(
        foreach ($item in @($Navigation)) {
            $label = [string]$item.Label
            $file = [string]$item.File
            $view = [string]$item.View
            $isPrimary = $false
            $isExternal = $false
            if ($item.PSObject.Properties['Primary']) { $isPrimary = [bool]$item.Primary }
            if ($item.PSObject.Properties['External']) { $isExternal = [bool]$item.External }
            $classes = @('pill')
            if ($ActiveView -eq $view) { $classes += 'is-active' }
            if ($isPrimary) { $classes += 'primary-link' }
            $externalAttributes = if ($isExternal) { ' target="_blank" rel="noopener noreferrer"' } else { '' }
            '<a class="' + ($classes -join ' ') + '" href="' + (ConvertTo-AppExposureReportHtml $file) + '"' + $externalAttributes + '>' + (ConvertTo-AppExposureReportHtml $label) + '</a>'
        }
    ) -join ''
    $scriptHtml = if ([string]::IsNullOrWhiteSpace($Script)) { '' } else { "<script>`n$Script`n</script>" }
    $extra = @(
        foreach ($name in @($HtmlAttributes.Keys | Sort-Object)) {
            if ([string]$name -notmatch '^[A-Za-z_:][A-Za-z0-9_.:-]*$') {
                throw "Invalid HTML attribute name '$name'."
            }
            $encodedValue = ConvertTo-AppExposureReportHtml ([string]$HtmlAttributes[$name])
            ' ' + [string]$name + '="' + $encodedValue + '"'
        }
    ) -join ''

    return @"
<!doctype html>
<html lang="en" data-theme="light" data-entra-app-exposure-report-ui="$script:AppExposureReportUiVersion" data-entra-assessment-report-shell="1.0"$extra>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$(ConvertTo-AppExposureReportHtml $Title)</title>
  <style>
$css
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-grid">
      <div>
        <div class="brand-lockup"><span class="project-mark" aria-label="Entra App Exposure project mark">EA</span><span class="brand-accent" aria-hidden="true"></span><div><div class="brand">Entra application identity assessment</div><div class="product-label">$(ConvertTo-AppExposureReportHtml $Brand)</div></div></div>
        <h1>$(ConvertTo-AppExposureReportHtml $Title)</h1>
        $HeroMeta
        <p class="subtitle">$(ConvertTo-AppExposureReportHtml $Subtitle)</p>
      </div>
      <div class="toolbar"><nav class="report-nav" aria-label="Report navigation">$navHtml<button id="themeToggle" type="button">Toggle theme</button></nav></div>
    </div>
  </header>
  <main class="shell">
$Body
  </main>
  <footer class="footer">$(ConvertTo-AppExposureReportHtml $Footer)<br><span>Independent community project; not affiliated with, sponsored by, or endorsed by Microsoft.</span></footer>
  $scriptHtml
</body>
</html>
"@
}


<# HTML section/document rendering helpers. Offline only. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function New-AppExposureReportDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Subtitle,
        [Parameter(Mandatory = $true)][string]$Body,
        [Parameter(Mandatory = $true)][ValidateSet('Assessment','Evidence','Diagnostics')][string]$ActiveView,
        [Parameter(Mandatory = $false)][string]$HeroMeta = '',
        [Parameter(Mandatory = $false)][string]$Script = '',
        [Parameter(Mandatory = $false)][string]$TenantPortalUrl = 'https://entra.microsoft.com'
    )

    $navItems = [System.Collections.Generic.List[object]]::new()
    $navItems.Add([PSCustomObject]@{ Label='Assessment'; File='report.html'; View='Assessment' })
    $navItems.Add([PSCustomObject]@{ Label='Evidence'; File='evidence.html'; View='Evidence' })
    $navItems.Add([PSCustomObject]@{ Label='Diagnostics'; File='diagnostics.html'; View='Diagnostics' })
    if ($ActiveView -eq 'Assessment') {
        $navItems.Add([PSCustomObject]@{ Label='Focus'; File='#analyst-focus'; View='Focus' })
        $navItems.Add([PSCustomObject]@{ Label='Findings'; File='#findings'; View='Findings' })
        $navItems.Add([PSCustomObject]@{ Label='Snapshot drift'; File='#drift'; View='Drift' })
    }
    $navItems.Add([PSCustomObject]@{ Label='Open Microsoft Entra'; File=$TenantPortalUrl; View='External'; Primary=$true; External=$true })

    return New-AppExposureReportUiDocument `
        -Title $Title `
        -Subtitle $Subtitle `
        -Body $Body `
        -Brand 'Entra App Exposure' `
        -Footer 'Entra App Exposure · Built by Alaaeddine Ayedi · https://github.com/0xDarknightHacks · Read-only · Offline compatible' `
        -Navigation @($navItems.ToArray()) `
        -ActiveView $ActiveView `
        -HeroMeta $HeroMeta `
        -Script $Script `
        -HtmlAttributes @{ 'data-entra-app-exposure-report-shell' = '1.0' }
}
function New-AppExposureBarChartHtml {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Items = @(),
        [Parameter(Mandatory = $false)][string]$EmptyText = 'No data is available for this visualization.'
    )

    $itemsArray = @($Items | Where-Object { $null -ne $_ })
    if ($itemsArray.Count -eq 0) {
        return '<p class="empty-state">' + (ConvertTo-AppExposureReportHtml $EmptyText) + '</p>'
    }

    $maxValue = 0.0
    foreach ($item in $itemsArray) {
        $value = 0.0
        [void][double]::TryParse([string](Get-AppExposurePropertyValue -Object $item -Name 'Value'), [ref]$value)
        if ($value -gt $maxValue) { $maxValue = $value }
    }
    if ($maxValue -le 0) { $maxValue = 1.0 }

    return @(
        foreach ($item in $itemsArray) {
            $label = [string](Get-AppExposurePropertyValue -Object $item -Name 'Label')
            $rawValue = Get-AppExposurePropertyValue -Object $item -Name 'Value'
            $value = 0.0
            [void][double]::TryParse([string]$rawValue, [ref]$value)
            $barClass = [string](Get-AppExposurePropertyValue -Object $item -Name 'Class')
            if ([string]::IsNullOrWhiteSpace($barClass)) { $barClass = 'bar-brand' }
            $percentage = [int][Math]::Round([Math]::Max(2.0, [Math]::Min(100.0, (($value / $maxValue) * 100.0))))
            '<div class="bar-row"><div class="bar-meta"><span>' + (ConvertTo-AppExposureReportHtml $label) + '</span><strong>' + (ConvertTo-AppExposureReportHtml $rawValue) + '</strong></div><div class="bar-track" aria-hidden="true"><span class="bar-fill ' + (ConvertTo-AppExposureReportHtml $barClass) + '" style="width:' + $percentage + '%"></span></div></div>'
        }
    ) -join [Environment]::NewLine
}

function New-AppExposureFindingHtml {
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][hashtable]$ObservationById,
        [Parameter(Mandatory = $false)][string]$EvidenceFileName = 'evidence.html',
        [Parameter(Mandatory = $false)][hashtable]$ObjectPortalUrlById = @{},
        [Parameter(Mandatory = $false)][hashtable]$ObjectSpClassificationById = @{}
    )

    $findingId = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'FindingId')
    $ruleId = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'RuleId')
    $severity = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'Severity')
    $category = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'Category')
    $title = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'Title')
    $objectName = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'ObjectDisplayName')
    $objectId = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'ObjectId')
    $what = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'WhatHappened')
    $why = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'WhyItMatters')
    $recommendation = [string](Get-AppExposurePropertyValue -Object $Finding -Name 'Recommendation')
    $evidenceIds = @((Get-AppExposurePropertyValue -Object $Finding -Name 'EvidenceIds'))
    $evidenceSummary = @((Get-AppExposurePropertyValue -Object $Finding -Name 'EvidenceSummary'))
    $references = @((Get-AppExposurePropertyValue -Object $Finding -Name 'References'))

    $summaryItems = if ($evidenceSummary.Count -gt 0) {
        @($evidenceSummary | ForEach-Object { '<li>' + (ConvertTo-AppExposureReportHtml $_) + '</li>' }) -join ''
    }
    else { '<li>No additional evidence summary was supplied.</li>' }

    $evidenceLinks = @(
        foreach ($evidenceIdValue in $evidenceIds) {
            $evidenceId = [string]$evidenceIdValue
            if ([string]::IsNullOrWhiteSpace($evidenceId)) { continue }
            $statusClass = if ($ObservationById.ContainsKey($evidenceId)) { 'status-success' } else { 'status-danger' }
            '<a class="pill ' + $statusClass + '" href="' + (ConvertTo-AppExposureReportHtml $EvidenceFileName) + '#evidence-' + (ConvertTo-AppExposureReportHtml $evidenceId) + '">' + (ConvertTo-AppExposureReportHtml $evidenceId) + '</a>'
        }
    ) -join ''
    if ([string]::IsNullOrWhiteSpace($evidenceLinks)) {
        $evidenceLinks = '<span class="pill status-default">No ObservationIds</span>'
    }

    $referenceLinks = if ($references.Count -gt 0) {
        @($references | Where-Object { $_ } | ForEach-Object { '<a href="' + (ConvertTo-AppExposureReportHtml $_) + '" target="_blank" rel="noopener noreferrer">Microsoft Learn</a>' }) -join ' · '
    } else { '' }
    $search = ConvertTo-AppExposureReportSearchAttribute -Values @($findingId,$ruleId,$severity,$category,$title,$objectName,$objectId,$what,$why,$recommendation,$evidenceSummary,$evidenceIds,$references)
    $severityClass = Get-AppExposureReportSeverityClass -Severity $severity
    $portalLink = if ($objectId -and $ObjectPortalUrlById.ContainsKey($objectId) -and $ObjectPortalUrlById[$objectId]) { ' · <a href="' + (ConvertTo-AppExposureReportHtml $ObjectPortalUrlById[$objectId]) + '" target="_blank" rel="noopener noreferrer">Open in Entra</a>' } else { '' }
    $spClassification = if ($ObjectSpClassificationById.ContainsKey($objectId)) { [string]$ObjectSpClassificationById[$objectId] } else { '' }

    return @"
<article id="finding-$(ConvertTo-AppExposureReportHtml $findingId)" class="finding-card" data-severity="$(ConvertTo-AppExposureReportHtml $severity)" data-category="$(ConvertTo-AppExposureReportHtml $category)" data-kind="Individual" data-sp-classifications="$(ConvertTo-AppExposureReportHtml $spClassification)" data-search="$search">
  <div class="finding-top">
    <div>
      <div class="finding-category">$(ConvertTo-AppExposureReportHtml $category)</div>
      <div class="finding-title">$(ConvertTo-AppExposureReportHtml $title)</div>
      <div class="object-line">$(ConvertTo-AppExposureReportHtml $objectName) · <code>$(ConvertTo-AppExposureReportHtml $objectId)</code>$portalLink</div>
    </div>
    <div class="pill-row"><span class="pill $severityClass">$(ConvertTo-AppExposureReportHtml $severity)</span><span class="pill status-default">$(ConvertTo-AppExposureReportHtml $ruleId)</span></div>
  </div>
  <div class="finding-summary-grid">
    <div class="finding-summary-item"><span class="field-label">What happened</span><span class="field-value">$(ConvertTo-AppExposureReportHtml $what)</span></div>
    <div class="finding-summary-item"><span class="field-label">Why it matters</span><span class="field-value">$(ConvertTo-AppExposureReportHtml $why)</span></div>
  </div>
  <div class="finding-action"><strong>Recommended action:</strong> $(ConvertTo-AppExposureReportHtml $recommendation)</div>
  $(if ($referenceLinks) { '<div class="object-line"><strong>Rule reference:</strong> ' + $referenceLinks + '</div>' } else { '' })
  <details class="finding-technical evidence">
    <summary>Evidence · $($evidenceIds.Count) observation reference(s)</summary>
    <ul class="evidence-list">$summaryItems</ul>
    <div class="evidence-links">$evidenceLinks</div>
    <div class="finding-meta"><span class="pill status-default">Finding ID: $(ConvertTo-AppExposureReportHtml $findingId)</span></div>
  </details>
</article>
"@
}
function New-AppExposureEvidenceHtml {
    param(
        [Parameter(Mandatory = $true)]$Observation,
        [Parameter(Mandatory = $false)][hashtable]$ObjectPortalUrlById = @{}
    )

    $id = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'ObservationId')
    $category = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'Category')
    $objectName = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'ObjectDisplayName')
    $objectId = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'ObjectId')
    $identityKey = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'IdentityKey')
    $sourceUri = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'SourceUri')
    $collected = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'CollectedAtUtc')
    $fingerprint = [string](Get-AppExposurePropertyValue -Object $Observation -Name 'Fingerprint')
    $value = Get-AppExposurePropertyValue -Object $Observation -Name 'Value'
    $search = ConvertTo-AppExposureReportSearchAttribute -Values @($id,$category,$objectName,$objectId,$identityKey,$sourceUri,$fingerprint)
    $portalLink = if ($objectId -and $ObjectPortalUrlById.ContainsKey($objectId) -and $ObjectPortalUrlById[$objectId]) { ' · <a href="' + (ConvertTo-AppExposureReportHtml $ObjectPortalUrlById[$objectId]) + '" target="_blank" rel="noopener noreferrer">Open in Entra</a>' } else { '' }

    return @"
<article id="evidence-$(ConvertTo-AppExposureReportHtml $id)" class="evidence-card" data-sidecar-search="true" data-search="$search">
  <h3>$(ConvertTo-AppExposureReportHtml $id)</h3>
  <div class="evidence-meta">
    <span class="pill status-default">$(ConvertTo-AppExposureReportHtml $category)</span>
    <span class="pill status-default">$(ConvertTo-AppExposureReportHtml $objectName)</span>
    <span class="pill status-default">Collected $(ConvertTo-AppExposureReportHtml $collected)</span>
  </div>
  <div class="object-line"><strong>Object:</strong> <code>$(ConvertTo-AppExposureReportHtml $objectId)</code>$portalLink</div>
  <div class="object-line"><strong>Identity key:</strong> <code>$(ConvertTo-AppExposureReportHtml $identityKey)</code></div>
  <div class="object-line"><strong>Fingerprint:</strong> <code>$(ConvertTo-AppExposureReportHtml $fingerprint)</code></div>
  <div class="object-line"><strong>Source:</strong> $(ConvertTo-AppExposureReportHtml $sourceUri)</div>
  <pre class="raw-evidence">$(ConvertTo-AppExposureReportEvidenceJson $value)</pre>
</article>
"@
}


<# Assessment artifact export pipeline. Offline only. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function New-AppExposureArtifactManifest {
    param(
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [Parameter(Mandatory=$true)]$Snapshot,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$FindingGroups,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Drift,
        [Parameter(Mandatory=$true)][string]$DriftStatus,
        [Parameter(Mandatory=$false)][string]$BaselineSnapshotId,
        [Parameter(Mandatory=$true)][int]$GraphCallsAfterSnapshot
    )
    $collection = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Collection'
    $recordCounts = @{
        'snapshot.json'      = [int](Get-AppExposurePropertyValue -Object $collection -Name 'ObservationCount')
        'findings.json'      = @($Findings).Count
        'finding-groups.json'= @($FindingGroups).Count
        'findings.csv'       = @($Findings).Count
        'drift.json'         = @($Drift).Count
        'run-summary.json'   = 1
        'report.html'        = $null
        'evidence.html'      = $null
        'diagnostics.html'   = $null
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($name in @('snapshot.json','findings.json','finding-groups.json','findings.csv','drift.json','run-summary.json','report.html','evidence.html','diagnostics.html')) {
        $path = Join-Path $OutputDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Artifact manifest cannot be created because '$name' is missing." }
        $file = Get-Item -LiteralPath $path
        $items.Add([PSCustomObject]@{
            Name        = $name
            SizeBytes   = [int64]$file.Length
            RecordCount = $recordCounts[$name]
            Sha256      = Get-AppExposureFileSha256 -Path $path
        })
    }
    return [PSCustomObject]@{
        ManifestVersion    = '1.1'
        Generator          = 'Entra App Exposure'
        Author             = 'Alaaeddine Ayedi'
        ProjectUri         = 'https://github.com/0xDarknightHacks/EntraAppExposure'
        SnapshotId         = Get-AppExposurePropertyValue -Object $Snapshot -Name 'SnapshotId'
        DriftStatus        = $DriftStatus
        BaselineSnapshotId = $BaselineSnapshotId
        GraphCallsAfterSnapshot = $GraphCallsAfterSnapshot
        ArtifactCount      = $items.Count
        Artifacts          = @($items.ToArray())
    }
}
function Export-AppExposureAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]]$Drift = @(),
        [Parameter(Mandatory = $false)][ValidateSet('NotCompared','Compared')][string]$DriftStatus = 'NotCompared',
        [Parameter(Mandatory = $false)][string]$BaselineSnapshotId,
        [Parameter(Mandatory = $false)][string]$BaselineCollectedAtUtc,
        [Parameter(Mandatory = $false)][ValidateRange(0,2147483647)][int]$GraphCallsAfterSnapshot = 0,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $false)][string]$RulePackPath,
        [Parameter(Mandatory = $false)][datetime]$RunStartedAtUtc = ([datetime]::UtcNow),
        [Parameter(Mandatory = $false)][AllowNull()][System.Collections.IDictionary]$PhaseTimingsMs,
        [Parameter(Mandatory = $false)][switch]$ExcludeMicrosoftFirstParty
    )

    $reportExportStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($null -eq $PhaseTimingsMs) { $PhaseTimingsMs = [ordered]@{} }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $findingsPath = Join-Path $OutputDirectory 'findings.json'
    $findingGroupsPath = Join-Path $OutputDirectory 'finding-groups.json'
    $findingsCsvPath = Join-Path $OutputDirectory 'findings.csv'
    $driftPath = Join-Path $OutputDirectory 'drift.json'
    $summaryPath = Join-Path $OutputDirectory 'run-summary.json'
    $htmlPath = Join-Path $OutputDirectory 'report.html'
    $evidenceHtmlPath = Join-Path $OutputDirectory 'evidence.html'
    $diagnosticsHtmlPath = Join-Path $OutputDirectory 'diagnostics.html'
    $manifestPath = Join-Path $OutputDirectory 'artifact-manifest.json'

    $findingsArray = @($Findings)
    $findingGroups = @(New-AppExposureFindingGroups -Findings $findingsArray)
    $driftArray = @($Drift)
    ConvertTo-Json -InputObject $findingsArray -Depth 20 | Set-Content -LiteralPath $findingsPath -Encoding UTF8
    ConvertTo-Json -InputObject $findingGroups -Depth 20 | Set-Content -LiteralPath $findingGroupsPath -Encoding UTF8

    if ($findingsArray.Count -gt 0) {
        $findingsArray | Select-Object FindingId, RuleId, Severity, Category, ObjectDisplayName, ObjectId, Title, WhatHappened, WhyItMatters, Recommendation,
            @{Name='References';Expression={ @($_.References) -join ';' }},
            @{Name='EvidenceIds';Expression={ @($_.EvidenceIds) -join ';' }},
            @{Name='EvidenceSummary';Expression={ @($_.EvidenceSummary) -join '; ' }} |
            Export-Csv -LiteralPath $findingsCsvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        '"FindingId","RuleId","Severity","Category","ObjectDisplayName","ObjectId","Title","WhatHappened","WhyItMatters","Recommendation","References","EvidenceIds","EvidenceSummary"' |
            Set-Content -LiteralPath $findingsCsvPath -Encoding UTF8
    }

    if ($DriftStatus -eq 'Compared' -and [string]::IsNullOrWhiteSpace($BaselineSnapshotId)) { throw 'BaselineSnapshotId is required when DriftStatus is Compared.' }
    $driftDocument = [PSCustomObject]@{
        DriftStatus            = $DriftStatus
        BaselineSnapshotId     = $BaselineSnapshotId
        BaselineCollectedAtUtc = $BaselineCollectedAtUtc
        CurrentSnapshotId      = Get-AppExposurePropertyValue -Object $Snapshot -Name 'SnapshotId'
        ChangeCount            = $driftArray.Count
        Changes                = $driftArray
    }
    $driftDocument | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $driftPath -Encoding UTF8

    $severityNames = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $severityCounts = [ordered]@{}
    foreach ($name in $severityNames) {
        $severityCounts[$name] = @($findingsArray | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity') -eq $name }).Count
    }
    $affectedIdentityCount = @(
        $findingsArray |
        ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    ).Count
    $actionableFindings = @($findingsArray | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity') -ne 'Informational' })
    $informationalFindingCount = $findingsArray.Count - $actionableFindings.Count
    $actionableIdentityCount = @(
        $actionableFindings |
        ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    ).Count
    $actionableSeverityCounts = [ordered]@{}
    foreach ($name in $severityNames) {
        $actionableSeverityCounts[$name] = @($actionableFindings | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity') -eq $name }).Count
    }
    $highPriorityFindingCount = [int]$actionableSeverityCounts['Critical'] + [int]$actionableSeverityCounts['High']

    $severityClassByName = @{
        Critical='bar-critical'; High='bar-high'; Medium='bar-medium'; Low='bar-low'; Informational='bar-info'
    }
    $severityChartItems = @(
        foreach ($name in $severityNames) {
            [PSCustomObject]@{ Label=$name; Value=[int]$actionableSeverityCounts[$name]; Class=$severityClassByName[$name] }
        }
    )
    $categoryChartItems = @(
        $actionableFindings |
        Group-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Category') } |
        Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false} |
        ForEach-Object { [PSCustomObject]@{ Label=$(if ([string]::IsNullOrWhiteSpace($_.Name)) { 'Uncategorized' } else { $_.Name }); Value=$_.Count; Class='bar-brand' } }
    )

    $collection = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Collection'
    $tenant = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Tenant'
    $assessment = Get-AppExposurePropertyValue -Object $Snapshot -Name 'Assessment'
    $applications = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Applications'))
    $servicePrincipals = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'ServicePrincipals'))
    $orphanApplicationCount = @($applications | Where-Object { [bool](Get-AppExposurePropertyValue -Object $_ -Name 'IsOrphan') }).Count
    $observations = @((Get-AppExposurePropertyValue -Object $Snapshot -Name 'Observations'))
    $classificationChartItems = @(
        $servicePrincipals |
        Group-Object { $classification = [string](Get-AppExposurePropertyValue -Object $_ -Name 'Classification'); if ([string]::IsNullOrWhiteSpace($classification)) { 'Unknown' } else { $classification } } |
        Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false} |
        ForEach-Object { [PSCustomObject]@{ Label=$_.Name; Value=$_.Count; Class='bar-brand' } }
    )
    $topAffectedIdentityItems = @(
        $actionableFindings |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId')) } |
        Group-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectId') } |
        Sort-Object @{Expression='Count';Descending=$true}, @{Expression='Name';Descending=$false} |
        Select-Object -First 10 |
        ForEach-Object {
            $first = @($_.Group)[0]
            $display = [string](Get-AppExposurePropertyValue -Object $first -Name 'ObjectDisplayName')
            if ([string]::IsNullOrWhiteSpace($display)) { $display = $_.Name }
            [PSCustomObject]@{ Label=$display; Value=$_.Count; Class='bar-high' }
        }
    )
    $tenantId = [string](Get-AppExposurePropertyValue -Object $tenant -Name 'Id')
    $objectPortalUrlById = @{}
    $objectTypeById = @{}
    $objectSpClassificationById = @{}
    foreach ($application in $applications) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $application -Name 'ObjectId')
        $appId = [string](Get-AppExposurePropertyValue -Object $application -Name 'AppId')
        if ($objectId) {
            $objectPortalUrlById[$objectId] = Get-AppExposurePortalUri -TenantId $tenantId -Kind Application -ObjectId $objectId -AppId $appId
            $objectTypeById[$objectId] = 'App registration'
        }
    }
    foreach ($servicePrincipal in $servicePrincipals) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $servicePrincipal -Name 'ObjectId')
        $appId = [string](Get-AppExposurePropertyValue -Object $servicePrincipal -Name 'AppId')
        if ($objectId) {
            $objectPortalUrlById[$objectId] = Get-AppExposurePortalUri -TenantId $tenantId -Kind ServicePrincipal -ObjectId $objectId -AppId $appId
            $classification = [string](Get-AppExposurePropertyValue -Object $servicePrincipal -Name 'Classification')
            $spType = [string](Get-AppExposurePropertyValue -Object $servicePrincipal -Name 'ServicePrincipalType')
            $filterClassification = if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } elseif ($classification) { $classification } elseif ($spType) { $spType } else { 'Unknown' }
            $objectSpClassificationById[$objectId] = $filterClassification
            $objectTypeById[$objectId] = $(if ($spType -eq 'ManagedIdentity') { 'Managed identity' } else { switch ($classification) { 'MicrosoftFirstParty' { 'Microsoft first-party SP' } 'ThirdParty' { 'Third-party SP' } 'Local' { 'Tenant-local SP' } default { 'Other service principal' } } })
        }
    }
    foreach ($application in $applications) {
        $objectId = [string](Get-AppExposurePropertyValue -Object $application -Name 'ObjectId')
        if (-not $objectId) { continue }
        $linkedClassifications = @(
            @((Get-AppExposurePropertyValue -Object $application -Name 'LinkedServicePrincipalIds')) |
            ForEach-Object { $linkedId = [string]$_; if ($objectSpClassificationById.ContainsKey($linkedId)) { [string]$objectSpClassificationById[$linkedId] } } |
            Where-Object { $_ } | Sort-Object -Unique
        )
        if ($linkedClassifications.Count -gt 0) { $objectSpClassificationById[$objectId] = ($linkedClassifications -join '|') }
    }

    $observationById = @{}
    foreach ($observation in $observations) {
        $observationId = [string](Get-AppExposurePropertyValue -Object $observation -Name 'ObservationId')
        if (-not [string]::IsNullOrWhiteSpace($observationId) -and -not $observationById.ContainsKey($observationId)) {
            $observationById[$observationId] = $observation
        }
    }

    $findingGroupHtml = if ($findingGroups.Count -eq 0) {
        ''
    }
    else {
        @($findingGroups | ForEach-Object { New-AppExposureFindingGroupHtml -Group $_ -EvidenceFileName 'evidence.html' -ObjectPortalUrlById $objectPortalUrlById -ObjectSpClassificationById $objectSpClassificationById }) -join [Environment]::NewLine
    }
    $findingFlowHtml = New-AppExposureFindingSankeyHtml -Findings $findingsArray -ObjectTypeById $objectTypeById

    $firstPartyServicePrincipalCount = @($servicePrincipals | Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Classification') -eq 'MicrosoftFirstParty' }).Count
    $activitySources = @(
        $observations |
        Where-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Category') -eq 'Activity' } |
        ForEach-Object { [string](Get-AppExposurePropertyValue -Object (Get-AppExposurePropertyValue -Object $_ -Name 'Value') -Name 'SourceKind') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )

    $identityPriorities = @(New-AppExposureIdentityPriorities -Applications $applications -ServicePrincipals $servicePrincipals -Findings $actionableFindings -ObjectTypeById $objectTypeById -ObjectPortalUrlById $objectPortalUrlById)
    $priorityCounts = [ordered]@{}
    foreach ($priorityName in @('P0','P1','P2','P3')) { $priorityCounts[$priorityName] = @($identityPriorities | Where-Object Priority -eq $priorityName).Count }
    $p0IdentityCount = [int]$priorityCounts['P0']
    $analystFocusHtml = if ($identityPriorities.Count -eq 0) {
        '<p class="empty">No actionable identities require analyst focus from the current rule baseline.</p>'
    }
    else {
        $rows = @($identityPriorities | ForEach-Object {
            $priorityClass = 'priority-' + ([string]$_.Priority).ToLowerInvariant()
            $portal = if ($_.Portal) { ' <a href="' + (ConvertTo-AppExposureReportHtml $_.Portal) + '" target="_blank" rel="noopener noreferrer">Open in Entra</a>' } else { '' }
            '<tr class="focus-row" data-priority="' + (ConvertTo-AppExposureReportHtml $_.Priority) + '"><td><span class="pill ' + $priorityClass + '">' + (ConvertTo-AppExposureReportHtml $_.Priority) + '</span></td><td><a href="#finding-' + (ConvertTo-AppExposureReportHtml $_.FindingId) + '">' + (ConvertTo-AppExposureReportHtml $_.ObjectDisplayName) + '</a>' + $portal + '<br><code>' + (ConvertTo-AppExposureReportHtml $_.ObjectId) + '</code></td><td>' + (ConvertTo-AppExposureReportHtml $_.Target) + '</td><td>' + $_.FindingCount + '</td><td>' + (ConvertTo-AppExposureReportHtml $_.Reason) + '</td></tr>'
        }) -join ''
        '<div class="filter-row focus-filter-row" aria-label="Analyst priority filters"><button class="filter-button is-active" type="button" data-focus-priority="P0">P0 (' + $priorityCounts['P0'] + ')</button><button class="filter-button" type="button" data-focus-priority="P1">P1 (' + $priorityCounts['P1'] + ')</button><button class="filter-button" type="button" data-focus-priority="P2">P2 (' + $priorityCounts['P2'] + ')</button><button class="filter-button" type="button" data-focus-priority="P3">P3 (' + $priorityCounts['P3'] + ')</button></div><p id="focusEmpty" class="empty-state" hidden>No identities meet the selected priority level.</p><div class="table-wrap analyst-focus"><table class="data-table"><thead><tr><th>Priority</th><th>Identity</th><th>Type</th><th>Findings</th><th>Why prioritized</th></tr></thead><tbody>' + $rows + '</tbody></table></div>'
    }
    $sortedFindings = @(
        $findingsArray |
        Sort-Object @{Expression={ Get-AppExposureSeverityRank -Severity ([string](Get-AppExposurePropertyValue -Object $_ -Name 'Severity')) }; Descending=$true},
                    @{Expression={ [string](Get-AppExposurePropertyValue -Object $_ -Name 'ObjectDisplayName') }},
                    @{Expression={ [string](Get-AppExposurePropertyValue -Object $_ -Name 'RuleId') }}
    )

    $findingHtml = if ($sortedFindings.Count -eq 0) {
        '<p class="empty">No deterministic findings were produced from the collected evidence.</p>'
    }
    else {
        @($sortedFindings | ForEach-Object { New-AppExposureFindingHtml -Finding $_ -ObservationById $observationById -EvidenceFileName 'evidence.html' -ObjectPortalUrlById $objectPortalUrlById -ObjectSpClassificationById $objectSpClassificationById }) -join [Environment]::NewLine
    }

    $categories = @(
        $findingsArray |
        ForEach-Object { [string](Get-AppExposurePropertyValue -Object $_ -Name 'Category') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )
    $categoryOptions = @($categories | ForEach-Object { '<option value="' + (ConvertTo-AppExposureReportHtml $_) + '">' + (ConvertTo-AppExposureReportHtml $_) + '</option>' }) -join ''
    $spClassificationOptions = @(@('Local','ThirdParty','MicrosoftFirstParty','ManagedIdentity','Legacy','Unknown') | Where-Object { $value=$_; @($objectSpClassificationById.Values | Where-Object { $_ -eq $value }).Count -gt 0 } | ForEach-Object { $label = switch ($_) { 'Local' {'Tenant-local'} 'ThirdParty' {'Third-party'} 'MicrosoftFirstParty' {'Microsoft first-party'} 'ManagedIdentity' {'Managed identity'} default { $_ } }; '<option value="' + (ConvertTo-AppExposureReportHtml $_) + '">' + (ConvertTo-AppExposureReportHtml $label) + '</option>' }) -join ''

    $driftHtml = if ($DriftStatus -eq 'NotCompared') {
        '<p class="empty">No baseline snapshot was supplied. Drift was not evaluated for this run.</p>'
    }
    elseif ($driftArray.Count -eq 0) {
        '<p class="empty">Baseline comparison completed and no comparable semantic changes were detected.</p>'
    }
    else {
        $rows = @(
            $driftArray | ForEach-Object {
                $changeType = Get-AppExposurePropertyValue -Object $_ -Name 'ChangeType'
                $driftCategory = Get-AppExposurePropertyValue -Object $_ -Name 'Category'
                $objectDisplayName = Get-AppExposurePropertyValue -Object $_ -Name 'ObjectDisplayName'
                $description = Get-AppExposurePropertyValue -Object $_ -Name 'Description'
                '<tr><td>' + (ConvertTo-AppExposureReportHtml $changeType) + '</td><td>' + (ConvertTo-AppExposureReportHtml $driftCategory) + '</td><td>' + (ConvertTo-AppExposureReportHtml $objectDisplayName) + '</td><td>' + (ConvertTo-AppExposureReportHtml $description) + '</td></tr>'
            }
        ) -join [Environment]::NewLine
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>Change</th><th>Category</th><th>Object</th><th>Description</th></tr></thead><tbody>' + $rows + '</tbody></table></div>'
    }

    $referencedEvidenceIds = @(
        $findingsArray |
        ForEach-Object { @((Get-AppExposurePropertyValue -Object $_ -Name 'EvidenceIds')) } |
        ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )
    $missingEvidenceIds = @($referencedEvidenceIds | Where-Object { -not $observationById.ContainsKey($_) })
    $evidenceHtml = @(
        foreach ($evidenceId in $referencedEvidenceIds) {
            if ($observationById.ContainsKey($evidenceId)) {
                New-AppExposureEvidenceHtml -Observation $observationById[$evidenceId] -ObjectPortalUrlById $objectPortalUrlById
            }
        }
    ) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($evidenceHtml)) {
        $evidenceHtml = '<p class="empty">No finding-linked observations are present.</p>'
    }

    $incompleteIds = @((Get-AppExposurePropertyValue -Object $collection -Name 'IncompleteObjectIds'))
    $incompleteText = if ($incompleteIds.Count -gt 0) { $incompleteIds -join ', ' } else { 'None' }
    $telemetry = Get-AppExposurePropertyValue -Object $collection -Name 'GraphTelemetry'

    $coreComplete = Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete'
    $scope = [string](Get-AppExposurePropertyValue -Object $collection -Name 'Scope')
    $scopeTarget = [string](Get-AppExposurePropertyValue -Object $collection -Name 'ScopeTarget')
    $scopeText = if ([string]::IsNullOrWhiteSpace($scopeTarget)) { $scope } else { "$($scope): $scopeTarget" }
    $clientName = [string](Get-AppExposurePropertyValue -Object $assessment -Name 'ClientName')
    $consultantName = [string](Get-AppExposurePropertyValue -Object $assessment -Name 'ConsultantName')
    $tenantName = [string](Get-AppExposurePropertyValue -Object $tenant -Name 'Name')
    $collectedAt = [string](Get-AppExposurePropertyValue -Object $Snapshot -Name 'CollectedAtUtc')
    $snapshotId = [string](Get-AppExposurePropertyValue -Object $Snapshot -Name 'SnapshotId')
    $script = Get-AppExposureReportClientScript

    $tenantPortalUrl = Get-AppExposurePortalBaseUri -TenantId $tenantId
    $severityChartHtml = New-AppExposureBarChartHtml -Items $severityChartItems -EmptyText 'No findings were produced.'
    $categoryChartHtml = New-AppExposureBarChartHtml -Items $categoryChartItems -EmptyText 'No finding categories were produced.'
    $classificationChartHtml = New-AppExposureBarChartHtml -Items $classificationChartItems -EmptyText 'No service-principal classification data is available.'
    $topAffectedIdentityHtml = New-AppExposureBarChartHtml -Items $topAffectedIdentityItems -EmptyText 'No actionable identities are affected by findings.'
    $activitySourceText = if ($activitySources.Count -gt 0) { $activitySources -join ', ' } else { 'Not collected' }

    $heroMeta = @"
<div class="hero-meta">
  <span class="pill">Collected $(ConvertTo-AppExposureReportHtml $collectedAt)</span>
  <span class="pill">Snapshot ID: $(ConvertTo-AppExposureReportHtml $snapshotId)</span>
</div>
"@

    $assessmentBody = @"
<section id="client-tenant-details" class="section">
  <div class="section-header"><h2>Tenant details</h2><span class="muted">Assessment context</span></div>
  <div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>
    <tr><td>Client</td><td>$(ConvertTo-AppExposureReportHtml $clientName)</td></tr>
    <tr><td>Consultant</td><td>$(ConvertTo-AppExposureReportHtml $consultantName)</td></tr>
    <tr><td>Tenant</td><td>$(ConvertTo-AppExposureReportHtml $tenantName)</td></tr>
    <tr><td>Tenant ID</td><td><code>$(ConvertTo-AppExposureReportHtml $tenantId)</code></td></tr>
    <tr><td>Scope</td><td>$(ConvertTo-AppExposureReportHtml $scopeText)</td></tr>
    <tr><td>Collected</td><td>$(ConvertTo-AppExposureReportHtml $collectedAt)</td></tr>
  </tbody></table></div>
</section>
<section id="overview" class="section">
  <div class="section-header"><h2>At a glance</h2><span class="muted">Assessment priorities and identity coverage</span></div>
  <div class="metric-grid">
    <div class="metric-card status-info"><div class="metric-label">Applications</div><div class="metric-value">$($applications.Count)</div><div class="metric-hint">Application registrations assessed; orphan: $orphanApplicationCount</div></div>
    <div class="metric-card status-info"><div class="metric-label">Service principals</div><div class="metric-value">$($servicePrincipals.Count)</div><div class="metric-hint">Enterprise application identities retained in snapshot</div></div>
    <div class="metric-card status-info"><div class="metric-label">Actionable identities</div><div class="metric-value">$actionableIdentityCount</div><div class="metric-hint">Distinct objects with High, Medium, or Low findings</div></div>
    <div class="metric-card severity-high"><div class="metric-label">Critical + High</div><div class="metric-value">$highPriorityFindingCount</div><div class="metric-hint">Highest-priority deterministic findings</div></div>
    <div class="metric-card status-info"><div class="metric-label">Actionable findings</div><div class="metric-value">$($actionableFindings.Count)</div><div class="metric-hint">Informational context excluded; context: $informationalFindingCount</div></div>
    <div class="metric-card severity-high"><div class="metric-label">P0 identities</div><div class="metric-value">$p0IdentityCount</div><div class="metric-hint">Correlation-gated immediate review priorities</div></div>
  </div>
</section>
<section id="analyst-focus" class="section">
  <div class="section-header"><h2>Analyst focus</h2><span class="muted">Identity-level exposure priority · defaults to P0</span></div>
  <p class="section-intro">P0 is reserved for the strongest correlated exposure chain: sensitive OAuth access combined with weak ownership/accountability and credential exposure. Trust, state, or configuration correlations without credential exposure remain lower priority. Priority is deterministic and explainable; it is not a numerical risk score.</p>
  $analystFocusHtml
</section>
<section id="exposure-distribution" class="section">
  <div class="section-header"><h2>Exposure distribution</h2><span class="muted">Counts only — no numerical risk score</span></div>
  <div class="visual-grid">
    <div class="viz-card"><h3>Actionable findings by severity</h3><p class="viz-subtitle">Informational context is excluded so the chart reflects the analyst work queue.</p><div class="bar-chart">$severityChartHtml</div></div>
    <div class="viz-card"><h3>Actionable findings by category</h3><p class="viz-subtitle">Where current High, Medium, and Low exposure evidence is concentrated.</p><div class="bar-chart">$categoryChartHtml</div></div>
    <div class="viz-card" style="grid-column:1/-1"><h3>Finding flow</h3><p class="viz-subtitle">All actionable flow combinations: severity → category → assessed identity type. Every non-informational finding is represented; link width reflects finding count, not a score.</p>$findingFlowHtml</div>
  </div>
</section>
<section id="identity-landscape" class="section">
  <div class="section-header"><h2>Application identity landscape</h2><span class="muted">Assessment context derived from the portable snapshot</span></div>
  <div class="visual-grid">
    <div class="viz-card"><h3>Service principals by classification</h3><p class="viz-subtitle">Microsoft first-party, tenant-local, third-party, and unresolved identities.</p><div class="bar-chart">$classificationChartHtml</div></div>
    <div class="viz-card"><h3>Top actionable identities</h3><p class="viz-subtitle">Up to 10 objects with the highest number of non-informational findings.</p><div class="bar-chart">$topAffectedIdentityHtml</div></div>
  </div>
</section>
<section id="findings" class="section">
  <div class="section-header"><h2>Findings</h2><span id="findingResultCount" class="muted">$($findingsArray.Count) individual · $($findingGroups.Count) grouped</span></div>
  <div class="finding-filter-panel" aria-label="Finding filters">
    <div class="filter-row" aria-label="Finding severity filters">
      <span class="filter-label">Severity</span>
      <button class="filter-button is-active" type="button" data-filter-severity="All">All</button>
      <button class="filter-button" type="button" data-filter-severity="Critical">Critical</button>
      <button class="filter-button" type="button" data-filter-severity="High">High</button>
      <button class="filter-button" type="button" data-filter-severity="Medium">Medium</button>
      <button class="filter-button" type="button" data-filter-severity="Low">Low</button>
      <button class="filter-button" type="button" data-filter-severity="Informational">Informational</button>
    </div>
    <div class="investigation-bar">
      <input id="findingSearch" type="search" placeholder="Search finding, object, rule, permission, recommendation, or evidence ID" aria-label="Search findings">
      <select id="kindFilter" aria-label="Filter findings by entry type"><option value="All">All entries</option><option value="Grouped">Grouped</option><option value="Individual">Individual</option></select>
      <select id="categoryFilter" aria-label="Filter findings by category"><option value="">All categories</option>$categoryOptions</select>
      <select id="spClassificationFilter" aria-label="Filter findings by service-principal classification"><option value="">All SP classifications</option>$spClassificationOptions</select>
      <button id="resetFilters" type="button">Clear filters</button>
    </div>
  </div>
  <p id="noFindingResults" class="empty-state" hidden>No findings match the current filters.</p>
  <div class="finding-list">$findingGroupHtml
$findingHtml</div>
  <div id="findingPagination" class="pagination-controls" aria-label="Finding pagination">
    <div class="pagination-main"><button id="findingPrevPage" type="button">Previous</button><div id="findingPageButtons" class="pagination-pages" aria-label="Finding pages"></div><button id="findingNextPage" type="button">Next</button><span id="findingPageSummary" class="pagination-summary"></span></div>
    <div class="pagination-size"><label for="findingPageSize">Per page</label><select id="findingPageSize"><option value="10">10</option><option value="20" selected>20</option><option value="50">50</option><option value="all">All</option></select></div>
  </div>
</section>
<section id="drift" class="section">
  <div class="section-header"><h2>Snapshot drift</h2><span class="muted">Semantic changes only</span></div>
  $driftHtml
</section>
"@

    $assessmentHtml = New-AppExposureReportDocument `
        -Title 'Entra App Exposure Assessment' `
        -Subtitle 'Read-only Microsoft Entra ID assessment. Start with P0 identity-level exposure priorities, then review grouped and individual findings, evidence, and snapshot drift.' `
        -Body $assessmentBody `
        -ActiveView 'Assessment' `
        -HeroMeta $heroMeta `
        -Script $script `
        -TenantPortalUrl $tenantPortalUrl

    $missingEvidenceNotice = if ($missingEvidenceIds.Count -gt 0) {
        '<div class="card"><span class="pill status-danger">Evidence integrity warning</span><p>' + (ConvertTo-AppExposureReportHtml ($missingEvidenceIds -join ', ')) + '</p></div>'
    }
    else {
        '<div class="card"><span class="pill status-success">Evidence integrity verified</span><p>Every finding ObservationId resolves to a canonical observation in snapshot.json.</p></div>'
    }

    $evidenceBody = @"
<section class="section">
  <div class="section-header"><h2>How to read this report</h2><span class="muted">Finding → Observation → snapshot evidence</span></div>
  <div class="card"><p style="margin:0"><strong>Grouped entries</strong> are tagged inside the same Findings workspace for rule-level triage. <strong>Individual findings</strong> remain deterministic per-identity outcomes, and <strong>observations</strong> are normalized evidence records from the portable snapshot. The source URI identifies the live collection surface; this evidence report itself performs no Graph calls.</p></div>
</section>
<section class="section">
  <div class="section-header"><h2>Evidence integrity</h2><span class="muted">$($referencedEvidenceIds.Count) finding-linked observation IDs</span></div>
  $missingEvidenceNotice
</section>
<section class="section">
  <div class="section-header"><h2>Evidence search</h2><span class="muted">Search exact observation provenance</span></div>
  <input id="sidecarSearch" class="filter" type="search" placeholder="Search observation ID, category, object, identity key, source URI, or fingerprint" aria-label="Search evidence">
</section>
<section class="section">
  <div class="section-header"><h2>Finding-linked observation index</h2><span class="muted">Detailed evidence stays secondary to assessment findings</span></div>
  <div class="evidence-index">$evidenceHtml</div>
</section>
"@

    $evidenceReportHtml = New-AppExposureReportDocument `
        -Title 'Entra App Exposure Evidence' `
        -Subtitle 'Offline finding-oriented evidence view. The portable snapshot remains the source of truth.' `
        -Body $evidenceBody `
        -ActiveView 'Evidence' `
        -HeroMeta $heroMeta `
        -Script $script `
        -TenantPortalUrl $tenantPortalUrl

    $telemetryRows = if ($telemetry) {
        @(
            [PSCustomObject]@{ Name='Physical Graph requests'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'Requests') },
            [PSCustomObject]@{ Name='Batch requests'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'BatchRequests') },
            [PSCustomObject]@{ Name='Batch subrequests'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'BatchSubRequests') },
            [PSCustomObject]@{ Name='Pages/subresponses collected'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'Pages') },
            [PSCustomObject]@{ Name='Retries'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'Retries') },
            [PSCustomObject]@{ Name='Throttles'; Value=(Get-AppExposurePropertyValue -Object $telemetry -Name 'Throttles') },
            [PSCustomObject]@{ Name='Activity evidence source'; Value=$activitySourceText },
            [PSCustomObject]@{ Name='Microsoft first-party finding evaluation'; Value=$(if ($ExcludeMicrosoftFirstParty) { 'Excluded' } else { 'Included' }) },
            [PSCustomObject]@{ Name='GraphCallsAfterSnapshot'; Value=$GraphCallsAfterSnapshot },
            [PSCustomObject]@{ Name='DriftStatus'; Value=$DriftStatus },
            [PSCustomObject]@{ Name='BaselineSnapshotId'; Value=$(if ($BaselineSnapshotId) { $BaselineSnapshotId } else { 'None' }) }
        )
    }
    else {
        @(
            [PSCustomObject]@{ Name='Telemetry'; Value='Not recorded' },
            [PSCustomObject]@{ Name='Activity evidence source'; Value=$activitySourceText },
            [PSCustomObject]@{ Name='Microsoft first-party finding evaluation'; Value=$(if ($ExcludeMicrosoftFirstParty) { 'Excluded' } else { 'Included' }) },
            [PSCustomObject]@{ Name='GraphCallsAfterSnapshot'; Value=$GraphCallsAfterSnapshot },
            [PSCustomObject]@{ Name='DriftStatus'; Value=$DriftStatus },
            [PSCustomObject]@{ Name='BaselineSnapshotId'; Value=$(if ($BaselineSnapshotId) { $BaselineSnapshotId } else { 'None' }) }
        )
    }

    $runtimeRows = New-Object System.Collections.Generic.List[object]
    $runtimeRows.Add([PSCustomObject]@{ Name='Run started (UTC)'; Value=$RunStartedAtUtc.ToUniversalTime().ToString('o') })
    foreach ($phaseName in @($PhaseTimingsMs.Keys)) {
        $runtimeRows.Add([PSCustomObject]@{ Name=('Phase: ' + [string]$phaseName); Value=([string]$PhaseTimingsMs[$phaseName] + ' ms') })
    }
    $telemetryTableRows = @($telemetryRows | ForEach-Object { '<tr><td>' + (ConvertTo-AppExposureReportHtml $_.Name) + '</td><td>' + (ConvertTo-AppExposureReportHtml $_.Value) + '</td></tr>' }) -join ''
    $runtimeTableRows = @($runtimeRows.ToArray() | ForEach-Object { '<tr><td>' + (ConvertTo-AppExposureReportHtml $_.Name) + '</td><td>' + (ConvertTo-AppExposureReportHtml $_.Value) + '</td></tr>' }) -join ''
    $runtimeChartItems = @(
        foreach ($phaseName in @($PhaseTimingsMs.Keys)) {
            [PSCustomObject]@{ Label=[string]$phaseName; Value=[int64]$PhaseTimingsMs[$phaseName]; Class='bar-brand' }
        }
    )
    $runtimeChartHtml = New-AppExposureBarChartHtml -Items $runtimeChartItems -EmptyText 'No phase timing telemetry was recorded.'
    $diagnosticStatusClass = if (($coreComplete -eq $true) -and $missingEvidenceIds.Count -eq 0) { 'status-success' } else { 'status-danger' }

    $diagnosticsBody = @"
<section class="section">
  <div class="section-header"><h2>Assessment integrity</h2><span class="pill $diagnosticStatusClass">Core complete: $(ConvertTo-AppExposureReportHtml $coreComplete)</span></div>
  <div class="trust-grid">
    <div class="trust-box"><h3>Snapshot</h3><p><strong>Schema:</strong> $(ConvertTo-AppExposureReportHtml (Get-AppExposurePropertyValue -Object $Snapshot -Name 'SchemaVersion'))<br><strong>Snapshot ID:</strong> <code>$(ConvertTo-AppExposureReportHtml $snapshotId)</code><br><strong>Collected:</strong> $(ConvertTo-AppExposureReportHtml $collectedAt)</p></div>
    <div class="trust-box"><h3>Scope</h3><p><strong>Scope:</strong> $(ConvertTo-AppExposureReportHtml $scopeText)<br><strong>Applications:</strong> $($applications.Count)<br><strong>Orphan applications:</strong> $orphanApplicationCount<br><strong>Service principals:</strong> $($servicePrincipals.Count)<br><strong>Observations:</strong> $($observations.Count)</p></div>
    <div class="trust-box"><h3>Evidence linkage</h3><p><strong>Individual findings:</strong> $($findingsArray.Count)<br><strong>Grouped findings:</strong> $($findingGroups.Count)<br><strong>Actionable findings:</strong> $($actionableFindings.Count)<br><strong>Referenced observations:</strong> $($referencedEvidenceIds.Count)<br><strong>Missing references:</strong> $($missingEvidenceIds.Count)</p></div>
  </div>
</section>
<section class="section">
  <div class="section-header"><h2>Collection diagnostics</h2><span class="muted">Captured during live Graph collection</span></div>
  <div class="table-wrap"><table class="data-table"><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>$telemetryTableRows</tbody></table></div>
</section>
<section class="section">
  <div class="section-header"><h2>Runtime phases</h2><span class="muted">Relative phase duration; final totals are recorded in run-summary.json</span></div>
  <div class="visual-grid">
    <div class="viz-card"><h3>Phase duration</h3><p class="viz-subtitle">Milliseconds. Longer bars identify the dominant collection or analysis stages.</p><div class="bar-chart">$runtimeChartHtml</div></div>
    <div class="viz-card"><h3>Exact timings</h3><div class="table-wrap"><table class="data-table"><thead><tr><th>Phase</th><th>Value</th></tr></thead><tbody>$runtimeTableRows</tbody></table></div></div>
  </div>
</section>
<section class="section">
  <div class="section-header"><h2>Incomplete object IDs</h2><span class="muted">Absence-based conclusions require complete collection</span></div>
  <div class="card"><code>$(ConvertTo-AppExposureReportHtml $incompleteText)</code></div>
</section>
"@

    $diagnosticsReportHtml = New-AppExposureReportDocument `
        -Title 'Entra App Exposure Diagnostics' `
        -Subtitle 'Collection completeness, evidence linkage, and runtime collection telemetry. No security score is calculated.' `
        -Body $diagnosticsBody `
        -ActiveView 'Diagnostics' `
        -HeroMeta $heroMeta `
        -Script $script `
        -TenantPortalUrl $tenantPortalUrl

    $assessmentHtml | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    $evidenceReportHtml | Set-Content -LiteralPath $evidenceHtmlPath -Encoding UTF8
    $diagnosticsReportHtml | Set-Content -LiteralPath $diagnosticsHtmlPath -Encoding UTF8

    $reportExportStopwatch.Stop()
    $PhaseTimingsMs['ReportExport'] = [int64][Math]::Round($reportExportStopwatch.Elapsed.TotalMilliseconds)
    $completedAtUtc = [datetime]::UtcNow
    $runDurationMs = [int64][Math]::Max(0, [Math]::Round(($completedAtUtc - $RunStartedAtUtc.ToUniversalTime()).TotalMilliseconds))
    $phaseObject = [ordered]@{}
    foreach ($phaseName in @($PhaseTimingsMs.Keys)) { $phaseObject[[string]$phaseName] = [int64]$PhaseTimingsMs[$phaseName] }
    $runTelemetry = [PSCustomObject]@{
        StartedAtUtc         = $RunStartedAtUtc.ToUniversalTime().ToString('o')
        CompletedAtUtc       = $completedAtUtc.ToString('o')
        TotalDurationMs      = $runDurationMs
        TotalDurationSeconds = [Math]::Round(($runDurationMs / 1000.0), 3)
        PhasesMs             = [PSCustomObject]$phaseObject
    }

    $summary = [PSCustomObject]@{
        SnapshotId              = Get-AppExposurePropertyValue -Object $Snapshot -Name 'SnapshotId'
        SchemaVersion           = Get-AppExposurePropertyValue -Object $Snapshot -Name 'SchemaVersion'
        CollectedAtUtc          = Get-AppExposurePropertyValue -Object $Snapshot -Name 'CollectedAtUtc'
        TenantId                = Get-AppExposurePropertyValue -Object $tenant -Name 'Id'
        TenantName              = Get-AppExposurePropertyValue -Object $tenant -Name 'Name'
        ClientName              = Get-AppExposurePropertyValue -Object $assessment -Name 'ClientName'
        ConsultantName          = Get-AppExposurePropertyValue -Object $assessment -Name 'ConsultantName'
        Scope                   = Get-AppExposurePropertyValue -Object $collection -Name 'Scope'
        ScopeTarget             = Get-AppExposurePropertyValue -Object $collection -Name 'ScopeTarget'
        CoreCollectionComplete  = Get-AppExposurePropertyValue -Object $collection -Name 'CoreComplete'
        ApplicationCount        = $applications.Count
        OrphanApplicationCount  = $orphanApplicationCount
        ServicePrincipalCount   = $servicePrincipals.Count
        ObservationCount        = $observations.Count
        FindingCount            = $findingsArray.Count
        GroupedFindingCount     = $findingGroups.Count
        ActionableFindingCount  = $actionableFindings.Count
        InformationalFindingCount = $informationalFindingCount
        AffectedIdentityCount   = $affectedIdentityCount
        ActionableIdentityCount = $actionableIdentityCount
        P0IdentityCount          = $p0IdentityCount
        ExcludeMicrosoftFirstParty = [bool]$ExcludeMicrosoftFirstParty
        MicrosoftFirstPartyServicePrincipalCount = $firstPartyServicePrincipalCount
        ActivityEvidenceSources = @($activitySources)
        Generator               = 'Entra App Exposure'
        Author                  = 'Alaaeddine Ayedi'
        ProjectUri              = 'https://github.com/0xDarknightHacks/EntraAppExposure'
        DriftStatus             = $DriftStatus
        BaselineSnapshotId      = $BaselineSnapshotId
        BaselineCollectedAtUtc  = $BaselineCollectedAtUtc
        DriftCount              = $driftArray.Count
        GraphCallsAfterSnapshot = $GraphCallsAfterSnapshot
        SeverityCounts          = [PSCustomObject]$severityCounts
        RulePack                = $(if ($RulePackPath) { Split-Path -Leaf $RulePackPath } else { $null })
        GraphTelemetry          = Get-AppExposurePropertyValue -Object $collection -Name 'GraphTelemetry'
        RunTelemetry            = $runTelemetry
    }
    $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

    $manifest = New-AppExposureArtifactManifest -OutputDirectory $OutputDirectory -Snapshot $Snapshot -Findings $findingsArray -FindingGroups $findingGroups -Drift $driftArray -DriftStatus $DriftStatus -BaselineSnapshotId $BaselineSnapshotId -GraphCallsAfterSnapshot $GraphCallsAfterSnapshot
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    return [PSCustomObject]@{
        FindingsJson          = (Resolve-Path -LiteralPath $findingsPath).Path
        FindingGroupsJson     = (Resolve-Path -LiteralPath $findingGroupsPath).Path
        FindingsCsv           = (Resolve-Path -LiteralPath $findingsCsvPath).Path
        DriftJson             = (Resolve-Path -LiteralPath $driftPath).Path
        SummaryJson           = (Resolve-Path -LiteralPath $summaryPath).Path
        HtmlReport            = (Resolve-Path -LiteralPath $htmlPath).Path
        EvidenceHtmlReport    = (Resolve-Path -LiteralPath $evidenceHtmlPath).Path
        DiagnosticsHtmlReport = (Resolve-Path -LiteralPath $diagnosticsHtmlPath).Path
        ArtifactManifest      = (Resolve-Path -LiteralPath $manifestPath).Path
        RunTelemetry          = $runTelemetry
    }
}

