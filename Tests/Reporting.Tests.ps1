#Requires -Modules Pester
BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\EntraAppExposure.psd1') -Force }

InModuleScope EntraAppExposure {
Describe 'Standalone report UI component' {
    It 'exposes a stable semantic version and standalone report shell' {
        Get-AppExposureReportUiVersion | Should -Be '1.4.1'
        
        $navigation = @(
            [PSCustomObject]@{ Label='Overview'; File='index.html'; View='Overview' },
            [PSCustomObject]@{ Label='Evidence'; File='evidence.html'; View='Evidence' }
        )
        $html = New-AppExposureReportUiDocument `
            -Title 'Example report' `
            -Subtitle 'Example subtitle' `
            -Body '<section>Body</section>' `
            -Brand 'Example Tool' `
            -Footer 'Static offline report' `
            -Navigation $navigation `
            -ActiveView 'Overview' `
            -Script (Get-AppExposureReportClientScript)

        $html | Should -Match ('data-entra-app-exposure-report-ui="{0}"' -f [regex]::Escape((Get-AppExposureReportUiVersion)))
        $html | Should -Match 'Example Tool'
        $html | Should -Match 'href="index.html"'
        $html | Should -Match 'href="evidence.html"'
        $html | Should -Match 'id="themeToggle"'
        $html | Should -Match 'findingPageSize'
        $html | Should -Match 'pagination-controls'
        $html | Should -Not -Match '<script\s+[^>]*src='
        $html | Should -Not -Match '<link\s+[^>]*rel=["'']stylesheet'
    }

    It 'contains no Graph transport dependency' {
        $reportingPath = Join-Path (Get-Module EntraAppExposure).ModuleBase 'Private\Reporting.ps1'
        $text = Get-Content -LiteralPath $reportingPath -Raw
        $text | Should -Not -Match 'Invoke-MgGraphRequest|Invoke-AppExposureGraphRequest|Connect-AppExposureGraph|Invoke-RestMethod'
    }

    It 'provides reusable status, severity, search, and evidence primitives' {
        Get-AppExposureReportSeverityClass -Severity 'Critical' | Should -Be 'severity-critical'
        Get-AppExposureReportStatusClass -Value 'Complete' | Should -Be 'status-success'
        ConvertTo-AppExposureReportSearchAttribute -Values @('Hello','WORLD') | Should -Be 'hello world'
        ConvertTo-AppExposureReportHtml '<unsafe>' | Should -Be '&lt;unsafe&gt;'
        ConvertTo-AppExposureReportEvidenceJson ([PSCustomObject]@{ Value='<x>' }) | Should -Match '&quot;Value&quot;'
    }

    It 'prioritizes correlated identity exposure independently from finding severity' {
        $findings = @(
            [PSCustomObject]@{ FindingId='f1'; RuleId='EAE-OAUTH-APP-001'; Severity='High'; Category='ApplicationPermission'; ObjectId='sp1'; ObjectDisplayName='Priority App' },
            [PSCustomObject]@{ FindingId='f2'; RuleId='EAE-SP-OWNER-001'; Severity='Medium'; Category='Ownership'; ObjectId='sp1'; ObjectDisplayName='Priority App' },
            [PSCustomObject]@{ FindingId='f3'; RuleId='EAE-APP-CRED-003'; Severity='Medium'; Category='Credential'; ObjectId='app1'; ObjectDisplayName='Priority App Registration' },
            [PSCustomObject]@{ FindingId='f4'; RuleId='EAE-OAUTH-APP-001'; Severity='High'; Category='ApplicationPermission'; ObjectId='sp2'; ObjectDisplayName='High Only' }
        )
        $apps = @([PSCustomObject]@{ ObjectId='app1'; DisplayName='Priority App Registration' })
        $sps = @(
            [PSCustomObject]@{ ObjectId='sp1'; DisplayName='Priority App'; AppRegistrationObjectId='app1' },
            [PSCustomObject]@{ ObjectId='sp2'; DisplayName='High Only'; AppRegistrationObjectId=$null }
        )
        $priorities = @(New-AppExposureIdentityPriorities -Applications $apps -ServicePrincipals $sps -Findings $findings)
        ($priorities | Where-Object ObjectId -eq 'sp1').Priority | Should -Be 'P0'
        ($priorities | Where-Object ObjectId -eq 'sp2').Priority | Should -Not -Be 'P0'
    }

    It 'renders every actionable Sankey flow combination without a Top-N cap' {
        $findings = @(1..20 | ForEach-Object { [PSCustomObject]@{ Severity='Medium'; Category=('Category' + $_); ObjectId='sp1' } })
        $html = New-AppExposureFindingSankeyHtml -Findings $findings -ObjectTypeById @{ sp1='Service principal' }
        $html | Should -Match 'Category1'
        $html | Should -Match 'Category20'
        $html | Should -Not -Match 'Top 18|First 18'
        $html | Should -Match 'viewBox="0 0 980 [0-9]+"'
    }

    It 'groups only repeated rule instances and renders grouped entries with the individual finding structure' {
        $findings = @(
            [PSCustomObject]@{
                FindingId='FND-1'; RuleId='EAE-OAUTH-APP-001'; Severity='High'; Category='ApplicationPermission';
                ObjectId='sp1'; ObjectDisplayName='Example One'; Title='Sensitive application permissions present';
                WhyItMatters='Standing app-only access.'; Recommendation='Review the grant.';
                References=@('https://learn.microsoft.com/example'); EvidenceIds=@('OBS-1'); EvidenceSummary=@('Permission one')
            },
            [PSCustomObject]@{
                FindingId='FND-2'; RuleId='EAE-OAUTH-APP-001'; Severity='High'; Category='ApplicationPermission';
                ObjectId='sp2'; ObjectDisplayName='Example Two'; Title='Sensitive application permissions present';
                WhyItMatters='Standing app-only access.'; Recommendation='Review the grant.';
                References=@('https://learn.microsoft.com/example'); EvidenceIds=@('OBS-2'); EvidenceSummary=@('Permission two')
            }
        )

        @(New-AppExposureFindingGroups -Findings @($findings[0])).Count | Should -Be 0
        $groups = @(New-AppExposureFindingGroups -Findings $findings)
        $groups.Count | Should -Be 1
        $groups[0].FindingCount | Should -Be 2
        $groups[0].AffectedObjectCount | Should -Be 2

        $html = New-AppExposureFindingGroupHtml -Group $groups[0] -EvidenceFileName 'evidence.html' -ObjectPortalUrlById @{ sp1='https://entra.microsoft.com/#view/sp1' } -ObjectSpClassificationById @{ sp1='Local'; sp2='ThirdParty' }
        $html | Should -Match 'class="finding-card finding-group-card"'
        $html | Should -Match 'class="finding-top"'
        $html | Should -Match 'What happened'
        $html | Should -Match 'Why it matters'
        $html | Should -Match 'Recommended action'
        $html | Should -Match 'Evidence · 2 observation reference'
        $html | Should -Match 'Permission one'
        $html | Should -Match 'grouped-tag'
        $html | Should -Match 'href="evidence.html#evidence-OBS-1"'
        $html | Should -Match '2 affected identity'
    }

}

Describe 'Offline report export' {
    It 'writes valid empty artifacts and a self-contained three-view HTML report when there are no findings or drift' {
        $snapshot = [PSCustomObject]@{
            SchemaVersion='2.1'; SnapshotId='snap1'; CollectedAtUtc='2026-09-08T12:00:00Z';
            Tenant=[PSCustomObject]@{ Id='tenant1'; Name='Tenant One' };
            Assessment=[PSCustomObject]@{ ClientName='Client'; ConsultantName='Analyst' };
            Collection=[PSCustomObject]@{
                Scope='All'; ScopeTarget=$null; CoreComplete=$true; IncompleteObjectIds=@();
                ApplicationCount=0; ServicePrincipalCount=0; ObservationCount=0; GraphTelemetry=$null
            };
            Applications=@(); ServicePrincipals=@(); Observations=@()
        }

        $out = Join-Path $TestDrive 'report'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $snapshot | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $out 'snapshot.json') -Encoding UTF8
        $artifacts = Export-AppExposureAssessment -Snapshot $snapshot -Findings @() -Drift @() -DriftStatus NotCompared -GraphCallsAfterSnapshot 0 -OutputDirectory $out

        @(Get-Content -LiteralPath $artifacts.FindingsJson -Raw | ConvertFrom-Json).Count | Should -Be 0
        $driftDocument = Get-Content -LiteralPath $artifacts.DriftJson -Raw | ConvertFrom-Json
        $driftDocument.DriftStatus | Should -Be 'NotCompared'
        $driftDocument.ChangeCount | Should -Be 0
        (Get-Content -LiteralPath $artifacts.FindingsCsv -First 1) | Should -Match 'FindingId'

        Test-Path -LiteralPath $artifacts.HtmlReport | Should -BeTrue
        Test-Path -LiteralPath $artifacts.EvidenceHtmlReport | Should -BeTrue
        Test-Path -LiteralPath $artifacts.FindingGroupsJson | Should -BeTrue
        @(Get-Content -LiteralPath $artifacts.FindingGroupsJson -Raw | ConvertFrom-Json).Count | Should -Be 0
        Test-Path -LiteralPath $artifacts.DiagnosticsHtmlReport | Should -BeTrue
        Test-Path -LiteralPath $artifacts.ArtifactManifest | Should -BeTrue
        $manifest = Get-Content -LiteralPath $artifacts.ArtifactManifest -Raw | ConvertFrom-Json
        $manifest.ArtifactCount | Should -Be 9
        @($manifest.Artifacts | Where-Object { $_.Name -eq 'snapshot.json' -and $_.Sha256 -match '^[0-9a-f]{64}$' }).Count | Should -Be 1

        $html = Get-Content -LiteralPath $artifacts.HtmlReport -Raw
        $html | Should -Match 'data-entra-app-exposure-report-ui="1.4.1"'
        $html | Should -Match 'data-entra-app-exposure-report-shell="1.0"'
        $html | Should -Match 'id="themeToggle"'
        $html | Should -Match 'id="findingSearch"'
        $html | Should -Match 'id="findingPagination"'
        $html | Should -Match 'id="findingPageSize"'
        $html | Should -Match 'Findings by severity'
        $html | Should -Match 'Service principals by classification'
        $html | Should -Match 'href="evidence.html"'
        $html | Should -Match 'href="diagnostics.html"'
        $html | Should -Match 'id="kindFilter"'
        $html | Should -Match '<option value="Grouped">Grouped</option>'
        $html | Should -Match 'id="spClassificationFilter"'
        $html | Should -Match 'Analyst focus'
        $html | Should -Match 'data-focus-priority="P0"'
        $html | Should -Match 'aria-label="Entra App Exposure project mark"'
        $html | Should -Match '>EA</span>'
        $html | Should -Not -Match 'class="ms-mark"'
        $html | Should -Match 'not affiliated with, sponsored by, or endorsed by Microsoft'
        $html | Should -Not -Match '<td>Microsoft first-party enterprise apps</td>'
        $html | Should -Not -Match '<td>Activity evidence source</td>'
        $html | Should -Not -Match '<div class="metric-label">Core collection</div>'
        $html | Should -Not -Match '<h2>Assessment integrity</h2>'
        $html | Should -Match 'Built by Alaaeddine Ayedi'
        $html | Should -Match 'github.com/0xDarknightHacks'
        $html | Should -Not -Match '<script\s+[^>]*src='
        $html | Should -Not -Match '<link\s+[^>]*rel=["'']stylesheet'
    }

    It 'links each finding to exact canonical evidence in the evidence sidecar' {
        $observation = [PSCustomObject]@{
            ObservationId='OBS-123'; ObservationKey='sp1|ApplicationPermission|resource|role';
            ObjectId='sp1'; ObjectDisplayName='Example App'; Category='ApplicationPermission';
            IdentityKey='resource|role'; Fingerprint='abc123'; SourceUri='https://graph.microsoft.com/v1.0/servicePrincipals/sp1/appRoleAssignments';
            CollectedAtUtc='2026-09-08T12:00:00Z'; Value=[PSCustomObject]@{ PermissionValue='Directory.ReadWrite.All'; ResourceDisplayName='Microsoft Graph' }
        }
        $snapshot = [PSCustomObject]@{
            SchemaVersion='2.1'; SnapshotId='snap2'; CollectedAtUtc='2026-09-08T12:00:00Z';
            Tenant=[PSCustomObject]@{ Id='tenant1'; Name='Tenant One' };
            Assessment=[PSCustomObject]@{ ClientName='Client'; ConsultantName='Analyst' };
            Collection=[PSCustomObject]@{ Scope='Single'; ScopeTarget='app1'; CoreComplete=$true; IncompleteObjectIds=@(); ApplicationCount=1; ServicePrincipalCount=1; ObservationCount=1; GraphTelemetry=[PSCustomObject]@{ Requests=3; BatchRequests=1; BatchSubRequests=2; Pages=3; Retries=0; Throttles=0 } };
            Applications=@([PSCustomObject]@{ ObjectId='appobj1'; AppId='app1'; DisplayName='Example App Registration' }); ServicePrincipals=@([PSCustomObject]@{ ObjectId='sp1'; AppId='app1'; DisplayName='Example App' }); Observations=@($observation)
        }
        $finding = [PSCustomObject]@{
            FindingId='FND-1'; RuleId='EAE-OAUTH-APP-001'; Severity='High'; Category='ApplicationPermission';
            ObjectDisplayName='Example App'; ObjectId='sp1'; Title='Sensitive application permissions present';
            WhatHappened='Sensitive permission present.'; WhyItMatters='Standing app-only access.'; Recommendation='Review the grant.';
            References=@('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners');
            EvidenceIds=@('OBS-123'); EvidenceSummary=@('Directory.ReadWrite.All')
        }

        $out = Join-Path $TestDrive 'report-with-evidence'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $snapshot | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $out 'snapshot.json') -Encoding UTF8
        $artifacts = Export-AppExposureAssessment -Snapshot $snapshot -Findings @($finding) -Drift @() -DriftStatus Compared -BaselineSnapshotId 'baseline-1' -BaselineCollectedAtUtc '2026-09-01T12:00:00Z' -GraphCallsAfterSnapshot 0 -OutputDirectory $out
        $html = Get-Content -LiteralPath $artifacts.HtmlReport -Raw
        $evidenceHtml = Get-Content -LiteralPath $artifacts.EvidenceHtmlReport -Raw
        $diagnosticsHtml = Get-Content -LiteralPath $artifacts.DiagnosticsHtmlReport -Raw

        $html | Should -Match 'href="evidence.html#evidence-OBS-123"'
        $html | Should -Match 'Open in Entra'
        $html | Should -Match 'ManagedAppMenuBlade'
        $html | Should -Match 'Rule reference'
        $html | Should -Match 'learn.microsoft.com'
        $html | Should -Not -Match 'data-kind="Grouped"'
        $html | Should -Match 'finding-sankey'
        $html | Should -Match 'Actionable findings'
        $groups = @(Get-Content -LiteralPath $artifacts.FindingGroupsJson -Raw | ConvertFrom-Json)
        $groups.Count | Should -Be 0
        $evidenceHtml | Should -Match 'id="evidence-OBS-123"'
        $evidenceHtml | Should -Match 'Directory.ReadWrite.All'
        $evidenceHtml | Should -Match 'Evidence integrity verified'
        $diagnosticsHtml | Should -Match 'Evidence linkage'
        $diagnosticsHtml | Should -Match '<td>Physical Graph requests</td><td>3</td>'
        $diagnosticsHtml | Should -Match '<td>Batch requests</td><td>1</td>'
        $diagnosticsHtml | Should -Match '<td>Batch subrequests</td><td>2</td>'
        $diagnosticsHtml | Should -Match 'Missing references:</strong> 0'
        $diagnosticsHtml | Should -Match 'GraphCallsAfterSnapshot'
        $diagnosticsHtml | Should -Match 'Phase duration'
        $diagnosticsHtml | Should -Match 'bar-chart'
        $summary = Get-Content -LiteralPath $artifacts.SummaryJson -Raw | ConvertFrom-Json
        $summary.DriftStatus | Should -Be 'Compared'
        $summary.BaselineSnapshotId | Should -Be 'baseline-1'
        $summary.GraphCallsAfterSnapshot | Should -Be 0
        $summary.GroupedFindingCount | Should -Be 0
        $summary.ActionableFindingCount | Should -Be 1
        $summary.Author | Should -Be 'Alaaeddine Ayedi'
        $summary.ProjectUri | Should -Be 'https://github.com/0xDarknightHacks/EntraAppExposure'
        $null -ne $summary.RunTelemetry | Should -BeTrue
        [double]$summary.RunTelemetry.TotalDurationMs | Should -BeGreaterOrEqual 0
        $null -ne $summary.RunTelemetry.PhasesMs.ReportExport | Should -BeTrue
        $null -ne $artifacts.RunTelemetry | Should -BeTrue

        foreach ($document in @($html, $evidenceHtml, $diagnosticsHtml)) {
            $document | Should -Not -Match '<script\s+[^>]*src='
            $document | Should -Not -Match '<link\s+[^>]*rel=["'']stylesheet'
        }
    }
}
}
