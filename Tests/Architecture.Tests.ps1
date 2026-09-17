#Requires -Modules Pester

Describe 'Lean Entra App Exposure repository architecture' {
    BeforeAll {
        $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
        Import-Module (Join-Path $root 'EntraAppExposure.psd1') -Force
    }

    It 'uses one canonical module and one public command' {
        foreach ($path in @(
            'EntraAppExposure.psd1','EntraAppExposure.psm1','Public/Invoke-EntraAppExposure.ps1'
        )) { Test-Path -LiteralPath (Join-Path $root $path) | Should -BeTrue }
        $manifest = Test-ModuleManifest -Path (Join-Path $root 'EntraAppExposure.psd1')
        @($manifest.ExportedFunctions.Keys) | Should -Be @('Invoke-EntraAppExposure')
    }

    It 'keeps the private runtime intentionally flat and compact' {
        $expected = @('Auth.ps1','Collection.ps1','Common.ps1','Drift.ps1','Graph.ps1','Pipeline.ps1','Reporting.ps1','Rules.ps1','Snapshot.ps1')
        $actual = @(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1' | Select-Object -ExpandProperty Name | Sort-Object)
        $actual | Should -Be ($expected | Sort-Object)
        @(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -Directory).Count | Should -Be 0
    }

    It 'contains no transitional production module and ignores generated reports' {
        foreach ($path in @('Modules','Tests/Support','OAuthApplicationIdentityExposureAnalyzer.psd1','EntraApplicationExposureAnalyzer.psd1','EntraApplicationExposureAnalyzer.psm1')) {
            Test-Path -LiteralPath (Join-Path $root $path) | Should -BeFalse -Because "legacy architecture path '$path' must be absent"
        }
        Get-Content -LiteralPath (Join-Path $root '.gitignore') | Should -Contain '/Reports/'
    }

    It 'keeps Graph transport in Auth and Graph only' {
        $runtimeFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1' | Where-Object Name -notin @('Auth.ps1','Graph.ps1'))
        $runtimeFiles += @(Get-ChildItem -LiteralPath (Join-Path $root 'Public') -File -Filter '*.ps1')
        $runtimeFiles += @(Get-Item -LiteralPath (Join-Path $root 'EntraAppExposure.psm1'))
        (($runtimeFiles | Get-Content -Raw) -join "`n") | Should -Not -Match 'Invoke-RestMethod|Invoke-MgGraphRequest|Connect-MgGraph|Get-MgContext|Disconnect-MgGraph'
        (Get-Content -LiteralPath (Join-Path $root 'Private/Graph.ps1') -Raw) | Should -Match 'Invoke-RestMethod'
    }

    It 'keeps snapshot, rules, drift and reporting offline from Graph' {
        foreach ($path in @('Private/Snapshot.ps1','Private/Rules.ps1','Private/Drift.ps1','Private/Reporting.ps1')) {
            (Get-Content -LiteralPath (Join-Path $root $path) -Raw) | Should -Not -Match 'Invoke-AppExposureGraphRequest|Invoke-MgGraphRequest|Connect-MgGraph|Invoke-RestMethod'
        }
    }


    It 'uses the canonical external rule baseline and EAE taxonomy' {
        Test-Path -LiteralPath (Join-Path $root 'Rules/Baseline.json') | Should -BeTrue
        $baseline = Get-Content -LiteralPath (Join-Path $root 'Rules/Baseline.json') -Raw | ConvertFrom-Json
        @($baseline.Definitions).Count | Should -BeGreaterOrEqual 25
        @($baseline.Definitions | Select-Object -ExpandProperty Id -Unique).Count | Should -Be @($baseline.Definitions).Count
        [string]$baseline.SchemaVersion | Should -Be '2.1'
        foreach ($rule in @($baseline.Definitions)) {
            [string]$rule.Id | Should -Match '^EAE-[A-Z]+(?:-[A-Z]+)*-[0-9]{3}$'
            @($rule.RequiredEvidence).Count | Should -BeGreaterThan 0
        }
        foreach ($entry in @($baseline.Policy.SensitiveApplicationPermissions) + @($baseline.Policy.SensitiveDelegatedPermissions)) {
            [string]$entry.ResourceAppId | Should -Not -BeNullOrEmpty
            [string]$entry.PermissionValue | Should -Not -BeNullOrEmpty
        }
        [int]$baseline.Policy.Activity.MinimumReviewLookbackDays | Should -Be 90
    }

    It 'exports only the canonical public assessment command' {
        $module = Get-Module EntraAppExposure
        @($module.ExportedFunctions.Keys) | Should -Be @('Invoke-EntraAppExposure')
    }

    It 'exposes the expected public invocation parameters' {
        $parameters = (Get-Command Invoke-EntraAppExposure).Parameters.Keys
        foreach ($name in @('ConfigPath','SecretVault','SecretName','OutputDirectory','Scope','IncludeActivity','ActivityLookbackDays','ExcludeMicrosoftFirstParty','BaselineSnapshotPath','OfflineSnapshotPath','RulePackPath')) { $parameters | Should -Contain $name }
    }

    It 'contains no numerical scoring engine or dotenv implementation' {
        $text = ((Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1' | Get-Content -Raw) -join "`n")
        $text | Should -Not -Match 'PSSQLite|Invoke-Sqlite|Out-DataTable|Import-DotEnvFile|Get-AppExposureRiskScore|Get-AppExposureScoringModel'
    }

    It 'keeps private function names unique in root module scope' {
        $functions = @{}
        foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $root 'Private') -File -Filter '*.ps1')) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($match in [regex]::Matches($content, '(?im)^\s*function\s+([A-Za-z0-9_-]+)\b')) {
                $name = $match.Groups[1].Value.ToLowerInvariant()
                if ($functions.ContainsKey($name)) { throw "Duplicate private function '$($match.Groups[1].Value)' in '$($functions[$name])' and '$($file.Name)'." }
                $functions[$name] = $file.Name
            }
        }
        $functions.Count | Should -BeGreaterThan 0
    }
}
