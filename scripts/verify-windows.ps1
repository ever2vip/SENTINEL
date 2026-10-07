[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SetupPath,
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\artifacts\windows-verification'),
    [string]$ExpectedVersion = '1.1.0',
    [string]$BaselineSetupPath,
    [string]$BaselineSetupSha256 = '13b2d877223657b604c7607179afe91b151d8331308ddc8f299378da50b64ad2',
    [string]$UpgradeProbePath,
    [string]$DesktopAcceptanceScript,
    [switch]$InstallUninstall,
    [switch]$DesktopSmoke
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This verification script requires Windows PowerShell 7 or later on Windows x64.' }
$SetupPath = [IO.Path]::GetFullPath($SetupPath)
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
foreach ($pathParameter in @('BaselineSetupPath', 'UpgradeProbePath', 'DesktopAcceptanceScript')) {
    $value = Get-Variable -Name $pathParameter -ValueOnly
    if ($value) {
        $resolved = [IO.Path]::GetFullPath($value)
        Write-Host "Windows verification dependency [$pathParameter]: $resolved"
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Missing Windows verification dependency '$pathParameter': $resolved" }
        Set-Variable -Name $pathParameter -Value $resolved
    }
}
if ($BaselineSetupPath -and (-not $InstallUninstall -or -not $UpgradeProbePath)) {
    throw 'V1.0 upgrade verification requires -InstallUninstall and the published -UpgradeProbePath.'
}
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$checks = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [scriptblock]$Operation) {
    try {
        & $Operation
        $checks.Add([ordered]@{ name = $Name; status = 'passed'; details = '' })
    } catch {
        $checks.Add([ordered]@{ name = $Name; status = 'failed'; details = $_.Exception.Message })
        throw
    }
}
function Run-Installer([string]$Path, [string[]]$Arguments) {
    $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Installer returned $($process.ExitCode)." }
}
function Assert-InstalledVersion([string]$Version) {
    $installed = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL' -Name DisplayVersion
    if ($installed -ne $Version) { throw "Expected installed SENTINEL $Version; found $installed." }
}
function Run-UpgradeProbe([string]$Mode, [string]$ResultPath) {
    & dotnet $UpgradeProbePath --mode $Mode --desktop (Join-Path $installDirectory 'Desktop') --data (Join-Path $env:LOCALAPPDATA 'Sentinel') --result $ResultPath
    if ($LASTEXITCODE -ne 0) { throw "Installed application upgrade probe failed with exit code $LASTEXITCODE." }
}
function Wait-Health {
    $path = Join-Path $env:ProgramData 'Sentinel\ServiceState\health.json'
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (Test-Path -LiteralPath $path) {
            $health = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($health.status -eq 'healthy' -and $health.assessmentsEnabled -eq $false -and ([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($health.heartbeatAtUtc)).TotalSeconds -lt 90) { return $health }
        }
        Start-Sleep -Seconds 1
    }
    throw 'The maintenance service did not produce a fresh healthy heartbeat.'
}
$installDirectory = Join-Path $env:ProgramFiles 'SENTINEL'
$desktop = $null
try {
    Check 'installer-exists' { if (-not (Test-Path -LiteralPath $SetupPath -PathType Leaf)) { throw 'Installer not found.' } }
    Check 'installer-is-pe' {
        $stream = [IO.File]::OpenRead($SetupPath)
        try { if ($stream.ReadByte() -ne 0x4d -or $stream.ReadByte() -ne 0x5a) { throw 'Installer is not a PE executable.' } } finally { $stream.Dispose() }
    }
    Get-FileHash -LiteralPath $SetupPath -Algorithm SHA256 | ConvertTo-Json | Set-Content (Join-Path $EvidenceDirectory 'setup-sha256.json')
    Get-AuthenticodeSignature -LiteralPath $SetupPath | Select-Object Status, StatusMessage | ConvertTo-Json | Set-Content (Join-Path $EvidenceDirectory 'authenticode.json')
    if ($InstallUninstall) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Install/uninstall verification requires an elevated disposable Windows VM.' }
        if (Get-Service -Name SentinelMaintenance -ErrorAction SilentlyContinue) { throw 'Use a clean disposable VM: SENTINEL is already installed.' }
        if (Test-Path -LiteralPath $installDirectory) { throw 'Use a clean disposable VM: the SENTINEL installation directory already exists.' }
        if ($BaselineSetupPath -and (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Sentinel'))) { throw 'Actual V1.0 upgrade QA requires a clean disposable operator profile; SENTINEL user data already exists.' }
        Check 'silent-install' { Run-Installer $SetupPath @('/S'); Assert-InstalledVersion $ExpectedVersion }
        Check 'service-account-and-start' {
            $service = Get-CimInstance Win32_Service -Filter "Name='SentinelMaintenance'"
            if (-not $service -or $service.StartName -ne 'NT AUTHORITY\LocalService' -or $service.State -ne 'Running') { throw 'Service did not run as LocalService.' }
            if (-not $service.PathName.StartsWith('"') -or -not $service.PathName.EndsWith('"')) { throw 'Service executable path was not quoted.' }
            $service | Select-Object Name, StartName, State, PathName, StartMode | ConvertTo-Json | Set-Content (Join-Path $EvidenceDirectory 'service.json')
        }
        Check 'service-health' { Wait-Health | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $EvidenceDirectory 'health.json') }
        Check 'service-boundaries' {
            $state = Join-Path $env:ProgramData 'Sentinel\ServiceState'
            $logs = Join-Path $env:ProgramData 'Sentinel\ServiceLogs'
            $stateAcl = Get-Acl -LiteralPath $state
            $logsAcl = Get-Acl -LiteralPath $logs
            foreach ($acl in @($stateAcl, $logsAcl)) {
                if (-not $acl.AreAccessRulesProtected) { throw 'Service data ACLs inherited unexpected permissions.' }
            }
            $userRules = @($stateAcl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' -and $_.AccessControlType -eq 'Allow' })
            foreach ($rule in $userRules) {
                if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0) { throw 'Ordinary Users can write service state.' }
            }
            if (@($logsAcl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' }).Count -ne 0) { throw 'Service logs are readable by ordinary Users.' }
            $aclEvidence = foreach ($directory in @($state, $logs)) {
                # icacls accepts one directory per invocation; check both absolute paths separately.
                $output = & icacls.exe $directory 2>&1
                if ($LASTEXITCODE -ne 0) { throw "Could not inspect service ACLs for '$directory' (icacls exit $LASTEXITCODE)." }
                $output
            }
            $aclEvidence | Set-Content (Join-Path $EvidenceDirectory 'service-acls.txt')
        }
        Check 'start-menu-and-uninstall' {
            if (-not (Test-Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SENTINEL\SENTINEL Enterprise.lnk'))) { throw 'Start Menu shortcut missing.' }
            if (-not (Test-Path -LiteralPath (Join-Path $installDirectory 'Uninstall.exe'))) { throw 'Uninstaller missing.' }
        }
        if ($DesktopSmoke) {
            Check 'desktop-first-launch' {
                $desktop = Start-Process -FilePath (Join-Path $installDirectory 'Desktop\Sentinel.Desktop.exe') -PassThru
                if (-not $desktop.WaitForInputIdle(20000)) { throw 'Desktop did not become input-ready.' }
                Start-Sleep -Seconds 2
                $desktop.Refresh()
                if ($desktop.HasExited -or $desktop.MainWindowHandle -eq 0) { throw 'Desktop did not show a first-launch window.' }
                $desktop.CloseMainWindow() | Out-Null
                if (-not $desktop.WaitForExit(15000)) { throw 'Desktop did not close gracefully.' }
                $desktop = $null
            }
        }
        # A real second install verifies stable service identity and in-place upgrades.
        Check 'same-version-upgrade' { Run-Installer $SetupPath @('/S'); Assert-InstalledVersion $ExpectedVersion; Wait-Health | Out-Null }
        $sentinel = Join-Path $env:LOCALAPPDATA 'Sentinel'
        New-Item -ItemType Directory -Path $sentinel -Force | Out-Null
        $marker = Join-Path $sentinel 'qa-retention-marker.txt'
        Set-Content -LiteralPath $marker -Value 'Uninstall must preserve operator evidence.'
        Check 'silent-uninstall' {
            # NSIS relocates its uninstaller unless _?= is passed last. Running in place makes process completion observable.
            Run-Installer (Join-Path $installDirectory 'Uninstall.exe') @('/S', "_?=$installDirectory")
            if (Get-Service -Name SentinelMaintenance -ErrorAction SilentlyContinue) { throw 'Service registration remains after uninstall.' }
            if (Test-Path -LiteralPath (Join-Path $installDirectory 'Desktop\Sentinel.Desktop.exe')) { throw 'Desktop executable remains after uninstall.' }
            if (-not (Test-Path -LiteralPath $marker)) { throw 'Uninstall removed operator assessment data.' }
            if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Sentinel\ServiceLogs'))) { throw 'Uninstall removed service audit evidence.' }
            # An in-place uninstaller cannot delete its own running image. Remove that test-only residue after exit.
            Remove-Item -LiteralPath (Join-Path $installDirectory 'Uninstall.exe') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $installDirectory -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $marker -Force
        }
        if ($BaselineSetupPath) {
            # This profile was asserted clean before the fresh-install gate above.
            # Remove only QA-created data so genuine V1.0 binaries can create their
            # own database, Demo Organization, preferences and DPAPI fixture.
            if (Test-Path -LiteralPath $sentinel) { Remove-Item -LiteralPath $sentinel -Recurse -Force }
            Check 'public-v1.0-baseline-hash' {
                $hash = (Get-FileHash -LiteralPath $BaselineSetupPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($hash -ne $BaselineSetupSha256) { throw "Public V1.0 installer checksum mismatch: $hash" }
                Write-Host "Verified historical V1.0 installer SHA-256: $hash"
            }
            # A custom directory with spaces verifies that V1.1 resolves the
            # existing x64 registry location instead of assuming its default.
            $installDirectory = Join-Path $env:ProgramFiles 'SENTINEL V1.0 Upgrade QA'
            if (Test-Path -LiteralPath $installDirectory) { throw "The disposable upgrade directory already exists: $installDirectory" }
            Check 'public-v1.0-install' { Run-Installer $BaselineSetupPath @('/S', "/D=$installDirectory"); Assert-InstalledVersion '1.0.0'; Wait-Health | Out-Null }
            $baselineResult = Join-Path $EvidenceDirectory 'v1.0-installed-evidence.json'
            Check 'public-v1.0-demo-settings-dpapi-seed' {
                Run-UpgradeProbe 'seed' $baselineResult
                $result = Get-Content -LiteralPath $baselineResult -Raw | ConvertFrom-Json
                if ($result.infrastructureVersion -ne '1.0.0.0') { throw 'The upgrade baseline was not seeded by the installed V1.0 binaries.' }
            }
            $maintenanceSettings = Join-Path $env:ProgramData 'Sentinel\maintenance-settings.json'
            Set-Content -LiteralPath $maintenanceSettings -Value '{"enableServiceLogRetention":false,"serviceLogRetentionDays":47}' -Encoding utf8
            $auditMarker = Join-Path $env:ProgramData 'Sentinel\ServiceLogs\qa-upgrade-preserved.jsonl'
            Set-Content -LiteralPath $auditMarker -Value '{"event":"synthetic upgrade preservation fixture"}' -Encoding utf8
            $continuityFiles = @($maintenanceSettings, $auditMarker) + @(Get-ChildItem -LiteralPath $sentinel -File -Filter 'sentinel.db*' | ForEach-Object FullName) + @(Get-ChildItem -LiteralPath (Join-Path $sentinel 'secrets') -File | ForEach-Object FullName)
            $before = @($continuityFiles | ForEach-Object { [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() } })
            $before | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'upgrade-preserved-files.json') -Encoding utf8
            Check 'v1.0-to-v1.1-in-place-upgrade' {
                Run-Installer $SetupPath @('/S'); Assert-InstalledVersion $ExpectedVersion; Wait-Health | Out-Null
                $registeredPath = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\SENTINEL' -Name InstallDir
                if ($registeredPath -ne $installDirectory) { throw 'Upgrade changed the existing custom installation directory.' }
                if (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'SENTINEL\Desktop\Sentinel.Desktop.exe')) { throw 'Upgrade unexpectedly created a second installation at the default path.' }
            }
            Check 'v1.0-data-settings-secret-and-audit-bytes-preserved' {
                foreach ($file in $before) {
                    if (-not (Test-Path -LiteralPath $file.path -PathType Leaf)) { throw "Upgrade removed preserved operator/service data: $($file.path)" }
                    if ((Get-FileHash -LiteralPath $file.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw "Upgrade changed preserved operator/service data: $($file.path)" }
                }
            }
            Check 'v1.1-reads-original-v1.0-demo-settings-and-dpapi' {
                $upgradedResult = Join-Path $EvidenceDirectory 'v1.1-upgraded-evidence.json'
                Run-UpgradeProbe 'inspect' $upgradedResult
                $baseline = Get-Content -LiteralPath $baselineResult -Raw | ConvertFrom-Json
                $upgraded = Get-Content -LiteralPath $upgradedResult -Raw | ConvertFrom-Json
                if ($upgraded.infrastructureVersion -ne "$ExpectedVersion.0") { throw 'Evidence was not read by the upgraded installed V1.1 binaries.' }
                foreach ($property in @('snapshotSha256', 'settingsSha256', 'historySha256', 'auditSha256', 'assetCount', 'findingCount', 'nodeCount', 'theme', 'retentionDays', 'dpapiContinuity')) {
                    if ($baseline.$property -ne $upgraded.$property) { throw "V1.0 to V1.1 continuity mismatch: $property" }
                }
            }
            Check 'upgraded-service-account-and-health' {
                $service = Get-CimInstance Win32_Service -Filter "Name='SentinelMaintenance'"
                if (-not $service -or $service.StartName -ne 'NT AUTHORITY\LocalService' -or $service.State -ne 'Running') { throw 'The upgraded maintenance service did not retain its least-privilege identity.' }
                Wait-Health | Out-Null
            }
            # Repository reads may legitimately checkpoint SQLite's WAL. Freeze
            # the current bytes again after semantic compatibility/decryption is
            # verified so uninstall is assessed against the actual latest state.
            $afterReadFiles = @($maintenanceSettings, $auditMarker) + @(Get-ChildItem -LiteralPath $sentinel -File -Filter 'sentinel.db*' | ForEach-Object FullName) + @(Get-ChildItem -LiteralPath (Join-Path $sentinel 'secrets') -File | ForEach-Object FullName)
            $afterRead = @($afterReadFiles | ForEach-Object { [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() } })
            $afterRead | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'uninstall-preserved-files.json') -Encoding utf8
        }
        if ($DesktopAcceptanceScript) {
            # The acceptance executable loads actual installed WPF assemblies,
            # using isolated QA data so the upgrade-continuity fixture is untouched.
            if (-not $BaselineSetupPath) { Run-Installer $SetupPath @('/S'); Assert-InstalledVersion $ExpectedVersion }
            Check 'installed-desktop-functional-and-rendered-acceptance' {
                & $DesktopAcceptanceScript -DesktopDirectory (Join-Path $installDirectory 'Desktop') -EvidenceDirectory (Join-Path $EvidenceDirectory 'desktop')
                if ($LASTEXITCODE -ne 0) { throw "Installed desktop acceptance failed with exit code $LASTEXITCODE." }
            }
        }
        if ($BaselineSetupPath -or $DesktopAcceptanceScript) {
            Check 'upgraded-silent-uninstall-preserves-evidence' {
                Run-Installer (Join-Path $installDirectory 'Uninstall.exe') @('/S', "_?=$installDirectory")
                if (Get-Service -Name SentinelMaintenance -ErrorAction SilentlyContinue) { throw 'Upgraded service registration remains after uninstall.' }
                if (Test-Path -LiteralPath (Join-Path $installDirectory 'Desktop\Sentinel.Desktop.exe')) { throw 'Upgraded desktop executable remains after uninstall.' }
                if ($BaselineSetupPath) {
                    foreach ($file in $afterRead) {
                        if (-not (Test-Path -LiteralPath $file.path -PathType Leaf)) { throw "Uninstall removed preserved upgrade data: $($file.path)" }
                        if ((Get-FileHash -LiteralPath $file.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw "Uninstall changed preserved upgrade data: $($file.path)" }
                    }
                }
                Remove-Item -LiteralPath (Join-Path $installDirectory 'Uninstall.exe') -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $installDirectory -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        $checks.Add([ordered]@{ name = 'install-uninstall'; status = 'not-run'; details = 'Pass -InstallUninstall on an elevated disposable Windows VM.' })
    }
    $checks.Add([ordered]@{ name = 'physical-windows10-and-native-dpi-acceptance'; status = 'not-run'; details = 'Rendered and functional CI acceptance uses a Windows runner; physical Windows 10/11 and native 125%/150% desktop scaling remain manual acceptance.' })
} finally {
    if ($desktop -and -not $desktop.HasExited) { $desktop.CloseMainWindow() | Out-Null }
    [ordered]@{ schemaVersion = 1; platform = [Environment]::OSVersion.VersionString; checks = $checks.ToArray() } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'verification-results.json') -Encoding utf8
}
