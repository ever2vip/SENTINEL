[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SetupPath,
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\artifacts\windows-verification'),
    [switch]$InstallUninstall,
    [switch]$DesktopSmoke
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This verification script requires Windows PowerShell 7 or later on Windows x64.' }
$SetupPath = [IO.Path]::GetFullPath($SetupPath)
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
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
        Check 'silent-install' { Run-Installer $SetupPath @('/S') }
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
        Check 'same-version-upgrade' { Run-Installer $SetupPath @('/S'); Wait-Health | Out-Null }
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
    } else {
        $checks.Add([ordered]@{ name = 'install-uninstall'; status = 'not-run'; details = 'Pass -InstallUninstall on an elevated disposable Windows VM.' })
    }
    $checks.Add([ordered]@{ name = 'interactive-product-qa'; status = 'not-run'; details = 'Demo, all navigation, themes, reports, authorized malformed targets, cancellation and settings require the manual acceptance checklist.' })
} finally {
    if ($desktop -and -not $desktop.HasExited) { $desktop.CloseMainWindow() | Out-Null }
    [ordered]@{ schemaVersion = 1; platform = [Environment]::OSVersion.VersionString; checks = $checks.ToArray() } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'verification-results.json') -Encoding utf8
}
