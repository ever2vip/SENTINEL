[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '1.0.0',
    [string]$Configuration = 'Release',
    [string]$Makensis = 'makensis.exe',
    [switch]$SkipTests,
    [switch]$SkipPublish
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).Replace([IO.Path]::AltDirectorySeparatorChar, [IO.Path]::DirectorySeparatorChar)
$artifacts = Join-Path $root 'artifacts'
$publish = Join-Path $artifacts 'publish'
$releaseVersion = if ($Version.EndsWith('.0')) { $Version.Substring(0, $Version.Length - 2) } else { $Version }
$releaseDirectory = Join-Path (Join-Path $root 'release') "SENTINEL-Enterprise-V$releaseVersion"
function Resolve-InstallerFile([string]$Path, [string]$Name) {
    $absolute = [IO.Path]::GetFullPath($Path).Replace([IO.Path]::AltDirectorySeparatorChar, [IO.Path]::DirectorySeparatorChar)
    Write-Host "Installer dependency [$Name]: $absolute"
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw "Missing installer dependency '$Name': $absolute"
    }
    return (Resolve-Path -LiteralPath $absolute).ProviderPath.Replace([IO.Path]::AltDirectorySeparatorChar, [IO.Path]::DirectorySeparatorChar)
}
# Resolve inputs from the repository, never from the caller's working directory.
$repositoryInputs = [ordered]@{
    INSTALLER_SCRIPT = 'installer/Sentinel.nsi'
    STOP_HELPER = 'installer/helpers/Stop-Sentinel.ps1'
    PREPARE_HELPER = 'installer/helpers/Prepare-Sentinel.ps1'
    CONFIGURE_HELPER = 'installer/helpers/Configure-Sentinel.ps1'
    REMOVE_HELPER = 'installer/helpers/Remove-SentinelService.ps1'
    INSTALLATION_DOC = 'docs/INSTALLATION.md'
    WINDOWS_VERIFICATION_SCRIPT = 'scripts/verify-windows.ps1'
}
$installerInputs = [ordered]@{}
foreach ($name in $repositoryInputs.Keys) {
    $installerInputs[$name] = Resolve-InstallerFile (Join-Path $root $repositoryInputs[$name]) $name
}
if (-not [IO.Path]::IsPathRooted($Makensis) -and ($Makensis.Contains('/') -or $Makensis.Contains('\'))) {
    $Makensis = Join-Path $root $Makensis
}
try { $compiler = Get-Command -Name $Makensis -CommandType Application -ErrorAction Stop | Select-Object -First 1 }
catch { throw "NSIS compiler '$Makensis' is unavailable. Install NSIS or pass -Makensis with its absolute executable path." }
$compilerPath = Resolve-InstallerFile $compiler.Source 'NSIS compiler'
$nativePowerShell = Resolve-InstallerFile (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') 'Native Windows PowerShell helper host'
$nsisRoot = Split-Path $compilerPath -Parent
# Check the installed NSIS includes, Unicode plugins, and standard MUI resources used by this script.
$nsisInputs = @(
    'Include/MUI2.nsh', 'Include/LogicLib.nsh', 'Include/x64.nsh', 'Include/WinVer.nsh',
    'Include/WinMessages.nsh', 'Include/nsDialogs.nsh', 'Include/LangFile.nsh', 'Include/Util.nsh',
    'Contrib/Modern UI 2/MUI2.nsh', 'Contrib/Modern UI 2/Deprecated.nsh',
    'Contrib/Modern UI 2/Interface.nsh', 'Contrib/Modern UI 2/Localization.nsh', 'Contrib/Modern UI 2/Pages.nsh',
    'Contrib/Modern UI 2/Pages/Components.nsh', 'Contrib/Modern UI 2/Pages/Directory.nsh',
    'Contrib/Modern UI 2/Pages/Finish.nsh', 'Contrib/Modern UI 2/Pages/InstallFiles.nsh',
    'Contrib/Modern UI 2/Pages/License.nsh', 'Contrib/Modern UI 2/Pages/StartMenu.nsh',
    'Contrib/Modern UI 2/Pages/UninstallConfirm.nsh', 'Contrib/Modern UI 2/Pages/Welcome.nsh',
    'Contrib/Language files/English.nlf', 'Contrib/Language files/English.nsh',
    'Plugins/x86-unicode/nsExec.dll', 'Plugins/x86-unicode/nsDialogs.dll',
    'Contrib/UIs/modern.exe',
    'Contrib/Graphics/Icons/modern-install.ico', 'Contrib/Graphics/Icons/modern-uninstall.ico',
    'Contrib/Graphics/Checks/modern.bmp', 'Contrib/Graphics/Wizard/win.bmp'
)
$nsisDependencies = @($nsisInputs | ForEach-Object { Resolve-InstallerFile (Join-Path $nsisRoot $_) "NSIS $_" })
function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE." }
}
Push-Location $root
try {
    New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
    New-Item -ItemType Directory -Path $releaseDirectory -Force | Out-Null
    if (-not $SkipPublish) {
        Invoke-Checked 'dotnet' @('restore', 'Sentinel.sln', '-p:EnableWindowsTargeting=true')
        Invoke-Checked 'dotnet' @('build', 'Sentinel.sln', '--no-restore', '-c', $Configuration, '-p:EnableWindowsTargeting=true', "-p:Version=$Version", '-warnaserror')
        if (-not $SkipTests) {
            Invoke-Checked 'dotnet' @('run', '--project', 'tests/Sentinel.Tests/Sentinel.Tests.csproj', '--no-build', '-c', $Configuration)
        }
        foreach ($component in @('Desktop', 'Service')) {
            $destination = Join-Path $publish $component
            if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
            Invoke-Checked 'dotnet' @('publish', "src/Sentinel.$component/Sentinel.$component.csproj", '-c', $Configuration, '-r', 'win-x64', '--self-contained', 'true', '-p:EnableWindowsTargeting=true', "-p:Version=$Version", '-p:PublishSingleFile=false', '-p:PublishTrimmed=false', '-o', $destination)
        }
    }
    $files = @()
    foreach ($component in @('Desktop', 'Service')) {
        $componentDirectory = [IO.Path]::GetFullPath((Join-Path $publish $component)).Replace([IO.Path]::AltDirectorySeparatorChar, [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $componentDirectory -PathType Container)) {
            throw "Missing installer payload directory for ${component}: $componentDirectory"
        }
        $requiredFiles = @("Sentinel.$component.exe", "Sentinel.$component.dll", "Sentinel.$component.deps.json", "Sentinel.$component.runtimeconfig.json", 'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll', 'System.Private.CoreLib.dll')
        if ($component -eq 'Desktop') {
            $requiredFiles += @('e_sqlite3.dll', 'PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll', 'wpfgfx_cor3.dll')
        }
        foreach ($requiredFile in $requiredFiles) {
            Resolve-InstallerFile (Join-Path $componentDirectory $requiredFile) "$component payload/$requiredFile" | Out-Null
        }
        $componentFiles = @(Get-ChildItem -LiteralPath $componentDirectory -Recurse -File -Force | Sort-Object FullName)
        if ($componentFiles.Count -eq 0) { throw "Installer payload is empty: $componentDirectory" }
        Write-Host "Installer payload [$component]: $componentDirectory ($($componentFiles.Count) files)"
        $files += $componentFiles
    }
    # Recheck every selected file immediately before invoking NSIS, including all recursively bundled payload files.
    foreach ($dependency in @($installerInputs.Values) + @($compilerPath, $nativePowerShell) + $nsisDependencies + @($files.FullName)) {
        if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) {
            throw "Missing installer dependency before NSIS invocation: $dependency"
        }
    }
    $setup = Join-Path $releaseDirectory "SENTINEL-Enterprise-V$releaseVersion-Setup-x64.exe"
    Invoke-Checked $compilerPath @('/V3', "/DVERSION=$Version", "/DPUBLISH_DIR=$publish", "/DSTOP_HELPER=$($installerInputs['STOP_HELPER'])", "/DPREPARE_HELPER=$($installerInputs['PREPARE_HELPER'])", "/DCONFIGURE_HELPER=$($installerInputs['CONFIGURE_HELPER'])", "/DREMOVE_HELPER=$($installerInputs['REMOVE_HELPER'])", "/DINSTALLATION_DOC=$($installerInputs['INSTALLATION_DOC'])", "/DOUTPUT_FILE=$setup", $installerInputs['INSTALLER_SCRIPT'])
    $files += Get-Item -LiteralPath $setup
    $hashes = @($files | ForEach-Object {
        [ordered]@{ path = [IO.Path]::GetRelativePath($releaseDirectory, $_.FullName).Replace('\','/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    $commit = $null
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $candidate = & git rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { $commit = [string]$candidate }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        product = 'SENTINEL Enterprise'
        version = $Version
        target = 'Windows 10/11 x64'
        releaseStatus = 'unsigned-testing-build; Windows QA acceptance required'
        authenticodeSigned = $false
        managedAssembliesDeterministic = $true
        byteForByteReproducibilityVerified = $false
        sourceCommit = $commit
        sdkVersion = [string](& dotnet --version)
        files = $hashes
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseDirectory 'release-manifest.json') -Encoding utf8
    $hashes | ForEach-Object { "$($_.sha256)  $($_.path)" } | Set-Content -LiteralPath (Join-Path $releaseDirectory 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "Created unsigned testing installer: $setup"
    Write-Host 'Complete the Windows verification checklist before claiming a release candidate.'
} finally { Pop-Location }
