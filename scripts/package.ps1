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
$root = Split-Path $PSScriptRoot -Parent
$artifacts = Join-Path $root 'artifacts'
$publish = Join-Path $artifacts 'publish'
$releaseVersion = if ($Version.EndsWith('.0')) { $Version.Substring(0, $Version.Length - 2) } else { $Version }
$releaseDirectory = Join-Path $root "release/SENTINEL-Enterprise-V$releaseVersion"
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
    foreach ($component in @('Desktop', 'Service')) {
        if (-not (Test-Path -LiteralPath (Join-Path $publish "$component/Sentinel.$component.exe"))) {
            throw "Missing self-contained $component publication."
        }
    }
    $setup = Join-Path $releaseDirectory "SENTINEL-Enterprise-V$releaseVersion-Setup-x64.exe"
    Invoke-Checked $Makensis @('/V3', "/DVERSION=$Version", "/DPUBLISH_DIR=$publish", "/DSOURCE_DIR=$root", "/DOUTPUT_FILE=$setup", (Join-Path $root 'installer/Sentinel.nsi'))
    $files = @(Get-ChildItem -LiteralPath $publish -Recurse -File | Sort-Object FullName)
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
