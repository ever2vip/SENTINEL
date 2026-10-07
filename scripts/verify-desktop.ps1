[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DesktopDirectory,
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\artifacts\desktop-verification'),
    [string]$HarnessDirectory = (Join-Path $PSScriptRoot '..\artifacts\desktop-harness'),
    [switch]$Quick
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Desktop acceptance requires Windows x64 and PowerShell 7 or later.' }
if (-not [Environment]::Is64BitProcess) { throw 'Desktop acceptance must run in an x64 process.' }
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$DesktopDirectory = [IO.Path]::GetFullPath($DesktopDirectory)
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
$HarnessDirectory = [IO.Path]::GetFullPath($HarnessDirectory)
$desktopAssembly = Join-Path $DesktopDirectory 'Sentinel.Desktop.dll'
$project = Join-Path $repositoryRoot 'tests\Sentinel.DesktopTests\Sentinel.DesktopTests.csproj'
$harness = Join-Path $HarnessDirectory 'Sentinel.DesktopTests.exe'
foreach ($dependency in @($desktopAssembly, $project)) {
    Write-Host "Desktop QA dependency: $dependency"
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) { throw "Required desktop QA dependency is missing: $dependency" }
}
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $harness -PathType Leaf)) {
    # This publishes only the QA runner; the installed verified application is never rebuilt.
    & dotnet publish $project -c Release -r win-x64 --self-contained true -o $HarnessDirectory --warnaserror
    if ($LASTEXITCODE -ne 0) { throw "The Windows WPF acceptance harness could not be published (exit $LASTEXITCODE)." }
}
if (-not (Test-Path -LiteralPath $harness -PathType Leaf)) { throw "The Windows acceptance executable is missing after publication: $harness" }
$arguments = @('--desktop-directory', $DesktopDirectory, '--evidence-directory', $EvidenceDirectory)
if ($Quick) { $arguments += '--quick' }
Write-Host "Actual Desktop payload under test: $DesktopDirectory"
Write-Host "Rendered UI evidence: $EvidenceDirectory"
& $harness @arguments 2>&1 | Tee-Object -FilePath (Join-Path $EvidenceDirectory 'desktop-acceptance.log')
$harnessExit = $LASTEXITCODE
$results = Join-Path $EvidenceDirectory 'verification-results.json'
if (-not (Test-Path -LiteralPath $results -PathType Leaf)) { throw "Desktop acceptance produced no physical verification results (exit $harnessExit)." }
$verification = Get-Content -LiteralPath $results -Raw | ConvertFrom-Json
Write-Host "Desktop QA: $($verification.status); $($verification.passed) passed; $($verification.failed) failed; $(@($verification.renders).Count) actual PNG captures."
if ($harnessExit -ne 0 -or $verification.status -ne 'passed') { throw "The installed SENTINEL desktop acceptance gate failed (exit $harnessExit). See desktop-acceptance.log and verification-results.json." }
