[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallationDirectory)
$ErrorActionPreference = 'Stop'
try {
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $InstallationDirectory 'Desktop\Sentinel.Desktop.exe'))
    $active = @(Get-Process -Name 'Sentinel.Desktop' -ErrorAction SilentlyContinue | Where-Object {
        try { [string]::Equals($_.Path, $expectedPath, [StringComparison]::OrdinalIgnoreCase) } catch { $true }
    })
    if ($active.Count -gt 0) {
        Write-Output 'Close SENTINEL Desktop, allowing any assessment cancellation to finish, then choose Retry.'
        exit 10
    }
    $service = Get-Service -Name 'SentinelMaintenance' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $service.Stop()
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    exit 0
} catch {
    Write-Output 'SENTINEL could not stop its maintenance service. Review the Windows service state and retry.'
    exit 11
}
