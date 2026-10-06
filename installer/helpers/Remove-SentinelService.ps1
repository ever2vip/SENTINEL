$ErrorActionPreference = 'Stop'
try {
    $service = Get-Service -Name 'SentinelMaintenance' -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') {
            $service.Stop()
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        & sc.exe delete SentinelMaintenance | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Service registration could not be removed.' }
    }
    # Preserve both operator evidence and service audit files by default.
    exit 0
} catch {
    Write-Output 'SENTINEL could not remove its maintenance service. Review Windows Services and retry uninstall.'
    exit 13
}
