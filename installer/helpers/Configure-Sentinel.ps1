[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallationDirectory)
$ErrorActionPreference = 'Stop'
function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    # Preserve embedded quotes in SCM's binary path on Windows PowerShell 5.1.
    $quotedArguments = foreach ($argument in $Arguments) {
        if ($argument.Length -gt 0 -and $argument -notmatch '[\s"]') { $argument }
        else { '"' + ($argument -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $quotedArguments -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Installer operation failed: $Executable ($($process.ExitCode))." }
    $process.Dispose()
}
function Set-ProtectedDirectoryAcl([string]$Path, [string]$ServiceRights, [bool]$UsersMayRead) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $grants = @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-19', $ServiceRights))
    if ($UsersMayRead) { $grants += ,@('S-1-5-32-545','ReadAndExecute') }
    foreach ($grant in $grants) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($grant[0])
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $grant[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
try {
    $root = Join-Path $env:ProgramData 'Sentinel'
    $state = Join-Path $root 'ServiceState'
    $logs = Join-Path $root 'ServiceLogs'
    foreach ($path in @($root, $state, $logs)) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'SENTINEL service data directories must not be filesystem links.'
        }
    }
    foreach ($directory in @($state, $logs)) {
        if (@(Get-ChildItem -LiteralPath $directory -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
            throw 'SENTINEL service files must not contain filesystem links.'
        }
    }
    # Rebuild complete ACLs instead of retaining unexpected explicit grants.
    Set-ProtectedDirectoryAcl $root 'ReadAndExecute' $true
    Set-ProtectedDirectoryAcl $state 'Modify' $true
    Set-ProtectedDirectoryAcl $logs 'Modify' $false
    foreach ($directory in @($state, $logs)) {
        if (@(Get-ChildItem -LiteralPath $directory -Force).Count -gt 0) {
            Invoke-Native 'icacls.exe' @((Join-Path $directory '*'), '/reset', '/T', '/C', '/Q')
        }
    }
    $settings = Join-Path $root 'maintenance-settings.json'
    if (-not (Test-Path -LiteralPath $settings)) {
        Copy-Item -LiteralPath (Join-Path $InstallationDirectory 'Service\maintenance-settings.example.json') -Destination $settings
    }
    if ((Get-Item -LiteralPath $settings -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Maintenance settings must not be a filesystem link.' }
    Invoke-Native 'icacls.exe' @($settings, '/reset', '/Q')
    $serviceExe = Join-Path $InstallationDirectory 'Service\Sentinel.Service.exe'
    if (-not (Test-Path -LiteralPath $serviceExe)) { throw 'The published SENTINEL service executable is missing.' }
    $binaryPath = '"' + $serviceExe + '"'
    $existing = Get-Service -Name 'SentinelMaintenance' -ErrorAction SilentlyContinue
    $verb = if ($existing) { 'config' } else { 'create' }
    Invoke-Native 'sc.exe' @($verb, 'SentinelMaintenance', 'binPath=', $binaryPath, 'start=', 'delayed-auto', 'obj=', 'NT AUTHORITY\LocalService', 'DisplayName=', 'SENTINEL Maintenance')
    Invoke-Native 'sc.exe' @('description', 'SentinelMaintenance', 'Maintains service health and optional service-log retention. Does not run security assessments or access operator credentials.')
    Invoke-Native 'sc.exe' @('failure', 'SentinelMaintenance', 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/none/0')
    Start-Service -Name 'SentinelMaintenance'
    (Get-Service -Name 'SentinelMaintenance').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    exit 0
} catch {
    Write-Output ('SENTINEL service configuration failed. ' + $_.Exception.Message)
    exit 12
}
