[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallationDirectory)
$ErrorActionPreference = 'Stop'
try {
    $target = [IO.Path]::GetFullPath($InstallationDirectory).TrimEnd('\')
    $programFiles = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')
    if (-not $target.StartsWith($programFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Choose an installation directory beneath the 64-bit Program Files directory.'
    }
    $cursor = $target
    while ($cursor -and $cursor.Length -ge $programFiles.Length) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The installation path must not contain filesystem links.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    [IO.Directory]::CreateDirectory($target) | Out-Null
    if (@(Get-ChildItem -LiteralPath $target -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
        throw 'Existing installation files must not contain filesystem links.'
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($item in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','ReadAndExecute'), @('S-1-5-19','ReadAndExecute'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($item[0])
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $item[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $target -AclObject $acl
    if (@(Get-ChildItem -LiteralPath $target -Force).Count -gt 0) {
        & icacls.exe (Join-Path $target '*') /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Existing installation file permissions could not be repaired.' }
    }
    exit 0
} catch {
    Write-Output ('SENTINEL cannot prepare the installation directory. ' + $_.Exception.Message)
    exit 14
}
