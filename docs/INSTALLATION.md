# SENTINEL Enterprise Windows testing release

SENTINEL targets Windows 10/11 x64. The installer contains self-contained .NET desktop and service publications; the normal standalone installation requires no Docker, Node.js, PHP or database server. This build is unsigned and remains a testing build until Windows acceptance has been completed. Do not describe a successful Linux cross-build as Windows runtime validation.

## Install and first launch

1. Verify the installer SHA-256 against `SHA256SUMS.txt` from the same trusted build. An unsigned installer can trigger Windows SmartScreen; the release manifest explicitly records signing status.
2. Run `SENTINEL-Enterprise-V1.0-Setup-x64.exe` from `release/SENTINEL-Enterprise-V1.0`. Setup requests administrator elevation and installs beneath the 64-bit Program Files directory. A desktop shortcut is optional; the Start Menu entry is installed for all users.
3. Start **SENTINEL Enterprise** from the Start Menu as the operator's ordinary Windows account. Choose **Demo Organization** for offline synthetic evidence, or **Live Environment** and explicitly authorize the assessment scope. No network is assessed merely by installing or starting the service.

The Desktop stores its SQLite database, operator preferences, exports and protected connector configuration in that operator's `%LOCALAPPDATA%\Sentinel` directory. Connector secrets are protected for the Windows user with DPAPI. Back up operator data before upgrades; DPAPI secrets are bound to the Windows identity and require its key material for recovery. The service does not read user databases or connector credentials.

## Windows service and permissions

`SentinelMaintenance` is installed as **SENTINEL Maintenance**, runs as `NT AUTHORITY\LocalService`, and uses delayed automatic start. It records service health and can prune its own audit logs when explicitly configured. It does not schedule assessments, run scanners, enforce fixes, discover assets, or monitor operator evidence. Continuous change analysis is driven by successive assessments in the desktop application.

| Location | Purpose | Permissions |
| --- | --- | --- |
| `%PROGRAMFILES%\SENTINEL\Desktop` | Application binaries | Administrators/System write; ordinary users read and execute |
| `%PROGRAMFILES%\SENTINEL\Service` | Service binaries | Administrators/System write; LocalService read and execute |
| `%PROGRAMDATA%\Sentinel\maintenance-settings.json` | Non-secret maintenance settings | Administrators/System write; LocalService and Users read |
| `%PROGRAMDATA%\Sentinel\ServiceState\health.json` | Non-sensitive health heartbeat | LocalService write; Users read |
| `%PROGRAMDATA%\Sentinel\ServiceLogs` | Service audit JSONL files | LocalService write; Administrators/System access; no ordinary Users access |
| `%LOCALAPPDATA%\Sentinel` | Per-user assessments and settings | Separate operator data, never shared with the service |

Health includes a timestamp; a heartbeat older than 90 seconds is stale. The service writes no credentials or scan results to shared health. The installer rejects filesystem links in installation/service paths and replaces directory ACLs with the intended grants.

Retention is disabled by default. To enable retention of service logs, an administrator may edit `%PROGRAMDATA%\Sentinel\maintenance-settings.json`:

```json
{
  "enableServiceLogRetention": true,
  "serviceLogRetentionDays": 30
}
```

Retention accepts 7–365 days and deletes only expired `maintenance-*.jsonl` files in the service log directory. Assessment retention controls belong to the desktop application; this setting does not delete operator evidence. Restart the service to apply settings immediately, or wait for its periodic maintenance check. Keep credentials out of this file.

## Upgrade and uninstall

Run Setup again to upgrade the stable application/service identity. Close the desktop application and allow active assessment cancellation to finish first. Setup stops the maintenance service with a 30-second timeout and displays retry/cancel if the desktop remains open; it never terminates unrelated processes. Service configuration and user assessment data persist across upgrades. Setup replaces files in the publication directories; use a clean publication when packaging.

Uninstall through Windows **Installed apps** or the Start Menu. The uninstaller removes the service, binaries, shortcuts and application registration. Operator data and service audit evidence are preserved by default. An administrator can remove `%PROGRAMDATA%\Sentinel` after retention review; each operator can remove their own `%LOCALAPPDATA%\Sentinel` when they intend to delete all local evidence and protected settings. Do not remove those directories while the desktop is using them.

If service configuration fails during Setup, installation does not report success. Re-run Setup with administrator rights to repair configuration; an uninstaller is written before service configuration so the copied binaries can be removed. Review the setup detail log and Windows Event Viewer, recording the reported event/correlation ID when available.

## Build an installer

From the repository root on Windows with the pinned .NET SDK, PowerShell 7 and NSIS 3.11:

```powershell
./scripts/package.ps1 -Makensis 'C:\Program Files (x86)\NSIS\makensis.exe'
```

Packaging restores/builds the complete solution with warnings treated as errors, runs the product test harness, publishes self-contained `win-x64` Desktop and Service outputs to `artifacts/publish`, and produces `release/SENTINEL-Enterprise-V1.0/SENTINEL-Enterprise-V1.0-Setup-x64.exe`. `release-manifest.json` and `SHA256SUMS.txt` beside Setup record file hashes, version, source commit when available, SDK version, signing status and reproducibility limitations. Managed assemblies use deterministic compilation. A manifest enables verification; it does not prove byte-for-byte installer reproducibility, which requires an independent repeat build comparison.

The NSIS script can also compile on Linux after cross-publication:

```bash
makensis -DVERSION=1.0.0 -DPUBLISH_DIR=/absolute/path/artifacts/publish -DOUTPUT_FILE=/absolute/path/release/SENTINEL-Enterprise-V1.0/SENTINEL-Enterprise-V1.0-Setup-x64.exe installer/Sentinel.nsi
```

The GitHub Actions workflow builds on Windows, packages, runs elevated install/service/upgrade/uninstall smoke checks, and stores artifacts plus verification evidence. The optional manual workflow dispatch creates a draft prerelease only; it never automatically publishes a release.

## Windows release acceptance gate

Use an elevated disposable Windows VM for the install/uninstall gate, not an existing deployment:

```powershell
./scripts/verify-windows.ps1 -SetupPath ./release/SENTINEL-Enterprise-V1.0/SENTINEL-Enterprise-V1.0-Setup-x64.exe -InstallUninstall -DesktopSmoke
```

The script checks the PE installer, service account and quoted executable path, fresh heartbeat, protected service ACLs, Start Menu registration, first-launch window, same-version upgrade, uninstall and evidence preservation. It saves every completed check and any failure under `artifacts/windows-verification`. It refuses to overwrite an existing installation. It records interactive product QA as **not run**; automated process startup does not demonstrate full UI correctness.

Before naming a release candidate, record successful acceptance on both supported Windows editions:

- Full solution build, all product tests and warnings/errors review.
- First launch with clean per-user data; Demo Organization seeding; SQLite creation and supported migration behavior.
- Every navigation page, interactive evidence relationships and defensive path explanations.
- Risk calculations, remediation confidence and findings workflows using persisted evidence.
- Every implemented report format; readable PDF, structured exports and evidence references.
- Authorized scope acknowledgement; cancelled assessments; malformed/unavailable targets and human-readable errors.
- Settings restart persistence and dark/light themes, scaling, keyboard navigation and readable typography.
- Installer, service least privilege, upgrade, uninstall and preservation of operator data.
- Authenticode signing/release provenance policy before enterprise distribution.

Cloud/AD and future integration capabilities must remain labelled according to their actual implementation. A connector contract or configured credential is not evidence of a working integration.
