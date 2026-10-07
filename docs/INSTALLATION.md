# SENTINEL Enterprise Windows testing release

SENTINEL targets Windows 10/11 x64. The installer contains self-contained .NET desktop and service publications; the normal standalone installation requires no Docker, Node.js, PHP or database server. This build is unsigned and remains a testing build until Windows acceptance has been completed. Do not describe a successful Linux cross-build as Windows runtime validation.

## Install and first launch

1. Verify the installer SHA-256 against `SHA256SUMS.txt` from the same trusted build. An unsigned installer can trigger Windows SmartScreen; the release manifest explicitly records signing status.
2. Run `SENTINEL-Enterprise-V1.1.1-Setup-x64.exe` from `release/SENTINEL-Enterprise-V1.1.1`. Setup requests administrator elevation and installs beneath the 64-bit Program Files directory. A desktop shortcut is optional; the Start Menu entry is installed for all users.
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

Run V1.1.1 Setup over V1.0 or V1.1 to upgrade the stable application/service identity.
Setup preserves the per-user SQLite database, settings, protected credentials and
desktop remediation planning/review metadata and service maintenance settings/audit data. A newer installed version cannot be
downgraded by this installer; exit code 17 leaves its installation untouched.
Run Setup again for a same-version repair. Close the desktop application and allow active assessment cancellation to finish first. Setup stops the maintenance service with a 30-second timeout and displays retry/cancel if the desktop remains open; it never terminates unrelated processes. Service configuration and user assessment data persist across upgrades. Setup replaces files in the publication directories; use a clean publication when packaging.

Uninstall through Windows **Installed apps** or the Start Menu. The uninstaller removes the service, binaries, shortcuts and application registration. Operator data and service audit evidence are preserved by default. An administrator can remove `%PROGRAMDATA%\Sentinel` after retention review; each operator can remove their own `%LOCALAPPDATA%\Sentinel` when they intend to delete all local evidence and protected settings. Do not remove those directories while the desktop is using them.

If service configuration fails during Setup, installation does not report success. Re-run Setup with administrator rights to repair configuration; an uninstaller is written before service configuration so the copied binaries can be removed. Review the setup detail log and Windows Event Viewer, recording the reported event/correlation ID when available.

## Build an installer

From the repository root on Windows with the pinned .NET SDK, PowerShell 7 and NSIS 3.11:

```powershell
./scripts/package.ps1 -Makensis 'C:\Program Files (x86)\NSIS\makensis.exe'
```

Packaging restores/builds the complete solution with warnings treated as errors, runs the product test harness, publishes self-contained `win-x64` Desktop and Service outputs to `artifacts/publish`, and produces `release/SENTINEL-Enterprise-V1.1.1/SENTINEL-Enterprise-V1.1.1-Setup-x64.exe`. `release-manifest.json` and `SHA256SUMS.txt` beside Setup record file hashes, version, source commit when available, SDK version, signing status and reproducibility limitations. Managed assemblies use deterministic compilation. A manifest enables verification; it does not prove byte-for-byte installer reproducibility, which requires an independent repeat build comparison.

Use `scripts/package.ps1` for packaging: it resolves every repository helper and
document from its own script location, verifies all NSIS resources/native
PowerShell modules and all self-contained payload files, prints absolute paths,
and fails before NSIS if any dependency is absent. Direct NSIS invocation requires
all of these resolved inputs and must not assume the caller's working directory.
Native installer helpers run in Windows PowerShell x64 with an explicit native
module path. Diagnostics are retained in `%TEMP%\SENTINEL-Setup.log`.

The GitHub Actions workflow builds on Windows, packages, runs elevated
install/service/upgrade/uninstall checks and installed WPF acceptance, and stores
artifacts plus verification evidence. Manual workflow dispatch produces Actions
artifacts only. A `v1.1.1` tag run publishes a verified testing prerelease after
all gates pass. The reviewed `v1.1.1-release` branch can also repeat the full gate
and create the absent tag on its exact validated commit before publication;
an existing different tag is rejected. The release process
never modifies the historical `v1.0.0` or `v1.1.0` releases.

## Windows release acceptance gate

Use an elevated disposable Windows VM for the install/uninstall gate, not an existing deployment:

```powershell
./scripts/verify-windows.ps1 -SetupPath ./release/SENTINEL-Enterprise-V1.1.1/SENTINEL-Enterprise-V1.1.1-Setup-x64.exe -InstallUninstall -DesktopSmoke
```

The script checks the PE installer, expected installed version, service account and quoted executable path, fresh heartbeat, protected service ACLs, Start Menu registration, first-launch window, same-version upgrade, uninstall and evidence preservation. It saves every completed check and any failure under `artifacts/windows-verification`. It refuses to overwrite an existing installation. Pass `-BaselineSetupPath` with the verified public V1.0 EXE,
`-V11BaselineSetupPath` with the verified public V1.1 EXE,
`-UpgradeProbePath` with the QA-only probe DLL and `-DesktopAcceptanceScript`
with `scripts/verify-desktop.ps1` to run the complete release gate. That gate
requires a clean disposable operator profile. It first verifies a fresh V1.1.1
install, then separately installs the genuine V1.0 and V1.1 baselines and checks V1.1.1 upgrade
preservation of database bytes, evidence, history, settings, audit records,
maintenance settings and DPAPI decryption through the actual installed binaries.
The desktop script renders all navigation pages with both themes and exercises
core workflows through the installed WPF assembly, using isolated QA data.
Physical Windows 10/11 and native scaling remain explicitly **not run** by CI.

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
