# SENTINEL Enterprise V1.1.1

A native Windows defensive security operations platform that connects collected evidence to business context and prioritized remediation. The repository includes the desktop application, offline demo organization, contextual risk and graph engines, standalone SQLite storage, read-only collectors, reporting, optional AI interfaces, Windows maintenance service, and Setup infrastructure.

**V1.1.1 status: corrective Windows acceptance in progress.** This patch unifies executive recommendations with grouped remediation priorities, uses consistent published risk rounding, and requires scoped evidence for asset-to-asset path prerequisites. New offline Demo fixtures explicitly cover the gateway segmentation scenario. Existing stored environments, settings, planning metadata, SQLite schema and protected credentials are preserved. Historical V1.0 and V1.1 releases remain unchanged. The Windows gate repeats installed UI/report tests and genuine upgrades from both historical installers before publication. Physical Windows 10/11 and native display-DPI transitions remain manual acceptance; the installer is unsigned. See [patch details](docs/V1.1.1.md), [QA](docs/QA.md) and [installation](docs/INSTALLATION.md).

## Use on Windows

Run `SENTINEL-Enterprise-V1.1.1-Setup-x64.exe` from the release artifacts as an administrator. Then launch **SENTINEL Enterprise** from the Start Menu. Choose **Demo Organization** for a completely offline assessment, or **Live Environment** to collect evidence from an explicitly authorized scope.

The installation is self-contained: no Docker, Node.js, web server, separate database server, or developer IDE is required. The desktop runs as the signed-in operator. The Windows service uses LocalService and maintains its own health and optional log retention; it does not run security assessments or read operator secrets.

## Implemented product flows

- A desktop shell with all 20 requested navigation routes, dark/light/system themes, keyboard accessible controls, persistent settings, and human-readable errors with event IDs.
- Historical asset inventory, identities, finding dispositions, evidence relationships, contextual category/global scores, defensive path explanations, root-cause remediation groups, compliance mapping, incident case tracking, and change timelines.
- Explicitly scoped TCP reachability, local Windows posture, web HEAD/TLS/header/cookie posture, and DNS mail policy collectors. Failed and inaccessible checks remain unknown. No exploit execution, credential extraction, or remote configuration changes.
- Authorized, schema-validated exports for Azure, Microsoft 365, AWS, Google Cloud, Active Directory, and vulnerability intelligence, with tenant/account boundaries, source timestamps, and import hashes. Direct API polling is an extension point; these providers are not shown as connected.
- Seven report types in PDF, HTML, JSON, and CSV. Offline evidence analyst answers cite the workspace evidence. Optional provider output remains inference and never becomes scan evidence.
- A reproducible synthetic lab with 250 endpoints, 12 servers, network devices, cloud resources, web applications, identities, findings, certificates, and defensive paths. The lab uses the real analytics and storage code.

## Build and verify

Install the SDK specified in `global.json`. NSIS 3.11 or later is needed to build Setup.

```powershell
dotnet restore Sentinel.sln
dotnet build Sentinel.sln -c Release -warnaserror
dotnet run --project tests/Sentinel.Tests -c Release --no-build
dotnet run --project tests/Sentinel.EngineTests -c Release --no-build
./scripts/package.ps1 -Makensis 'C:\Program Files (x86)\NSIS\makensis.exe'
```

The tests are executable behavioral suites; a nonzero exit code indicates failure. They do not require a real network or a company environment. The separate engine suite uses temporary loopback listeners only.

On an isolated elevated Windows test machine:

```powershell
./scripts/verify-windows.ps1 -SetupPath ./release/SENTINEL-Enterprise-V1.1.1/SENTINEL-Enterprise-V1.1.1-Setup-x64.exe -InstallUninstall -DesktopSmoke
```

The verification script installs and uninstalls SENTINEL and is intended for a disposable test machine. The installed WPF harness captures all 20 routes in both themes across the required resolution/effective-scaling matrix and verifies actual controls, reports, analyst and data isolation. The upgrade gate uses the checksum-pinned historical V1.0 and V1.1 installers and preserves evidence/settings/DPAPI secrets and V1.1 planning/review metadata. See [V1.1 baseline](docs/V1.1-BASELINE.md) and [design contract](docs/V1.1-DESIGN.md). The physical Windows interactive checklist remains required.

For portable engine diagnostics, `dotnet run --project src/Sentinel.Cli -- --help` describes demo, status, report, authorized scan, and import commands. CLI collection requires an operator name and `--confirm-authorized`; default demo/status/report commands do not contact targets.

## Practical boundaries

SENTINEL prioritizes evidence; its heuristic score is neither breach probability nor a certification. A category with no conclusive assessment is **Not assessed**. A favorable score can still have incomplete coverage. TCP reachability does not prove Internet exposure or identify the listening application. HEAD checks do not test every TLS version or application vulnerability. Endpoint patch history is not a full CVE correlation feed. Cloud/AD export provenance is operator supplied and not independently verified. Path enumeration has explicit depth and count bounds.

The SQLite assessment database is protected by the operator profile permissions; it is not full-database encrypted. Sensitive connector/AI keys use Windows DPAPI CurrentUser and are never stored in the database or logs. Database backups and structured reports contain security evidence and should remain in access-controlled locations.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY.md), [engine/import schema](src/Sentinel.Engines/README.md), and [development stage record](docs/STAGES.md).
