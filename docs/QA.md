# SENTINEL Enterprise V1.0 verification

The automated checks are behavioral tests against the real Core, Infrastructure, Engines, and Service assemblies. They run as a .NET executable and return exit code 1 if any check fails. They require no test framework, company network, cloud account, credentials, or separate database server. Web checks contact only explicitly authorized loopback fixtures; DNS checks use an in-process resolver fixture.

## Run the checks

```powershell
dotnet build Sentinel.sln -c Release --warnaserror
dotnet run --project tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
dotnet run --project tests/Sentinel.EngineTests/Sentinel.EngineTests.csproj -c Release
```

For a constrained Linux sandbox, local socket permission is needed for the loopback fixtures and MSBuild communication. Denied socket permission is an environment failure, not a successful test. A single-worker build can avoid MSBuild worker sockets:

```bash
dotnet build Sentinel.sln -c Release --warnaserror -m:1 -p:UseSharedCompilation=false
```

## Recorded execution evidence

Execution logs are retained in `artifacts/verification/`. The latest recorded corrective run produced **93 passing product checks, zero failures, and zero skips**, plus **17 passing engine regression checks**. Earlier failures exposed a malformed-storage JSON error translation gap and a test assumption about the AWS connector display name; both were corrected and the corrective run passed. The suite now contains **93 checks** after adding two workflow regressions for business-context/retirement behavior and incident lifecycle persistence. Both workflow additions passed in the final packaging rerun. The suite includes a regression ensuring completed collectors with unknown measurements cannot report a perfect security score.

The full Release solution build completed with **zero warnings and zero errors** in this Linux environment. Windows x64 application and service publishing are recorded separately. These build and publish results do not establish that the Windows installer or desktop has executed successfully on Windows.

| Gate | Execution status | Evidence |
| --- | --- | --- |
| Full solution Release compilation | Passed, zero warnings/errors | `artifacts/verification/build.log` |
| Product behavioral harness | 93 passed, zero failed/skipped | `artifacts/verification/product-tests.log` |
| Engine regression harness | 17 passed, zero failed | `artifacts/verification/engine-tests.log` |
| Windows desktop/service publish | Passed, self-contained Windows x64 publishing | `artifacts/verification/publish-desktop.log`, `publish-service.log` |
| Windows installer execution, upgrade, uninstall | **NOT RUN** in Linux | Disposable Windows x64 VM required |
| Windows first-launch rendering, all navigation, interactive graph | **NOT RUN** in Linux | Interactive Windows acceptance required |
| Windows visual Dark/Light/System themes | **NOT RUN** in Linux; preference persistence is automated | Interactive Windows acceptance required |
| Windows current-user DPAPI round trip | **NOT RUN** in Linux; unsupported-platform fail-closed behavior passed | Windows harness selects DPAPI round-trip check |
| Windows local endpoint posture and service account/ACL behavior | **NOT RUN** in Linux | Authorized Windows VM required |
| Authenticode signing / SmartScreen reputation | No production signing result asserted | Verify released executable signature on Windows |

## Automated coverage

The product harness covers deterministic offline lab creation; 250 endpoints and 12 servers; synthetic provenance; graph/reference integrity; evidence-derived historical scores; contextual and confidence-aware risk; accepted/fixed/false-positive dispositions; unknown assessment coverage; bounded graph traversal and defensive breakpoints; root-cause remediation grouping and acceptance expiry; and incomplete framework coverage without certification claims.

Storage coverage includes fresh database creation, version-one migration and graph backfill, future-schema rejection, malformed saved payloads, separate Demo/Live workspaces, immutable historical asset state, invalid and cancelled save preservation, Dark/Light/System preference persistence, encrypted-secret platform boundaries, structured audit records, and retention that preserves unresolved risks and current inventory.

All seven report kinds are exported in JSON, CSV, HTML, and PDF, for 28 report matrix checks. Checks validate traceability, table structure, CSV quoting, spreadsheet formula neutralization, HTML escaping, PDF page and cross-reference structure, cancellation preservation, invalid destinations, local evidence-grounded analysis, external AI authorization, isolated provider input, and rejection of invented citations. PDF structure checks do not replace visual PDF review or a full independent PDF conformance validator.

Engine and coordinator coverage includes authorization expiry; exact target, port, concurrency, and workload boundaries; malformed inputs; pre-cancellation and in-flight cancellation; HEAD-only collection; redirect refusal; cookie-value exclusion; unavailable targets remaining unknown; SPF/DMARC evidence and resolver failures; strict authorized export/import provenance; file limits; connector availability honesty; no partial evidence commit; interrupted-run recovery; accepted disposition persistence; business importance changing risk; retirement retaining unresolved evidence; incident owner/status/note persistence and malformed-case rejection; and explicit completed assessment required before a prior finding can be resolved. Service checks cover atomic health, audit correlation, opt-in log retention, and owned-directory deletion boundaries.

## Windows acceptance before release-candidate declaration

Run the complete harness on clean Windows 10/11 x64, then execute `scripts/verify-windows.ps1 -SetupPath <setup.exe> -InstallUninstall -DesktopSmoke` in an elevated disposable VM. Retain its JSON evidence. Confirm first launch offers Live and Demo; Demo loads real analytics without network access; all navigation pages render; graph selection, filtering, topology, and breakpoints work; preferences survive restart; reports open correctly; cancellation does not commit partial findings; unavailable/malformed targets show human-readable errors; and dark/light/system themes remain readable at supported display scaling.

Verify Start Menu and optional desktop shortcuts, LocalService registration and quoted service path, service data ACLs, heartbeat, reinstall/upgrade, clean uninstall, and preservation of operator assessment and audit data. Do not mark these steps passed based on source inspection, cross-compilation, or installer packaging alone.

Actual installer compilation and archive integrity passed. All 635 bundled application/runtime files match the published payload hashes. Setup is available at `/workspace/release/SENTINEL-Enterprise-V1.0/SENTINEL-Enterprise-V1.0-Setup-x64.exe`. Windows installation and post-install interactive Demo checks remain NOT RUN.


## V1.1 acceptance cycle

Before UI edits, Windows run [37614951188](https://github.com/ever2vip/SENTINEL/actions/runs/37614951188) checked out the immutable v1.0.0 tag and passed the complete Release build (zero warnings/errors), 92 product checks and 17 engine checks; one machine-dependent local endpoint check was intentionally skipped. The accepted Core/Infrastructure/service/engine source and evidence schema remain unchanged.

V1.1 acceptance runs the actual installed Desktop assembly against isolated operator data. It navigates real sidebar controls, exercises asset/finding filters and detail tabs, graph/path controls, offline analyst citations, Report Studio preview/exports, remediation persistence and environment boundaries, authorized-scope rejection, settings/theme persistence and readable errors. RenderTargetBitmap produces 360 route/theme/resolution/effective-scale PNGs plus interaction captures. This tests equivalent DIP sizes and exports images at the requested pixel densities; it does not emulate physical OS display-DPI transitions.

The installer gate includes fresh installation, LocalService/ACL/heartbeat/first launch checks and actual V1.0-to-V1.1 upgrade from the public historical installer. It verifies evidence/settings/history/audit/protected secrets and preserves operator data on uninstall. Publication requires successful Windows and installed desktop results, matching installed/published Desktop assembly hashes and round-trip SHA-256 verification of release assets.

The completed development gate is [Windows run 37623200723](https://github.com/ever2vip/SENTINEL/actions/runs/37623200723), source `a1b79d75cd1cb2b715cea6cecf669194d1e29384`. It passed the full Release build with zero warnings/errors, **92 product checks, 17 engine checks, 10 publication safeguards, and 61 installed desktop checks**, with zero failures. One machine-dependent endpoint posture check remains an explicit skip. The installed desktop produced **369 actual PNG captures**, including the complete 360-route/theme/resolution/effective-scale matrix and interaction/dialog captures. The Windows install/service/actual V1.0 upgrade/data preservation/uninstall gate passed.

Actual rendered PNGs were reviewed across all 20 routes in Dark and Light, plus asset/finding selection, graph inspection, defensive breakpoints, analyst citations and Report Studio. Review caught provider counts using the wrong asset field, an unassessed-control label mismatch and a missing ComboBox display-template selector; these were fixed and covered by the passing acceptance gate. Report visual acceptance waits for the real generated preview.

Earlier integrated runs exposed two C# naming conflicts, Window/button theme inheritance gaps, monitor-limited rendering and detached-tree resource notification errors. All were corrected. A later gate caught the acceptance Application opening a second, ordinary operator-profile window because WPF schedules OnStartup even with Dispatcher.Run. The harness now explicitly suppresses that operator startup, asserts exactly one isolated window, and verifies the preserved upgrade profile remains byte-identical before uninstall. This fixed the cause; no preservation assertion was removed or reset. Failed and superseded runs remain available in Actions.

The final release branch repeats all gates before creating the immutable v1.1.0 tag and publishing SHA-256-verified assets. Native physical monitor DPI transitions, physical Windows 10/11 acceptance, native report SaveFileDialog, tray/OS notification appearance and external authenticated connectors remain manual or unavailable checks. The installer is unsigned and published as a testing prerelease. GitHub Actions upload steps emit upstream Node deprecation notices; application compilation has zero warnings. These notices do not constitute product compiler warnings.
