# Product architecture

SENTINEL is organized around a single environment snapshot. Live and demo workspaces are separate; each mutation preserves a historical SQLite snapshot and updates the current graph projections transactionally. Synthetic data can never launch a live collector through the coordinator.

| Module | Responsibility |
| --- | --- |
| Sentinel.Desktop | Native WPF/Fluent-inspired Windows shell, first launch, scope workflow, navigation, graph, operator actions, exports |
| Sentinel.Core | Domain contracts, evidence graph, contextual risk, defensive paths, remediation, compliance, offline demo |
| Sentinel.Engines | Explicit authorization, bounded read-only collectors, validated exported evidence, connector catalog |
| Sentinel.Infrastructure | SQLite migrations/history/audit/settings, DPAPI secrets, reports, evidence analyst, mutation coordinator |
| Sentinel.Service | Least-privilege service health and opt-in maintenance of its own logs |
| Sentinel.Cli | Diagnostic and authorized command-line workflows using the same coordinator |
| Sentinel.Tests / Sentinel.EngineTests | Portable behavioral and isolated loopback tests |
| installer / scripts | Self-contained x64 publishing, NSIS Setup, upgrade/uninstall helpers, Windows verification |

WPF is a deliberate implementation choice for a native, self-contained Windows desktop and reliable .NET cross-compilation. The UI uses vector geometry, Segoe UI, restrained colors, rounded surfaces and dynamic theme resources. WinUI 3 remains a future shell option; the domain and engine modules do not depend on WPF.

## Evidence and state

Graph nodes represent assets, identities, addresses, domains, services, software, vulnerabilities, permissions, findings, controls, certificates, cloud resources, and Internet exposure. Directed edges carry a relationship, observation confidence, dependencies on findings, and a defensive interruption recommendation. An edge participates in path analysis only if explicitly marked as enabling a path. A diagram is not proof of exploitation.

Stable collector identifiers support repeated assessments. Existing business owners/criticality and operator dispositions survive scan merges. New evidence is applied only after successful collection and validation; a cancellation preserves its scan/audit record but commits no partial output. Failed queries cannot resolve old findings. An operator must record verification when marking a finding fixed. Removing an asset by operator attestation retains its risk evidence until separately verified.

Current models are stored as versioned JSON in SQLite with indexed graph projections. Schema migrations are transactional; a database from a newer product version is rejected. A full historical snapshot enables a future relational or graph-server backend without changing the collector interfaces. Retention removes expired historical evidence and audit records under the configured policy; current active posture is retained.

## Contextual risk

Risk considers technical severity/CVSS, legitimate exploitability metadata, observed exposure, business criticality, privilege impact, identity reach, active graph path participation, affected-asset breadth, confidence, and compensating controls. Individual risks are bounded 0–100. Category scores use a documented fixed risk budget; the global score averages assessed category scores. Adding healthy inventory cannot dilute existing risk automatically.

Risk acceptance changes action disposition, not the score. Fixed and false-positive findings leave active risk. Accepted risk re-enters remediation when its review date expires. Root-cause remediation estimates sum their directly associated risks; they are model estimates, not guaranteed real-world loss reductions. Path traversal is bounded to eight edges, 100 paths and 25,000 graph expansions.

## Connectors and AI

`IAssessmentEngine`, `IConnector`, `ISecretStore`, `IAiProvider`, `IRiskEngine`, `IAttackPathEngine`, `IRemediationEngine`, and `IReportingEngine` separate product behavior. Constructor injection is used throughout the application. Plugin loading is an explicit integration step; arbitrary DLL loading from writable user folders is not enabled. Connector descriptors record least-privilege requirements and official documentation.

V1 can ingest authorized normalized official exports for supported provider categories. It does not silently authenticate to cloud tenants or claim that future Defender, SIEM, EDR, GitHub, VMware, or Kubernetes adapters are active. The optional AI abstraction is separate from local evidence answers, requires explicit configuration/disclosure consent, and cannot mutate evidence or execute remediation.

## Windows deployment

Setup installs desktop and service binaries beneath 64-bit Program Files, creates Start Menu entries and an optional desktop shortcut, registers the service, protects its data directories, and creates an uninstaller. Per-operator assessment data is stored below LocalAppData. The service state and audit logs are separate under ProgramData. Upgrades retain product identity and data; setup requests application shutdown before replacing files. User assessment data is preserved by uninstall and can be removed separately under the operator's retention policy.
