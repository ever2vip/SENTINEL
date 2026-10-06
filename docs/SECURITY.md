# Security and privacy model

## Authorization boundary

Every live assessment requires a current operator attestation and an explicit scope of exact hosts, exact web URLs, selected allowed ports, and/or the local endpoint. Wildcards and broad CIDR enumeration are rejected. Scope size, concurrency, duration, and authorization lifetime are bounded. Scope is copied before collection to prevent changes during an assessment. Cancelling an assessment propagates to network I/O and local processes.

The collectors connect only to requested targets. Web collection uses HEAD, does not read bodies, does not follow redirects, and retains certificate validation. Endpoint collection runs fixed read-only local queries. Mail collection examines scoped DNS TXT evidence; DKIM is unknown unless an explicit selector is configured. No collector extracts credentials, launches an exploit, executes a graph path, installs persistence, or changes remote systems.

An authorized name can resolve to changing addresses. V1 scopes DNS names as names and does not bind them to a pre-approved address inventory. Enterprise administrators should restrict outbound networking and supply approved literal addresses when address pinning is required.

## Local protection

- The desktop uses the current operator's permissions; elevation is not needed for the normal demo or evidence UI.
- SQLite resides beneath the operator's LocalAppData. It contains assessment evidence, not provider keys. Full database encryption is not implemented.
- Secret files use DPAPI CurrentUser. A different user cannot decrypt the key merely by copying its protected bytes. Non-Windows secret operations fail closed.
- Installer ACLs restrict binaries and service configuration to administrators/System, run maintenance as LocalService, and give ordinary users read access to health only.
- The service cannot access operator DPAPI secrets or assessments and never initiates assessments.
- Exports preserve provenance and avoid HTML injection and CSV formula execution. They remain sensitive security documents; their destination is chosen by the operator.

## Audit, errors, retention

Authorization, scans, finding dispositions, asset business context, incidents, report generation, settings, and imports are audited. Audit records include event IDs and avoid credentials. The local database and audit are not tamper-proof against the current operator or machine administrators; central append-only audit export is a future integration.

Normal UI errors show a readable message, exception category, and correlation ID without a stack trace. Unknown targets and unavailable checks remain unknown. Risk acceptance requires a reason and review date. Retention bounds apply to historical records; current asset/finding state remains available.

## AI and extension trust

Local evidence answers require no AI account. Optional external providers require explicit evidence disclosure consent and a DPAPI-protected credential. Provider-generated claims are labeled inference, and references must correspond to actual evidence IDs. The provider cannot create scan facts or execute actions. Future plugins must be trusted and reviewed; no automatic installation of third-party code is enabled.

## Release boundaries

This build is intended for controlled testing. Authenticode signing, Windows install/upgrade/uninstall, interactive first launch, dark/light rendering, DPAPI user isolation, and accessible navigation require Windows validation. Shipping an unsigned binary as a production-certified release would exceed the recorded validation. Dependency vulnerability auditing remains enabled and warnings are release failures.
