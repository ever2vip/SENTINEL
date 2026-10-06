# Development stage record

The implementation follows the requested internal stages. A stage records code delivered and its test boundary; it does not imply every future connector is live or every Windows acceptance gate has passed.

| Stage | Delivered |
| --- | --- |
| 1 Architecture/Foundation | Modular .NET solution, contracts, injection, error and audit model |
| 2 Enterprise UI Shell | Native desktop, all navigation routes, environment chooser, theme resources |
| 3 Asset Model | Stable IDs, owner/business importance, historical asset snapshots |
| 4 Discovery Framework | Authorized scope, bounded collector contracts, cancellation |
| 5 Network Posture | Selected-port TCP observations and service graph; public exposure remains unknown without evidence |
| 6 Endpoint Security | Read-only Windows CIM/PowerShell posture, inaccessible checks remain unknown |
| 7 Vulnerability Intelligence | CVE/CVSS schema, provenance, version/remediation metadata, dispositions, import architecture |
| 8 Identity/AD | Users/groups/privileges/MFA model, relationships and authorized AD export ingestion |
| 9 Cloud Connectors | Provider descriptors and scoped validated Azure/M365/AWS/GCP export ingestion; direct polling extension point |
| 10 Web/DNS/Email | HEAD/TLS/certificates/headers/cookie attributes and scoped mail TXT posture |
| 11 Evidence Graph | Directed graph contracts, SQLite graph projections, interactive relationship canvas |
| 12 Contextual Risk | Category/global scores, business/identity/exposure factors, history |
| 13 Defensive Attack Paths | Bounded evidence traversal, confidence and BREAK THIS PATH recommendations |
| 14 Compliance | NIST CSF2/CIS mapping and evidence-gap disclosure |
| 15 Remediation Engine | Root-cause grouping, affected assets, verification, modeled reduction/confidence |
| 16 Continuous Monitoring | Scan records, repeated observations, changes/history; assessments are operator initiated in V1 |
| 17 Reporting | All seven requested report kinds; PDF/HTML/CSV/JSON |
| 18 AI Analyst Architecture | Local evidence analyst, optional provider interfaces and disclosure controls |
| 19 Demo Organization | Deterministic offline organization exercising real storage/risk/graph/report code |
| 20 Enterprise Security Hardening | DPAPI, scope isolation, transactional commits, no secret logging, bounded import validation |
| 21 Installer/Release | Self-contained x64 binaries, Setup, service ACLs, shortcuts, upgrades/uninstall and hash manifest |
| 22 Full QA/Release Candidate | Portable automated suites and full cross-build; Windows acceptance checklist remains a release gate |

The maintenance service reports health and optionally prunes its own logs. Scheduled network/cloud assessments, fleet endpoint deployment, central multi-user RBAC, direct cloud authentication, and SIEM/EDR plugins remain future integrations and are not simulated as active features.
