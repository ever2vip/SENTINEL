# SENTINEL defensive collectors and exported evidence

`NetworkPostureEngine`, `LocalEndpointEngine`, `WebPostureEngine` and
`EmailPostureEngine` implement `IAssessmentEngine`. Each has a default constructor.
Use `AssessAsync(new ScanContext(scope, progress), cancellationToken)`.

`ScopeGuard.Validate(scope)` requires an affirmative operator attestation no older
than 24 hours, exact targets, at most 128 hosts and 64 URLs, 32 selected supported
ports, 4,096 host/port checks, concurrency 1–16 and timeout 1–30 seconds. CIDR,
ranges, wildcards, URL credentials, query strings and fragments are rejected.
Collector contexts copy and normalize scope to prevent caller-side mutation during
an assessment. Cancellation propagates without being converted to a finding.

Network collection makes TCP connections only. It never reads a banner, sends
application payloads, authenticates or identifies a service from the port number.
Reachability does not establish Internet exposure. A potential cleartext port is a
low-confidence review item, not a verified vulnerable service.

Web collection sends one HEAD request to each exact URL, with redirects disabled,
system trust validation enforced, no stored cookies, no proxy credentials and no
response-body collection. Only successful application responses generate missing
header findings. It does not test old TLS protocol support or exploit applications.

Local endpoint collection runs fixed read-only Windows PowerShell queries with no
profile, no arbitrary command input and no execution-policy bypass. It reads OS,
firewall profiles, BitLocker, Defender/Security Center, hotfix inventory and UAC.
Unusable or inaccessible observations are **unknown**. A hotfix age observation is
not a claim that a specific update is missing. Third-party EDR and extended OS
support require authoritative evidence.

Email collection queries exact domains and their `_dmarc` records through an
OS-configured DNS resolver. It does not enumerate DKIM selectors, SPF include
chains or organizational-domain DMARC fallback outside the scope. Supply known
selectors explicitly:

```csharp
var engine = new EmailPostureEngine(dkimSelectors:
    new Dictionary<string, IReadOnlyList<string>>
    {
        ["example.org"] = new[] { "selector1", "selector2" }
    });
```

The domain must already be in the exact scan scope. A published DKIM key does not
prove that messages are signed. Absent selectors and failed DNS queries remain
unknown; they are not counted as passed controls. The UDP TXT client validates
response IDs, answer counts and wire lengths and rejects truncated responses.

## Offline cloud, directory and vulnerability exports

`ConnectorRegistry.Descriptors` states actual availability. Azure, Microsoft 365,
AWS, Google Cloud, Active Directory and vulnerability intelligence support the
normalized **export import format below**. Native provider formats need an adapter
that maps their official read-only API/export fields to this schema. No live
provider API implementation or authentication is claimed. Defender, SIEM, EDR,
GitHub, VMware and Kubernetes are future capability declarations only.

Use `ExportedEvidenceImporter.ImportAsync(Stream, EvidenceImportAuthorization,
CancellationToken)`. It returns `ImportedEvidence`: `Result` contains assets,
findings, graph nodes/edges, observations and certificates; `Identities` is separate
because the shared `EngineResult` contract does not carry identities.
`VulnerabilityIntelImporter` offers the same signature restricted to the
`vulnerability-intel` source.

`EvidenceImportAuthorization` requires operator confirmation, authorizing name,
current `AuthorizedAt`, one supported `SourceId` (`azure`, `m365`, `aws`, `gcp`,
`ad`, `vulnerability-intel`) and the **exact** `OrganizationId` matching the
export. The organization is the tenant/account/directory identifier, not a guessed
hostname. Import is offline and cannot initiate a scan. It rejects unknown JSON
fields, wrong schema/source/organization, duplicates, dangling graph references,
invalid enumerations/scoring, malformed CVE identifiers and properties with
credential/secret names. Limit: 16 MiB. String enum names must be used.

Minimal schema-v1 example (replace time and organization with the actual export):

```json
{
  "schemaVersion": 1,
  "sourceId": "azure",
  "organizationId": "tenant-123",
  "collectedAt": "2026-10-06T12:00:00Z",
  "assets": [
    {
      "id": "vm-01",
      "name": "Finance application VM",
      "kind": "CloudResource",
      "address": "/subscriptions/sub-123/resourceGroups/finance/providers/Microsoft.Compute/virtualMachines/vm-01",
      "businessCriticality": 4,
      "exposure": 0.8,
      "properties": { "region": "westeurope" }
    }
  ],
  "findings": [
    {
      "id": "finding-01",
      "title": "Public management rule observed in the authorized export",
      "description": "The exported configuration shows a source-prefix rule for the management listener. Effective routing and compensating controls require verification.",
      "rootCauseKey": "public-management-rule",
      "severity": "High",
      "category": "Cloud",
      "status": "Open",
      "confidence": 0.9,
      "assetIds": ["vm-01"],
      "evidenceIds": ["vm-01"],
      "references": ["https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"],
      "remediation": "Restrict management access to approved administration paths.",
      "verification": "Review effective network rules and produce a new authorized export."
    }
  ],
  "identities": [],
  "nodes": [],
  "edges": [],
  "observations": [],
  "certificates": []
}
```

Additional identity records use `id`, `displayName`, `principalName`, `provider`,
`isPrivileged`, nullable `mfaEnabled`, nullable `lastSignIn`, `groups` and
`permissions`. Missing MFA/sign-in data must remain null. Permission relationships
can be represented with `Permission` nodes and edges; `enablesPath: true` requires
real exported evidence and may include `findingIds` and `defensiveBreak`.

Each imported entity is namespaced by source and organization with a stable ID.
Asset and identity graph nodes are created when absent; asset/finding and
asset/certificate links are created when absent. Source, collection time and the
SHA-256 of the supplied file are retained. Imported evidence confidence is capped
at 0.95 and labeled operator-supplied, without pretending that provenance was
independently verified. An import hash verifies file identity, not truth.

Never resolve prior findings solely because they are absent from a later result:
scope changes, timeout, failed access and incomplete exports are not positive
verification of remediation. Preserve open findings until an explicit verified
disposition or a check with known successful coverage establishes resolution.
