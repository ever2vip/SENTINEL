using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>Capability declarations distinguish actual imports from unimplemented live APIs.</summary>
public sealed class ConnectorRegistry
{
    public IReadOnlyList<ConnectorDescriptor> Descriptors { get; } = Array.AsReadOnly(new[]
    {
        new ConnectorDescriptor("azure", "Microsoft Azure", "Validated export import supported; live API not configured", ["Read-only scoped Azure Reader; Security Reader only where required by the exported assessment"], "https://learn.microsoft.com/rest/api/azure/"),
        new ConnectorDescriptor("m365", "Microsoft 365", "Validated export import supported; live API not configured", ["Microsoft Graph read permissions limited to the exported inventory (for example User.Read.All or Group.Read.All); admin consent where required"], "https://learn.microsoft.com/graph/permissions-reference"),
        new ConnectorDescriptor("aws", "Amazon Web Services", "Validated export import supported; live API not configured", ["Read-only IAM role scoped to required inventory; AWS SecurityAudit only when justified"], "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html"),
        new ConnectorDescriptor("gcp", "Google Cloud", "Validated export import supported; live API not configured", ["Read-only project/account-scoped Cloud Asset Viewer and IAM security review permissions where required"], "https://cloud.google.com/asset-inventory/docs/access-control"),
        new ConnectorDescriptor("ad", "Active Directory", "Validated export import supported; live LDAP collection not configured", ["Authorized authenticated directory read access; domain administrator rights are not required"], "https://learn.microsoft.com/windows/win32/adsi/active-directory-service-interfaces-adsi"),
        new ConnectorDescriptor("vulnerability-intel", "Vulnerability intelligence", "Validated CVE export import supported; feed synchronization not configured", ["Authorized read access to the intelligence export; no endpoint credentials"], "https://nvd.nist.gov/developers"),
        new ConnectorDescriptor("defender", "Microsoft Defender", "Future connector; not connected", ["Future least-privilege read permissions to be configured per selected official API"], "https://learn.microsoft.com/defender-endpoint/api/apis-intro"),
        new ConnectorDescriptor("siem", "SIEM platforms", "Future connector; not connected", ["Future read-only incident and alert export permissions"], "https://learn.microsoft.com/azure/sentinel/"),
        new ConnectorDescriptor("edr", "EDR platforms", "Future connector; not connected", ["Future read-only device and posture permissions"], ""),
        new ConnectorDescriptor("github", "GitHub", "Future connector; not connected", ["Future repository security read permissions through an approved GitHub App"], "https://docs.github.com/rest"),
        new ConnectorDescriptor("vmware", "VMware", "Future connector; not connected", ["Future scoped read-only inventory role"], "https://developer.broadcom.com/"),
        new ConnectorDescriptor("kubernetes", "Kubernetes", "Future connector; not connected", ["Future namespace-scoped read-only RBAC role; no secret-content access"], "https://kubernetes.io/docs/reference/using-api/")
    });

    public IReadOnlyList<IConnector> CreateConnectors() => Descriptors.Select(descriptor => (IConnector)new UnconfiguredExportConnector(descriptor)).ToArray();
    private sealed class UnconfiguredExportConnector(ConnectorDescriptor descriptor) : IConnector
    {
        public ConnectorDescriptor Descriptor { get; } = descriptor;
        public Task<EngineResult> CollectAsync(ScanContext context, ISecretStore secrets, CancellationToken cancellationToken)
        {
            ScopeGuard.EnsureActive(context.Scope, cancellationToken);
            return Task.FromResult(new EngineResult([], [], [], [], [], [], [$"{Descriptor.Name}: {Descriptor.Status}. No live evidence was collected. Use an authorized schema-v1 exported-evidence import where supported."]));
        }
    }
}
