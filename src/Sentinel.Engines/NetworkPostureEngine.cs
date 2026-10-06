using System.Net;
using System.Net.Sockets;
using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>TCP connection attempts only; never reads banners or sends protocol payloads.</summary>
public sealed class NetworkPostureEngine : IAssessmentEngine
{
    public EngineDescriptor Descriptor { get; } = new("network", "Network posture", "Bounded TCP reachability on explicitly authorized hosts and selected ports. Service identity and public exposure require separate evidence.", true, "Available");

    public async Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken)
    {
        context = ScopeGuard.Snapshot(context, cancellationToken);
        var evidence = new EvidenceBuilder(Descriptor.Id);
        var work = context.Scope.Hosts.Select(ScopeGuard.NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase)
            .SelectMany(host => context.Scope.Ports.Distinct().Select(port => (Host: host, Port: port))).ToArray();
        await Parallel.ForEachAsync(work, new ParallelOptions { MaxDegreeOfParallelism = context.Scope.MaxConcurrency, CancellationToken = cancellationToken }, async (target, token) =>
        {
            ScopeGuard.EnsureActive(context.Scope, token);
            var asset = evidence.Asset(target.Host, AssetKind.Endpoint);
            evidence.Observe(asset, "Public exposure", "Unknown — TCP reachability does not establish Internet exposure.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(context.Scope.TimeoutSeconds));
            using var client = new TcpClient();
            try
            {
                context.Progress?.Report($"Checking {target.Host}:{target.Port}");
                await client.ConnectAsync(target.Host, target.Port, timeout.Token);
                evidence.Observe(asset, "CategoryCoverage", "assessed");
                var serviceId = EvidenceBuilder.StableId("service", target.Host + ":tcp:" + target.Port);
                evidence.Node(new EvidenceNode { Id = serviceId, Label = $"TCP {target.Port} reachable", Kind = EvidenceKind.Service, Source = Descriptor.Id, Properties = new() { ["transport"] = "TCP", ["port"] = target.Port.ToString(), ["protocolIdentity"] = "Unverified" } });
                evidence.Edge(asset.Id, serviceId, "reachable-port");
                evidence.Observe(asset, $"TCP {target.Port}", "Reachable; no banner or application traffic sent.");
                if (target.Port is 21 or 80 or 110 or 143 or 389 or 5985)
                    evidence.Finding(asset, "potential-cleartext-" + target.Port, $"Potential cleartext service on TCP {target.Port}", "The selected TCP port accepted a connection. This port is commonly used by an unencrypted protocol; actual protocol and encryption settings were not verified.", Severity.Low, SecurityCategory.Network, "Confirm the service and require encrypted transport where applicable; restrict access to approved segments.", "Review the owning process and service configuration, then assess the selected port again.", .6);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                evidence.Observe(asset, $"TCP {target.Port}", "Unknown — connection timed out.");
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionRefused) evidence.Observe(asset, "CategoryCoverage", "assessed");
                evidence.Observe(asset, $"TCP {target.Port}", ex.SocketErrorCode == SocketError.ConnectionRefused ? "Connection refused; port was not reachable at collection time." : $"Unknown — network result {ex.SocketErrorCode}.");
            }
            catch (ArgumentException)
            {
                evidence.Observe(asset, $"TCP {target.Port}", "Unknown — the target could not be resolved.");
            }
        });
        cancellationToken.ThrowIfCancellationRequested();
        evidence.Message("TCP collection completed without authentication, banner harvesting, exploitation or remote changes. Unreachable targets remain unknown.");
        return evidence.Build();
    }
}
