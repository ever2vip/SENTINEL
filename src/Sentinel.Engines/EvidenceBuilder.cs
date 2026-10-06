using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Engines;

internal sealed class EvidenceBuilder(string engineId)
{
    private readonly object gate = new();
    private readonly List<Asset> assets = [];
    private readonly List<Finding> findings = [];
    private readonly List<EvidenceNode> nodes = [];
    private readonly List<EvidenceEdge> edges = [];
    private readonly List<Observation> observations = [];
    private readonly List<CertificateRecord> certificates = [];
    private readonly List<string> messages = [];

    internal static string StableId(string kind, string key) => $"{kind}-{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..24].ToLowerInvariant()}";

    internal Asset Asset(string target, AssetKind kind, string? name = null)
    {
        var id = StableId("asset", target.ToLowerInvariant());
        lock (gate)
        {
            var existing = assets.FirstOrDefault(a => a.Id == id);
            if (existing is not null) return existing;
            var asset = new Asset { Id = id, Name = name ?? target, Address = target, Kind = kind, Environment = "Live", Properties = new() { ["collection"] = engineId } };
            assets.Add(asset);
            nodes.Add(new EvidenceNode { Id = id, Label = asset.Name, Kind = kind == AssetKind.CloudResource ? EvidenceKind.CloudResource : EvidenceKind.Asset, Source = engineId });
            return asset;
        }
    }

    internal void Observe(Asset asset, string property, string value, string? source = null)
    {
        lock (gate)
        {
            var id = StableId("observation", engineId + ":" + asset.Id + ":" + property);
            if (observations.All(o => o.Id != id)) observations.Add(new Observation { Id = id, AssetId = asset.Id, EngineId = engineId, Property = property, Value = value, Source = source ?? engineId });
        }
    }

    internal void Node(EvidenceNode node) { lock (gate) { if (nodes.All(n => n.Id != node.Id)) nodes.Add(node); } }
    internal void Edge(string source, string target, string relationship, bool enablesPath = false, string? findingId = null, string defensiveBreak = "")
    {
        lock (gate) edges.Add(new EvidenceEdge { Id = StableId("edge", source + ":" + relationship + ":" + target), SourceId = source, TargetId = target, Relationship = relationship, EnablesPath = enablesPath, FindingIds = findingId is null ? [] : [findingId], DefensiveBreak = defensiveBreak });
    }

    internal Finding Finding(Asset asset, string key, string title, string description, Severity severity, SecurityCategory category, string remediation, string verification, double confidence = 1)
    {
        var id = StableId("finding", engineId + ":" + asset.Id + ":" + key);
        var finding = new Finding { Id = id, Title = title, Description = description, RootCauseKey = key, Severity = severity, Category = category, AssetIds = [asset.Id], EvidenceIds = [asset.Id, id], Source = engineId, Remediation = remediation, Verification = verification, Confidence = confidence };
        lock (gate)
        {
            findings.Add(finding);
            nodes.Add(new EvidenceNode { Id = id, Label = title, Kind = EvidenceKind.Finding, Source = engineId, Confidence = confidence });
            edges.Add(new EvidenceEdge { Id = StableId("edge", asset.Id + ":finding:" + id), SourceId = asset.Id, TargetId = id, Relationship = "has-finding", FindingIds = [id], Confidence = confidence });
        }
        return finding;
    }
    internal void Certificate(CertificateRecord certificate) { lock (gate) certificates.Add(certificate); }
    internal void Message(string message) { lock (gate) messages.Add(message); }
    internal EngineResult Build() { lock (gate) return new(assets.ToArray(), findings.ToArray(), nodes.ToArray(), edges.ToArray(), observations.ToArray(), certificates.ToArray(), messages.ToArray()); }
}
