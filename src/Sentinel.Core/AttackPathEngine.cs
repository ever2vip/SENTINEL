using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core;

/// <summary>Traverses explicitly enabling evidence edges; never interacts with assets or executes a path.</summary>
public sealed class AttackPathEngine : IAttackPathEngine
{
    public const int MaximumDepth = 8;
    public const int MaximumPaths = 100;
    private const int MaximumExpansions = 25000;

    public IReadOnlyList<AttackPath> Analyze(EnvironmentSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var nodes = snapshot.Nodes.Where(x => !string.IsNullOrWhiteSpace(x.Id)).GroupBy(x => x.Id, StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.Ordinal);
        var assets = snapshot.Assets.Where(x => x.IsCritical).GroupBy(x => x.Id, StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.Ordinal);
        var findings = snapshot.Findings.GroupBy(x => x.Id, StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.Ordinal);
        var outgoing = snapshot.Edges.Where(x => x.EnablesPath && nodes.ContainsKey(x.SourceId) && nodes.ContainsKey(x.TargetId) &&
                x.FindingIds.All(id => findings.TryGetValue(id, out var finding) && RiskEngine.IsActive(finding)) &&
                HasRelatedAssetEvidence(x))
            .GroupBy(x => x.SourceId, StringComparer.Ordinal)
            .ToDictionary(x => x.Key, x => x.OrderBy(edge => edge.Id, StringComparer.Ordinal).ToArray(), StringComparer.Ordinal);
        var paths = new List<AttackPath>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var expansions = 0;
        foreach (var start in nodes.Values.Where(x => x.Kind == EvidenceKind.Internet).OrderBy(x => x.Id, StringComparer.Ordinal))
        {
            Walk(start.Id, [start.Id], []);
            if (paths.Count >= MaximumPaths || expansions >= MaximumExpansions) break;
        }
        return paths.OrderByDescending(x => x.Risk).ThenBy(x => x.Id, StringComparer.Ordinal).ToList();

        bool HasRelatedAssetEvidence(EvidenceEdge edge)
        {
            var source = nodes[edge.SourceId];
            var target = nodes[edge.TargetId];
            // An asset-to-asset transition cannot borrow a scoped finding from
            // unrelated assets. Keep the stored evidence intact, including older
            // Demo fixtures; omit unsupported inferences until scope is corrected.
            // Identity/service relationships have their own recorded scope.
            if (source.Kind is not (EvidenceKind.Asset or EvidenceKind.CloudResource) ||
                target.Kind is not (EvidenceKind.Asset or EvidenceKind.CloudResource)) return true;
            var sourceAsset = source.Properties.GetValueOrDefault("assetId", source.Id);
            var targetAsset = target.Properties.GetValueOrDefault("assetId", target.Id);
            return edge.FindingIds.All(id => findings[id].AssetIds.Contains(sourceAsset, StringComparer.Ordinal) ||
                findings[id].AssetIds.Contains(targetAsset, StringComparer.Ordinal));
        }

        void Walk(string currentId, List<string> route, List<EvidenceEdge> routeEdges)
        {
            if (++expansions > MaximumExpansions || paths.Count >= MaximumPaths) return;
            var current = nodes[currentId];
            var assetId = current.Properties.GetValueOrDefault("assetId", current.Id);
            if (routeEdges.Count > 0 && current.Kind is EvidenceKind.Asset or EvidenceKind.CloudResource && assets.TryGetValue(assetId, out var criticalAsset))
            {
                var dependencyIds = routeEdges.SelectMany(x => x.FindingIds).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
                var dependencies = dependencyIds.Select(id => findings[id]).ToList();
                var signature = string.Join("|", routeEdges.Select(x => x.Id));
                if (seen.Add(signature))
                {
                    // Confidence compounds independent observations; a long uncertain chain stays uncertain.
                    var confidence = route.Select(id => RiskEngine.Unit(nodes[id].Confidence)).Concat(routeEdges.Select(x => RiskEngine.Unit(x.Confidence)))
                        .Concat(dependencies.Select(x => RiskEngine.Unit(x.Confidence))).Aggregate(1.0, (a, b) => a * b);
                    var highestSeverity = dependencies.Count == 0 ? 0.25 : dependencies.Max(x => RiskEngine.SeverityWeight(x.Severity));
                    var risk = 100 * highestSeverity * (0.65 + 0.35 * Math.Clamp(criticalAsset.BusinessCriticality, 1, 5) / 5.0) * confidence;
                    var breakEdge = routeEdges.Where(x => !string.IsNullOrWhiteSpace(x.DefensiveBreak))
                        .OrderByDescending(x => x.FindingIds.Select(id => RiskEngine.SeverityWeight(findings[id].Severity)).DefaultIfEmpty(0).Max())
                        .ThenBy(x => routeEdges.IndexOf(x)).FirstOrDefault() ?? routeEdges[0];
                    var breakFinding = breakEdge.FindingIds.Select(id => findings[id]).OrderByDescending(x => RiskEngine.SeverityWeight(x.Severity)).FirstOrDefault();
                    var action = !string.IsNullOrWhiteSpace(breakEdge.DefensiveBreak) ? breakEdge.DefensiveBreak :
                        !string.IsNullOrWhiteSpace(breakFinding?.Remediation) ? breakFinding.Remediation :
                        "Review and restrict this enabling relationship; collect fresh evidence to verify the path is interrupted.";
                    paths.Add(new AttackPath(StableId("path", signature), $"Internet → {criticalAsset.Name}", route.ToArray(),
                        routeEdges.Select(x => x.Id).ToArray(), dependencyIds, criticalAsset.Id, Math.Round(risk, 2), Math.Round(confidence, 4),
                        $"{nodes[breakEdge.SourceId].Label} → {nodes[breakEdge.TargetId].Label}", action));
                }
            }
            if (routeEdges.Count >= MaximumDepth || !outgoing.TryGetValue(currentId, out var children)) return;
            foreach (var edge in children)
            {
                if (route.Contains(edge.TargetId, StringComparer.Ordinal)) continue;
                route.Add(edge.TargetId);
                routeEdges.Add(edge);
                Walk(edge.TargetId, route, routeEdges);
                routeEdges.RemoveAt(routeEdges.Count - 1);
                route.RemoveAt(route.Count - 1);
                if (paths.Count >= MaximumPaths || expansions >= MaximumExpansions) break;
            }
        }
    }

    internal static string StableId(string prefix, string value) =>
        $"{prefix}-{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..20]}";
}
