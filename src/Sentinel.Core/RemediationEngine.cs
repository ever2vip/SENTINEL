namespace Sentinel.Core;

/// <summary>Groups shared causes into operator-reviewed actions. No action is executed by this engine.</summary>
public sealed class RemediationEngine : IRemediationEngine
{
    private readonly IRiskEngine _risk;
    public RemediationEngine(IRiskEngine? riskEngine = null) => _risk = riskEngine ?? new RiskEngine();

    public IReadOnlyList<RemediationAction> Plan(EnvironmentSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var assessment = _risk.Calculate(snapshot, snapshot.UpdatedAt);
        var riskByFinding = assessment.RankedFindings.ToDictionary(x => x.Finding.Id, x => x.Risk, StringComparer.Ordinal);
        var assets = snapshot.Assets.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        var evidence = snapshot.Nodes.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        var actions = new List<RemediationAction>();
        var actionable = snapshot.Findings.Where(x => x.Status == FindingStatus.Open ||
            x.Status == FindingStatus.AcceptedRisk && x.AcceptedUntil.HasValue && x.AcceptedUntil <= snapshot.UpdatedAt);
        foreach (var group in actionable.GroupBy(x => string.IsNullOrWhiteSpace(x.RootCauseKey) ?
                     $"finding:{x.Id}" : x.RootCauseKey.Trim().ToLowerInvariant(), StringComparer.Ordinal))
        {
            var findings = group.OrderByDescending(x => riskByFinding.GetValueOrDefault(x.Id)).ThenBy(x => x.Id, StringComparer.Ordinal).ToList();
            var assetIds = findings.SelectMany(x => x.AssetIds).Where(assets.Contains).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var evidenceIds = findings.SelectMany(x => x.EvidenceIds).Where(evidence.Contains).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var reduction = findings.Sum(x => riskByFinding.GetValueOrDefault(x.Id));
            var weights = findings.Sum(x => riskByFinding.GetValueOrDefault(x.Id));
            var confidence = weights > 0 ? findings.Sum(x => RiskEngine.Unit(x.Confidence) * riskByFinding.GetValueOrDefault(x.Id)) / weights :
                findings.Average(x => RiskEngine.Unit(x.Confidence));
            var instructions = findings.Select(x => x.Remediation).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToList();
            var verification = findings.Select(x => x.Verification).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToList();
            if (instructions.Count == 0) instructions.Add("Have the asset owner review the finding evidence and implement a documented defensive configuration change.");
            if (verification.Count == 0) verification.Add("Run the authorized assessment again and compare the underlying observation before marking the finding fixed.");
            var highest = findings.Max(x => x.Severity);
            var why = $"Addresses {findings.Count} related {highest.ToString().ToLowerInvariant()}-or-lower finding(s) across {assetIds.Length} asset(s). " +
                $"Approximately {reduction:F1} currently modeled risk points are associated with this cause, with {confidence:P0} evidence confidence. " +
                "This is an estimate of directly associated finding risk, not a guaranteed loss reduction; verify the fix before closing findings.";
            if (findings.Any(x => x.Status == FindingStatus.AcceptedRisk)) why += " A previous risk acceptance has expired.";
            actions.Add(new RemediationAction(AttackPathEngine.StableId("action", group.Key),
                findings[0].Title + (assetIds.Length > 1 ? $" ({assetIds.Length} assets)" : ""), why,
                findings.Select(x => x.Id).ToArray(), assetIds, evidenceIds, Math.Round(reduction, 2), Math.Round(confidence, 4),
                string.Join(Environment.NewLine, instructions), string.Join(Environment.NewLine, verification)));
        }
        return actions.OrderByDescending(x => x.ModeledRiskReduction).ThenBy(x => x.Id, StringComparer.Ordinal).ToList();
    }
}
