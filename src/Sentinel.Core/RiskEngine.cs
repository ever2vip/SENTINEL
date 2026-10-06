namespace Sentinel.Core;

/// <summary>Evidence-based prioritization; scores are model estimates, not breach probabilities.</summary>
public sealed class RiskEngine : IRiskEngine
{
    private readonly IAttackPathEngine _paths;

    public RiskEngine(IAttackPathEngine? paths = null) => _paths = paths ?? new AttackPathEngine();

    public RiskAssessment Calculate(EnvironmentSnapshot snapshot, DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var assets = snapshot.Assets.GroupBy(x => x.Id, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.First(), StringComparer.Ordinal);
        var pathFindings = _paths.Analyze(snapshot).SelectMany(x => x.FindingIds).ToHashSet(StringComparer.Ordinal);
        var ranked = new List<ScoredFinding>();
        foreach (var finding in snapshot.Findings.Where(IsActive))
        {
            var affected = finding.AssetIds.Distinct(StringComparer.Ordinal).Where(assets.ContainsKey).Select(id => assets[id]).ToList();
            var confidence = Unit(finding.Confidence);
            var exposure = affected.Count == 0 ? 0 : affected.Max(x => Unit(x.Exposure));
            var criticality = affected.Count == 0 ? 0.4 : affected.Max(x => Math.Clamp(x.BusinessCriticality, 1, 5) / 5.0);
            var severity = SeverityWeight(finding.Severity);
            // CVSS refines technical severity, but cannot override business context or evidence confidence.
            if (finding.Cvss > 0 && double.IsFinite(finding.Cvss))
                severity = Math.Max(severity, Math.Clamp(finding.Cvss, 0, 10) / 10);
            var participates = pathFindings.Contains(finding.Id);
            var context = 0.48 + 0.16 * Unit(finding.Exploitability) + 0.20 * exposure +
                          0.16 * criticality + 0.12 * Unit(finding.PrivilegeImpact) +
                          0.10 * Unit(finding.IdentityReach) + (participates ? 0.16 : 0);
            // Many affected systems increase scope with diminishing returns, not linear duplicate amplification.
            var breadth = 1 + Math.Min(0.35, Math.Log2(Math.Max(1, affected.Count)) * 0.05);
            var risk = Math.Clamp(100 * severity * context * breadth * confidence *
                                  (1 - 0.7 * Unit(finding.CompensatingControl)), 0, 100);
            var reasons = new List<string>
            {
                $"{finding.Severity} technical severity; evidence confidence {confidence:P0}.",
                $"{affected.Count} inventoried affected asset(s); business importance {criticality:P0}."
            };
            if (exposure > 0) reasons.Add($"Observed exposure factor {exposure:P0}.");
            if (finding.Exploitability > 0) reasons.Add($"Reported exploitability intelligence factor {Unit(finding.Exploitability):P0}; no exploitation performed.");
            if (finding.PrivilegeImpact > 0 || finding.IdentityReach > 0) reasons.Add("Privilege impact and identity reach increase potential business impact.");
            if (participates) reasons.Add("Participates in an evidence-supported defensive attack path.");
            if (finding.CompensatingControl > 0) reasons.Add($"Compensating controls reduce modeled risk by {0.7 * Unit(finding.CompensatingControl):P0}.");
            if (finding.Status == FindingStatus.AcceptedRisk) reasons.Add("Risk acceptance changes disposition, not exposure or modeled risk.");
            if (affected.Count != finding.AssetIds.Distinct(StringComparer.Ordinal).Count()) reasons.Add("Some asset references are unresolved; context uses only inventoried assets.");
            ranked.Add(new ScoredFinding(finding, Math.Round(risk, 2), reasons));
        }

        // Unassessed categories are absent, so the UI can distinguish unknown posture from healthy posture.
        var assessed = snapshot.Findings.Select(x => x.Category).ToHashSet();
        // Collection success only means the collector ran. Unknown measurements, bookkeeping,
        // and reachability alone cannot establish a clean category. Engines explicitly declare
        // known assessment coverage after assessing defensive checks; coverage can still be partial.
        foreach (var observation in snapshot.Observations.Where(x => x.Property == "CategoryCoverage" && x.Value == "assessed"))
            if (CategoryFromEngine(observation.EngineId) is { } category) assessed.Add(category);
        var scores = new Dictionary<SecurityCategory, double>();
        foreach (var category in assessed.Order())
        {
            // A fixed, category-independent budget avoids making risk disappear when inventory grows.
            var categoryRisk = ranked.Where(x => x.Finding.Category == category).Sum(x => x.Risk);
            scores[category] = Math.Round(100 / (1 + categoryRisk / 150), 1);
        }
        var global = scores.Count == 0 ? 0 : Math.Round(scores.Values.Average(), 1);
        return new RiskAssessment(global, Math.Round(ranked.Sum(x => x.Risk), 2), scores,
            ranked.OrderByDescending(x => x.Risk).ThenBy(x => x.Finding.Id, StringComparer.Ordinal).ToList(), now ?? DateTimeOffset.UtcNow);
    }

    internal static bool IsActive(Finding finding) => finding.Status is FindingStatus.Open or FindingStatus.AcceptedRisk;
    internal static double Unit(double value) => double.IsFinite(value) ? Math.Clamp(value, 0, 1) : 0;
    internal static double SeverityWeight(Severity severity) => severity switch
    {
        Severity.Critical => 1, Severity.High => 0.75, Severity.Medium => 0.45, Severity.Low => 0.18, _ => 0
    };

    private static SecurityCategory? CategoryFromEngine(string id)
    {
        var value = id.ToLowerInvariant();
        if (value.Contains("endpoint", StringComparison.Ordinal)) return SecurityCategory.Endpoint;
        if (value.Contains("network", StringComparison.Ordinal)) return SecurityCategory.Network;
        if (value.Contains("vulnerab", StringComparison.Ordinal)) return SecurityCategory.Vulnerability;
        if (value.Contains("identity", StringComparison.Ordinal) || value.Contains("directory", StringComparison.Ordinal)) return SecurityCategory.Identity;
        if (value.Contains("cloud", StringComparison.Ordinal)) return SecurityCategory.Cloud;
        if (value.Contains("email", StringComparison.Ordinal) || value.Contains("dns", StringComparison.Ordinal)) return SecurityCategory.Email;
        if (value.Contains("web", StringComparison.Ordinal)) return SecurityCategory.Web;
        if (value.Contains("compliance", StringComparison.Ordinal)) return SecurityCategory.Compliance;
        return null;
    }
}
