using System.Globalization;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Infrastructure;

/// <summary>Always-available local explanation of collected evidence and deterministic engine results.</summary>
public sealed class EvidenceAnalyst : IEvidenceAnalyst
{
    private readonly IRiskEngine _risk;
    private readonly IRemediationEngine _remediation;
    private readonly IAttackPathEngine _paths;

    public EvidenceAnalyst() : this(new RiskEngine(), new RemediationEngine(), new AttackPathEngine()) { }

    public EvidenceAnalyst(IRiskEngine risk, IRemediationEngine remediation, IAttackPathEngine paths)
    {
        _risk = risk ?? throw new ArgumentNullException(nameof(risk));
        _remediation = remediation ?? throw new ArgumentNullException(nameof(remediation));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
    }

    public AnalystAnswer Answer(EnvironmentSnapshot snapshot, string question)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentException.ThrowIfNullOrWhiteSpace(question);
        if (question.Length > 4096) throw new ArgumentException("Keep analyst questions under 4,096 characters.", nameof(question));
        var normalized = question.Trim().ToLowerInvariant();
        var risk = _risk.Calculate(snapshot);
        var evidenceIds = new HashSet<string>(StringComparer.Ordinal);
        var inferences = new List<string>();
        var answer = new StringBuilder();
        answer.AppendLine($"Evidence scope: {snapshot.Name} ({snapshot.Mode}); last updated {snapshot.UpdatedAt:yyyy-MM-dd HH:mm} UTC.");
        if (snapshot.Mode == EnvironmentMode.Demo) answer.AppendLine("This is synthetic demo evidence; it does not describe a real organization.");
        var knownIds = snapshot.Nodes.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        void Cite(IEnumerable<string> ids) { foreach (var id in ids.Where(knownIds.Contains)) evidenceIds.Add(id); }

        if (normalized.Contains("change", StringComparison.Ordinal) || normalized.Contains("decrease", StringComparison.Ordinal) || normalized.Contains("score", StringComparison.Ordinal))
        {
            if (risk.CategoryScores.Count == 0)
                answer.AppendLine("Security posture is not assessed yet. Run an authorized assessment before interpreting a score.");
            else answer.AppendLine($"Current modeled security score: {risk.GlobalScore:0.0}/100, based on {risk.RankedFindings.Count} scored findings.");
            var history = snapshot.ScoreHistory.OrderBy(x => x.At).ToList();
            if (history.Count >= 2)
            {
                var latest = history[^1];
                var previous = history[^2];
                answer.AppendLine($"Recorded score changed from {previous.Score:0.0} to {latest.Score:0.0} ({latest.Score - previous.Score:+0.0;-0.0;0.0}) between {previous.At:yyyy-MM-dd HH:mm} and {latest.At:yyyy-MM-dd HH:mm} UTC.");
                answer.AppendLine($"Score sources: {previous.Source}; {latest.Source}.");
                inferences.Add("A score movement alone does not establish its cause; changes in assessed coverage or the model can also affect scores.");
            }
            else answer.AppendLine("There are fewer than two recorded scores. The collected history cannot establish a score trend.");
            var recent = snapshot.Changes.OrderByDescending(x => x.At).Take(6).ToList();
            if (recent.Count == 0) answer.AppendLine("No change events are recorded in the current retained history.");
            foreach (var change in recent)
            {
                answer.AppendLine($"• {change.At:yyyy-MM-dd HH:mm} UTC — {change.Kind}: {change.Summary} (source: {change.Source}).");
                if (knownIds.Contains(change.EntityId)) evidenceIds.Add(change.EntityId);
            }
            if (risk.RankedFindings.Count > 0)
            {
                var top = risk.RankedFindings[0];
                answer.AppendLine($"The largest current modeled contributor is “{top.Finding.Title}” ({top.Risk:0.0} risk points; confidence {top.Finding.Confidence:P0}).");
                Cite(top.Finding.EvidenceIds);
                inferences.Add("The largest current contributor is a prioritization estimate, not proof that it caused the historical score change.");
            }
        }
        else if (normalized.Contains("fix", StringComparison.Ordinal) || normalized.Contains("remedi", StringComparison.Ordinal) || normalized.Contains("remove", StringComparison.Ordinal) || normalized.Contains("first", StringComparison.Ordinal))
        {
            var actions = _remediation.Plan(snapshot).OrderByDescending(x => x.ModeledRiskReduction).Take(5).ToList();
            if (actions.Count == 0) answer.AppendLine("No actionable remediation is supported by the current findings. This does not establish that unassessed systems are secure.");
            foreach (var action in actions)
            {
                answer.AppendLine($"• {action.Title}: approximately {action.ModeledRiskReduction:0.0} modeled risk points; confidence {action.Confidence:P0}; {action.AssetIds.Count} affected assets.");
                answer.AppendLine($"  Why: {action.Why}");
                answer.AppendLine($"  Fix: {action.Instructions}");
                answer.AppendLine($"  Verify: {action.Verification}");
                Cite(action.EvidenceIds);
            }
            if (actions.Count > 0)
                inferences.Add("Risk removed is an estimate from the current context model. Actions may overlap; validate the configuration and reassess before declaring findings resolved.");
        }
        else if (normalized.Contains("asset", StringComparison.Ordinal) || normalized.Contains("highest risk", StringComparison.Ordinal))
        {
            var ranking = snapshot.Assets.Select(asset => new
            {
                Asset = asset,
                Findings = risk.RankedFindings.Where(f => f.Finding.AssetIds.Contains(asset.Id)).ToList()
            }).Select(x => new { x.Asset, x.Findings, Risk = x.Findings.Sum(f => f.Risk / Math.Max(1, f.Finding.AssetIds.Count)) })
                .OrderByDescending(x => x.Risk).ThenByDescending(x => x.Asset.BusinessCriticality).Take(5).ToList();
            if (ranking.Count == 0) answer.AppendLine("No assets have been collected. Run an authorized inventory first.");
            foreach (var item in ranking)
            {
                answer.AppendLine($"• {item.Asset.Name} ({item.Asset.Address}): {item.Risk:0.0} allocated modeled risk points; business importance {item.Asset.BusinessCriticality}/5; {item.Findings.Count} scored findings.");
                Cite(item.Findings.SelectMany(x => x.Finding.EvidenceIds));
                Cite(snapshot.Nodes.Where(x => x.Kind == EvidenceKind.Asset && (x.Id == item.Asset.Id || (x.Properties.TryGetValue("assetId", out var id) && id == item.Asset.Id))).Select(x => x.Id));
            }
            inferences.Add("A shared finding's modeled risk is allocated equally among its affected assets for this ranking; this is a prioritization estimate rather than a breach prediction.");
        }
        else if (normalized.Contains("path", StringComparison.Ordinal))
        {
            var paths = _paths.Analyze(snapshot).OrderByDescending(x => x.Risk).Take(5).ToList();
            if (paths.Count == 0) answer.AppendLine("No defensive attack path is supported by the currently modeled relationships. Incomplete evidence may conceal additional paths.");
            foreach (var path in paths)
            {
                answer.AppendLine($"• {path.Title}: risk {path.Risk:0.0}, confidence {path.Confidence:P0}.");
                answer.AppendLine($"  Break this path: {path.RecommendedAction} (break point: {path.BreakPoint}).");
                Cite(path.NodeIds);
            }
            if (paths.Count > 0) inferences.Add("Paths model relationships from evidence; SENTINEL has not executed or validated an exploit or lateral movement.");
        }
        else
        {
            // A finding ID or title gives a precise explanation without inventing a semantic match.
            var match = snapshot.Findings.FirstOrDefault(f => question.Contains(f.Id, StringComparison.OrdinalIgnoreCase))
                ?? snapshot.Findings.FirstOrDefault(f => !string.IsNullOrWhiteSpace(f.Title) && question.Contains(f.Title, StringComparison.OrdinalIgnoreCase));
            if (match is null && (normalized.Contains("finding", StringComparison.Ordinal) || normalized.Contains("explain", StringComparison.Ordinal)))
                match = risk.RankedFindings.FirstOrDefault()?.Finding;
            if (match is not null)
            {
                var scored = risk.RankedFindings.FirstOrDefault(x => x.Finding.Id == match.Id);
                answer.AppendLine($"Finding: {match.Title} [{match.Id}] — {match.Severity}, {match.Status}; observed by {match.Source}; confidence {match.Confidence:P0}.");
                answer.AppendLine($"Collected description: {match.Description}");
                if (scored is not null) answer.AppendLine($"Modeled priority: {scored.Risk:0.0} risk points. {string.Join("; ", scored.Reasons)}.");
                answer.AppendLine($"Remediation: {match.Remediation}");
                answer.AppendLine($"Verification: {match.Verification}");
                if (!string.IsNullOrWhiteSpace(match.Cve)) answer.AppendLine($"Intelligence identifier: {match.Cve}; references: {string.Join(", ", match.References)}.");
                Cite(match.EvidenceIds);
                inferences.Add("Modeled priority translates observed posture into a defensive work order; it does not establish exploitation or business loss.");
            }
            else
            {
                answer.AppendLine("The local analyst supports score changes, recent changes, first remediation actions, highest-risk assets, defensive paths, and finding explanations by ID or exact title. This question cannot be answered from the current evidence with the local rules.");
            }
        }
        if (evidenceIds.Count > 0)
        {
            answer.AppendLine("Evidence references:");
            foreach (var node in snapshot.Nodes.Where(x => evidenceIds.Contains(x.Id)).Take(20))
                answer.AppendLine($"• {node.Id}: {node.Label}; source {node.Source}; observed {node.ObservedAt:yyyy-MM-dd HH:mm} UTC; confidence {node.Confidence:P0}.");
            if (evidenceIds.Count > 20) answer.AppendLine($"{evidenceIds.Count - 20} additional evidence IDs are attached to this answer.");
        }
        if (inferences.Count > 0)
        {
            answer.AppendLine("Model interpretation:");
            foreach (var inference in inferences) answer.AppendLine($"• {inference}");
        }
        return new AnalystAnswer(answer.ToString().Trim(), evidenceIds.Order(StringComparer.Ordinal).ToArray(), inferences, false);
    }
}

/// <summary>Optional external AI extension. Provider output remains an interpretation and can never create scan evidence.</summary>
public sealed class EvidenceGroundedAiAnalyst
{
    private readonly IAiProvider _provider;
    public EvidenceGroundedAiAnalyst(IAiProvider provider) => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    public async Task<AnalystAnswer> AnswerAsync(EnvironmentSnapshot snapshot, string question, bool evidenceDisclosureAuthorized, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentException.ThrowIfNullOrWhiteSpace(question);
        if (!evidenceDisclosureAuthorized)
            throw new InvalidOperationException("External AI is disabled until an operator authorizes sharing the selected evidence with the configured provider.");
        if (question.Length > 4096) throw new ArgumentException("Keep analyst questions under 4,096 characters.", nameof(question));
        // Supply isolated copies, so a plugin cannot mutate the environment through shared nodes.
        var evidence = snapshot.Nodes.Select(n => new EvidenceNode
        {
            Id = n.Id, Label = n.Label, Kind = n.Kind, Source = n.Source,
            Confidence = n.Confidence, ObservedAt = n.ObservedAt, Properties = new(n.Properties)
        }).ToArray();
        var result = await _provider.AnswerAsync(question, evidence, cancellationToken).ConfigureAwait(false);
        if (result is null || string.IsNullOrWhiteSpace(result.Answer)) throw new InvalidDataException("The configured AI provider returned an empty interpretation.");
        var known = evidence.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        var invalidCitations = result.EvidenceIds.Where(id => !known.Contains(id)).ToList();
        if (invalidCitations.Count != 0)
            throw new InvalidDataException("The AI provider cited evidence that was not collected. This answer was rejected.");
        var inferences = result.Inferences.Concat([
            $"All text from {_provider.Name} is an unverified AI interpretation of the supplied evidence. It is not scan evidence and must be checked by an operator."
        ]).ToArray();
        var answer = $"AI interpretation from {_provider.Name} — verify before making decisions.\n{result.Answer}";
        return new AnalystAnswer(answer, result.EvidenceIds.Distinct(StringComparer.Ordinal).ToArray(), inferences, true);
    }
}
