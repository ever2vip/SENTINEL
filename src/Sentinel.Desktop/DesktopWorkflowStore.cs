using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Desktop;

// Desktop planning metadata has its own version and environment boundary. It never
// changes evidence, the V1.0 database schema, finding disposition, or engine scores.
internal sealed class DesktopWorkflowStore(string dataDirectory)
{
    private readonly string _directory = Path.Combine(dataDirectory, "Workflows");
    private readonly SemaphoreSlim _gate = new(1, 1);
    private WorkflowDocument _document = new();
    private string? _path;
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    internal IReadOnlyList<RemediationPlan> Plans => _document.Plans.Values.Select(Clone).ToArray();
    internal RemediationPlan? GetPlan(string actionId) => _document.Plans.TryGetValue(actionId, out var plan) ? Clone(plan) : null;
    internal bool IsUnderReview(string findingId) => _document.Reviews.TryGetValue(findingId, out var review) && review.UnderReview;

    internal async Task LoadAsync(string environmentId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(environmentId);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Clear the previous environment immediately. A malformed file must not
            // leave another environment's planning records available to this one.
            _document = new() { EnvironmentId = environmentId };
            _path = null;
            var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(environmentId))).ToLowerInvariant();
            var path = Path.Combine(_directory, key + ".v1.json");
            WorkflowDocument document;
            if (!File.Exists(path)) document = new() { EnvironmentId = environmentId };
            else
            {
                await using var stream = File.OpenRead(path);
                document = await JsonSerializer.DeserializeAsync<WorkflowDocument>(stream, Options, cancellationToken)
                    ?? throw new InvalidDataException("The local workflow metadata is empty. Evidence remains intact.");
                if (document.SchemaVersion != 1 || document.EnvironmentId != environmentId)
                    throw new InvalidDataException("This workflow metadata version or environment is incompatible. Existing evidence and planning files were preserved.");
                if (document.Plans is null || document.Reviews is null)
                    throw new InvalidDataException("The local workflow metadata is incomplete. Existing files were preserved.");
                foreach (var plan in document.Plans.Values)
                {
                    ValidatePlan(plan);
                    if (plan.EnvironmentId != environmentId)
                        throw new InvalidDataException("A saved remediation plan belongs to a different environment. Existing workflow metadata was preserved.");
                }
            }
            _document = document;
            _path = path;
        }
        finally { _gate.Release(); }
    }

    internal async Task SavePlanAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ValidatePlan(plan);
        await MutateAsync(document => document.Plans[plan.ActionId] = Clone(plan), cancellationToken, plan.EnvironmentId);
    }

    internal async Task SetUnderReviewAsync(string findingId, bool underReview, string reason, CancellationToken cancellationToken = default, string? environmentId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(findingId);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        if (reason.Length > 4096) throw new ArgumentException("Keep the review reason under 4,096 characters.");
        await MutateAsync(document => document.Reviews[findingId] = new()
        {
            UnderReview = underReview, Reason = reason.Trim(), UpdatedAt = DateTimeOffset.UtcNow
        }, cancellationToken, environmentId);
    }

    private async Task MutateAsync(Action<WorkflowDocument> mutate, CancellationToken cancellationToken, string? expectedEnvironment = null)
    {
        await _gate.WaitAsync(cancellationToken);
        string? temporary = null;
        try
        {
            var path = _path ?? throw new InvalidOperationException("Open an environment before saving workflow metadata.");
            if (expectedEnvironment is not null && expectedEnvironment != _document.EnvironmentId)
                throw new InvalidOperationException("The environment changed before this workflow update was saved. Reopen the record in the current environment and retry.");
            var candidate = JsonSerializer.Deserialize<WorkflowDocument>(JsonSerializer.Serialize(_document, Options), Options)!;
            mutate(candidate);
            Directory.CreateDirectory(_directory);
            temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16384, FileOptions.Asynchronous))
            {
                await JsonSerializer.SerializeAsync(stream, candidate, Options, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporary, path, overwrite: true);
            _document = candidate;
        }
        finally
        {
            if (temporary is not null && File.Exists(temporary)) File.Delete(temporary);
            _gate.Release();
        }
    }

    private static void ValidatePlan(RemediationPlan plan)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plan.ActionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(plan.EnvironmentId);
        if (plan.Owner is null || plan.Title is null || plan.Notes is null || plan.FindingIds is null || plan.AssetIds is null || plan.EvidenceIds is null || plan.RootCauseKeys is null)
            throw new ArgumentException("The saved remediation plan is incomplete. Existing workflow metadata was preserved.");
        if (!RemediationPlan.EditableStatuses.Contains(plan.Status, StringComparer.Ordinal))
            throw new ArgumentException("Verified is evidence-derived. Choose a supported planning status instead.");
        if (plan.Owner.Length > 256 || plan.Title.Length > 1024 || plan.Notes.Any(n => n.Text.Length > 4096))
            throw new ArgumentException("The owner, title, or planning note exceeds the supported length.");
        if (!double.IsFinite(plan.ModeledRiskReduction) || plan.ModeledRiskReduction < 0 || !double.IsFinite(plan.Confidence) || plan.Confidence < 0 || plan.Confidence > 1)
            throw new ArgumentException("The saved action must retain a valid modeled risk estimate and evidence confidence.");
    }

    private static RemediationPlan Clone(RemediationPlan plan)
        => JsonSerializer.Deserialize<RemediationPlan>(JsonSerializer.Serialize(plan, Options), Options)!;

    private sealed class WorkflowDocument
    {
        public WorkflowDocument() { }
        public int SchemaVersion { get; set; } = 1;
        public string EnvironmentId { get; set; } = "";
        public Dictionary<string, RemediationPlan> Plans { get; set; } = new(StringComparer.Ordinal);
        public Dictionary<string, FindingReview> Reviews { get; set; } = new(StringComparer.Ordinal);
    }

    private sealed class FindingReview
    {
        public FindingReview() { }
        public bool UnderReview { get; set; }
        public string Reason { get; set; } = "";
        public DateTimeOffset UpdatedAt { get; set; }
    }
}

internal sealed class RemediationPlan
{
    public RemediationPlan() { }
    internal static readonly string[] EditableStatuses = ["Recommended", "Planned", "In Progress", "Awaiting Verification", "Accepted"];
    public string ActionId { get; set; } = "";
    public string EnvironmentId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Why { get; set; } = "";
    public string Instructions { get; set; } = "";
    public string Verification { get; set; } = "";
    public string Status { get; set; } = "Recommended";
    public string Owner { get; set; } = "Unassigned";
    public List<string> RootCauseKeys { get; set; } = [];
    public List<string> FindingIds { get; set; } = [];
    public List<string> AssetIds { get; set; } = [];
    public List<string> EvidenceIds { get; set; } = [];
    public double ModeledRiskReduction { get; set; }
    public double Confidence { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<WorkflowNote> Notes { get; set; } = [];

    internal static RemediationPlan FromAction(RemediationAction action, EnvironmentSnapshot snapshot) => new()
    {
        ActionId = action.Id, EnvironmentId = snapshot.Id, Title = action.Title, Why = action.Why, Instructions = action.Instructions,
        Verification = action.Verification, FindingIds = action.FindingIds.ToList(), AssetIds = action.AssetIds.ToList(),
        EvidenceIds = action.EvidenceIds.ToList(), ModeledRiskReduction = action.ModeledRiskReduction, Confidence = action.Confidence,
        RootCauseKeys = snapshot.Findings.Where(f => action.FindingIds.Contains(f.Id)).Select(f => f.RootCauseKey).Distinct().ToList()
    };

    // Fixed is also assignable by an operator in V1.0. Only the original engine's
    // completed reassessment, matching completion observations, and its resolution
    // event together qualify as verification; an operator click never does.
    internal static bool IsEvidenceVerified(EnvironmentSnapshot snapshot, Finding finding)
    {
        if (finding.Status != FindingStatus.Fixed || finding.FixedAt is null || finding.AssetIds.Count == 0) return false;
        if (!snapshot.Changes.Any(c => c.EntityId == finding.Id && c.Kind == "Resolved finding" && c.Source == finding.Source && c.At >= finding.FixedAt)) return false;
        if (!snapshot.Scans.Any(s => s.EngineId == finding.Source && s.Status == ScanStatus.Completed && s.FinishedAt >= finding.FixedAt)) return false;
        return finding.AssetIds.All(id => snapshot.Observations.Any(o => o.AssetId == id && o.EngineId == finding.Source &&
            o.Property == "AssessmentComplete" && o.Value == "true" && o.ObservedAt >= finding.LastSeen && o.ObservedAt <= finding.FixedAt));
    }

    internal string EvidenceState(EnvironmentSnapshot snapshot)
    {
        var related = snapshot.Findings.Where(f => FindingIds.Contains(f.Id)).ToList();
        if (related.Count != FindingIds.Count || related.Count == 0) return "Evidence incomplete";
        if (related.All(f => IsEvidenceVerified(snapshot, f))) return "Verified";
        if (related.Any(f => f.Status == FindingStatus.Open)) return "Unresolved evidence";
        if (related.Any(f => f.Status == FindingStatus.Fixed)) return "Operator disposition · verification required";
        return "Disposition recorded · risk remains subject to review";
    }
}

internal sealed record WorkflowNote(DateTimeOffset At, string Author, string Text);
