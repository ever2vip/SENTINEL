using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Infrastructure;

/// <summary>Serializes workspace mutations. Scan output is committed only after successful collection.</summary>
public sealed class ApplicationCoordinator
{
    private readonly IEnvironmentRepository _repository;
    private readonly IReadOnlyDictionary<string, IAssessmentEngine> _engines;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IRiskEngine _risk = new RiskEngine();
    private readonly IAttackPathEngine _paths = new AttackPathEngine();
    private readonly IRemediationEngine _remediation = new RemediationEngine();
    private readonly IComplianceEngine _compliance = new ComplianceEngine();
    public EnvironmentSnapshot? Current { get; private set; }
    public RiskAssessment Risk { get; private set; } = new(0, 0, new Dictionary<SecurityCategory, double>(), [], DateTimeOffset.UtcNow);
    public IReadOnlyList<AttackPath> AttackPaths { get; private set; } = [];
    public IReadOnlyList<RemediationAction> Remediations { get; private set; } = [];
    public IReadOnlyList<ComplianceResult> Compliance { get; private set; } = [];
    public IReadOnlyList<EngineDescriptor> Engines => _engines.Values.Select(e => e.Descriptor).ToList();

    public ApplicationCoordinator(IEnvironmentRepository repository, IEnumerable<IAssessmentEngine>? engines = null)
    {
        _repository = repository;
        _engines = (engines ?? []).ToDictionary(e => e.Descriptor.Id, StringComparer.Ordinal);
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default) => _repository.InitializeAsync(cancellationToken);
    public Task<AppSettings> GetSettingsAsync(CancellationToken cancellationToken = default) => _repository.GetSettingsAsync(cancellationToken);

    public async Task<EnvironmentSnapshot> OpenAsync(EnvironmentMode mode, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var snapshot = await _repository.LoadAsync(mode, cancellationToken);
            if (snapshot is null)
            {
                snapshot = mode == EnvironmentMode.Demo ? new DemoLab().Create() : new EnvironmentSnapshot { Id = "live", Name = "Authorized environment", Mode = mode };
                await _repository.SaveAsync(snapshot, cancellationToken);
            }
            foreach (var run in snapshot.Scans.Where(s => s.Status == ScanStatus.Running))
            {
                run.Status = ScanStatus.Failed;
                run.FinishedAt = DateTimeOffset.UtcNow;
                run.Message = "Assessment was interrupted before completion. Collected output was not committed; retry the assessment.";
            }
            await _repository.SaveAsync(snapshot, cancellationToken);
            Current = snapshot;
            RefreshAnalytics();
            var settings = await _repository.GetSettingsAsync(cancellationToken);
            settings.LastEnvironment = mode;
            await _repository.SaveSettingsAsync(settings, cancellationToken);
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "workspace.open", snapshot.Id, mode.ToString(), EventId()), cancellationToken);
            return snapshot;
        }
        finally { _gate.Release(); }
    }

    public void RefreshAnalytics()
    {
        var current = Current ?? throw new InvalidOperationException("Open an environment first.");
        Risk = _risk.Calculate(current);
        AttackPaths = _paths.Analyze(current);
        Remediations = _remediation.Plan(current);
        Compliance = _compliance.Assess(current);
    }

    public async Task RunScanAsync(string engineId, ScanScope scope, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var current = Current ?? throw new InvalidOperationException("Open an environment first.");
            if (current.Mode != EnvironmentMode.Live) throw new InvalidOperationException("Live collection requires the Live Environment workspace. Demo data is fully offline.");
            if (!_engines.TryGetValue(engineId, out var engine)) throw new ArgumentException("Choose an available assessment engine.", nameof(engineId));
            if (!engine.Descriptor.IsAvailable) throw new InvalidOperationException(engine.Descriptor.AvailabilityReason);
            if (!scope.AuthorizationConfirmed || string.IsNullOrWhiteSpace(scope.AuthorizedBy) || scope.AuthorizedAt < DateTimeOffset.UtcNow.AddHours(-24) || scope.AuthorizedAt > DateTimeOffset.UtcNow.AddMinutes(5))
                throw new ArgumentException("Confirm authorization for this assessment with an operator name and a current scope.");
            // Copy caller-owned scope before authorization/audit so evidence and its recorded boundary agree.
            scope = JsonSerializer.Deserialize<ScanScope>(JsonSerializer.Serialize(scope))!;
            var run = new ScanRun { EngineId = engineId, ScopeSummary = $"Hosts=[{string.Join(", ", scope.Hosts)}]; URLs=[{string.Join(", ", scope.WebUrls)}]; ports=[{string.Join(",", scope.Ports)}]; local={scope.IncludeLocalEndpoint}; timeout={scope.TimeoutSeconds}s; concurrency={scope.MaxConcurrency}", Status = ScanStatus.Running, EventId = EventId() };
            current.Scans.Add(run);
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "scan.authorized", run.Id, $"Engine={engineId}; operator={scope.AuthorizedBy}; {run.ScopeSummary}", run.EventId), cancellationToken);
            await _repository.SaveAsync(current, cancellationToken);
            try
            {
                var result = await engine.AssessAsync(new(scope, progress), cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                var candidate = Clone(current);
                Merge(candidate, result, engineId);
                var completed = candidate.Scans.Single(s => s.Id == run.Id);
                completed.Status = ScanStatus.Completed;
                completed.FinishedAt = DateTimeOffset.UtcNow;
                completed.Message = string.Join("; ", result.Messages).Trim();
                RecordScore(candidate, engineId);
                await _repository.SaveAsync(candidate, cancellationToken);
                Current = candidate;
                RefreshAnalytics();
                await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "scan.completed", run.Id, $"{result.Assets.Count} assets; {result.Findings.Count} findings", run.EventId), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                run.Status = ScanStatus.Cancelled;
                run.FinishedAt = DateTimeOffset.UtcNow;
                run.Message = "Cancelled. No partial assessment evidence was committed.";
                await _repository.SaveAsync(current, CancellationToken.None);
                await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "scan.cancelled", run.Id, run.Message, run.EventId), CancellationToken.None);
                throw;
            }
            catch (Exception exception)
            {
                run.Status = ScanStatus.Failed;
                run.FinishedAt = DateTimeOffset.UtcNow;
                run.Message = $"Assessment could not finish. Event {run.EventId}. Retry after reviewing the target and connectivity.";
                await _repository.SaveAsync(current, CancellationToken.None);
                await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "scan.failed", run.Id, exception.GetType().Name, run.EventId), CancellationToken.None);
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    public Task ImportAsync(EngineResult result, string source, CancellationToken cancellationToken = default) => ImportAsync(result, source, [], cancellationToken);

    public async Task ImportAsync(EngineResult result, string source, IReadOnlyList<Identity> identities, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(identities);
        if (string.IsNullOrWhiteSpace(source)) throw new ArgumentException("An evidence source is required.");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var current = Current ?? throw new InvalidOperationException("Open an environment first.");
            if (current.Mode != EnvironmentMode.Live) throw new InvalidOperationException("Imported live evidence belongs in the Live Environment workspace.");
            var candidate = Clone(current);
            Merge(candidate, result, source);
            foreach (var identity in identities)
            {
                candidate.Identities.RemoveAll(i => i.Id == identity.Id);
                candidate.Identities.Add(identity);
            }
            RecordScore(candidate, source);
            await _repository.SaveAsync(candidate, cancellationToken);
            Current = candidate;
            RefreshAnalytics();
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "evidence.imported", current.Id, $"Source={source}; {result.Assets.Count} assets", EventId()), cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task UpdateFindingAsync(string id, FindingStatus status, string reason, DateTimeOffset? acceptedUntil = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("Record a reason or verification evidence for this decision.");
        if (status == FindingStatus.AcceptedRisk && (acceptedUntil is null || acceptedUntil <= DateTimeOffset.UtcNow)) throw new ArgumentException("Risk acceptance requires a future review date.");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var current = Current ?? throw new InvalidOperationException("Open an environment first.");
            var candidate = Clone(current);
            var finding = candidate.Findings.SingleOrDefault(f => f.Id == id) ?? throw new ArgumentException("This finding is no longer available.");
            finding.Status = status;
            finding.DispositionReason = reason.Trim();
            finding.AcceptedUntil = status == FindingStatus.AcceptedRisk ? acceptedUntil : null;
            finding.FixedAt = status == FindingStatus.Fixed ? DateTimeOffset.UtcNow : null;
            candidate.Changes.Add(new() { Kind = "Finding disposition", EntityId = id, Summary = $"{finding.Title}: {status}. {reason.Trim()}", Source = candidate.Mode == EnvironmentMode.Demo ? "Synthetic demo workflow" : "Operator decision" });
            RecordScore(candidate, "Operator decision");
            await _repository.SaveAsync(candidate, cancellationToken);
            Current = candidate;
            RefreshAnalytics();
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "finding.disposition", id, $"{status}: {reason.Trim()}", EventId()), cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        if (settings.Theme is not ("Dark" or "Light" or "System")) throw new ArgumentException("Choose Dark, Light, or System theme.");
        if (settings.RetentionDays is < 7 or > 3650) throw new ArgumentException("Data retention must be between 7 and 3650 days.");
        await _repository.SaveSettingsAsync(settings, cancellationToken);
        await _repository.ApplyRetentionAsync(settings.RetentionDays, cancellationToken);
        await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "settings.updated", "settings", $"Theme={settings.Theme}; retention={settings.RetentionDays} days", EventId()), cancellationToken);
    }

    public async Task UpdateAssetAsync(string id, string owner, int criticality, string reason, bool retired = false, CancellationToken cancellationToken = default)
    {
        if (criticality is < 1 or > 5) throw new ArgumentException("Business criticality must be between 1 and 5.");
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("Provide an asset owner and the reason for this change.");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var candidate = Clone(Current ?? throw new InvalidOperationException("Open an environment first."));
            var asset = candidate.Assets.SingleOrDefault(a => a.Id == id) ?? throw new ArgumentException("This asset is no longer available.");
            asset.Owner = owner.Trim();
            asset.BusinessCriticality = criticality;
            asset.Properties["lifecycle"] = retired ? "Operator retired" : "Active";
            candidate.Changes.Add(new() { Kind = retired ? "Removed asset (operator attested)" : "Asset business context", EntityId = id, Summary = $"{asset.Name}: owner {owner}; business criticality {criticality}. {reason}", Source = "Operator decision" });
            // A retirement declaration is not proof that vulnerabilities or exposures are fixed.
            RecordScore(candidate, "Asset business context");
            await _repository.SaveAsync(candidate, cancellationToken);
            Current = candidate;
            RefreshAnalytics();
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "asset.context.updated", id, $"Criticality={criticality}; retired={retired}; {reason}", EventId()), cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task CreateIncidentAsync(string title, string owner, IReadOnlyList<string> findingIds, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(title) || title.Length > 200 || string.IsNullOrWhiteSpace(owner)) throw new ArgumentException("Provide an incident title (up to 200 characters) and an owner.");
        ArgumentNullException.ThrowIfNull(findingIds);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var candidate = Clone(Current ?? throw new InvalidOperationException("Open an environment first."));
            var valid = candidate.Findings.Select(f => f.Id).ToHashSet();
            if (findingIds.Count == 0 || findingIds.Any(id => !valid.Contains(id))) throw new ArgumentException("Select at least one existing finding to support the incident.");
            var incident = new IncidentRecord { Title = title.Trim(), Owner = owner.Trim(), FindingIds = findingIds.Distinct().ToList() };
            incident.Notes.Add(new() { Kind = "Created", Summary = "Operator opened a case from collected findings. This does not confirm a security breach.", Source = "Operator decision", EntityId = incident.Id });
            candidate.Incidents.Add(incident);
            candidate.Changes.Add(new() { Kind = "Incident created", Summary = incident.Title, EntityId = incident.Id, Source = "Operator decision" });
            candidate.UpdatedAt = DateTimeOffset.UtcNow;
            await _repository.SaveAsync(candidate, cancellationToken);
            Current = candidate;
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "incident.created", incident.Id, incident.Title, EventId()), cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task UpdateIncidentAsync(string id, string status, string owner, string note, CancellationToken cancellationToken = default)
    {
        if (status is not ("Open" or "Investigating" or "Contained" or "Resolved")) throw new ArgumentException("Choose a supported incident status.");
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(note)) throw new ArgumentException("Provide an owner and an incident update note.");
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var candidate = Clone(Current ?? throw new InvalidOperationException("Open an environment first."));
            var incident = candidate.Incidents.SingleOrDefault(i => i.Id == id) ?? throw new ArgumentException("This incident is no longer available.");
            incident.Status = status;
            incident.Owner = owner.Trim();
            incident.UpdatedAt = DateTimeOffset.UtcNow;
            incident.Notes.Add(new() { Kind = status, Summary = note.Trim(), Source = "Operator decision", EntityId = id });
            candidate.Changes.Add(new() { Kind = "Incident updated", Summary = $"{incident.Title}: {status}", EntityId = id, Source = "Operator decision" });
            candidate.UpdatedAt = DateTimeOffset.UtcNow;
            await _repository.SaveAsync(candidate, cancellationToken);
            Current = candidate;
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "incident.updated", id, $"{status}: {note}", EventId()), cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task<ReportArtifact> ExportReportAsync(ReportKind kind, ReportFormat format, string path, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var current = Current ?? throw new InvalidOperationException("Open an environment first.");
            var artifact = await new ReportingEngine().ExportAsync(Clone(current), kind, format, path, cancellationToken);
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "report.exported", current.Id, $"{kind}; {format}", EventId()), cancellationToken);
            return artifact;
        }
        finally { _gate.Release(); }
    }

    private static void Merge(EnvironmentSnapshot current, EngineResult result, string source)
    {
        var now = DateTimeOffset.UtcNow;
        if (result.Assets.Select(a => a.Id).Distinct().Count() != result.Assets.Count) throw new InvalidDataException("Assessment contains duplicate asset identifiers.");
        foreach (var asset in result.Assets)
        {
            var existing = current.Assets.SingleOrDefault(a => a.Id == asset.Id);
            if (existing is null) current.Changes.Add(new() { Kind = "New asset", EntityId = asset.Id, Summary = $"Discovered {asset.Name}", Source = source });
            else
            {
                asset.FirstSeen = existing.FirstSeen;
                asset.BusinessCriticality = existing.BusinessCriticality;
                asset.Owner = existing.Owner;
                foreach (var property in asset.Properties.Where(p => !existing.Properties.TryGetValue(p.Key, out var value) || value != p.Value))
                    current.Changes.Add(new() { Kind = "Configuration change", EntityId = asset.Id, Summary = $"{asset.Name}: {property.Key} changed to {property.Value}", Source = source });
                if (asset.Exposure > existing.Exposure) current.Changes.Add(new() { Kind = "New exposure", EntityId = asset.Id, Summary = $"{asset.Name}: observed exposure increased", Source = source });
                current.Assets.Remove(existing);
            }
            if (!source.StartsWith("import:", StringComparison.Ordinal)) asset.LastSeen = now;
            current.Assets.Add(asset);
        }
        foreach (var finding in result.Findings)
        {
            var existing = current.Findings.SingleOrDefault(f => f.Id == finding.Id);
            if (existing is null) current.Changes.Add(new() { Kind = "New finding", EntityId = finding.Id, Summary = finding.Title, Source = source });
            else
            {
                finding.FirstSeen = existing.FirstSeen;
                // User dispositions persist unless a previous remediation is observed failing again.
                if (existing.Status is FindingStatus.AcceptedRisk or FindingStatus.FalsePositive)
                {
                    finding.Status = existing.Status;
                    finding.AcceptedUntil = existing.AcceptedUntil;
                    finding.DispositionReason = existing.DispositionReason;
                }
                if (existing.Status == FindingStatus.Fixed && finding.Status == FindingStatus.Open)
                    current.Changes.Add(new() { Kind = "Recurring finding", EntityId = finding.Id, Summary = finding.Title, Source = source });
                current.Findings.Remove(existing);
            }
            if (!source.StartsWith("import:", StringComparison.Ordinal)) finding.LastSeen = now;
            current.Findings.Add(finding);
        }
        // Only an explicit completed assessment of the same asset can resolve a previous engine finding.
        // An unavailable target or incomplete scan must never be interpreted as a successful fix.
        var completeIds = result.Observations.Where(o => o.EngineId == source && o.Property == "AssessmentComplete" && o.Value == "true").Select(o => o.AssetId).ToHashSet();
        var returnedIds = result.Findings.Select(f => f.Id).ToHashSet();
        foreach (var old in current.Findings.Where(f => f.Source == source && f.Status == FindingStatus.Open && !returnedIds.Contains(f.Id) && f.AssetIds.Count > 0 && f.AssetIds.All(completeIds.Contains)))
        {
            old.Status = FindingStatus.Fixed;
            old.FixedAt = now;
            old.DispositionReason = "The same engine completed a new assessment of all affected assets and no longer observed this condition.";
            current.Changes.Add(new() { Kind = "Resolved finding", EntityId = old.Id, Summary = old.Title, Source = source });
        }
        foreach (var node in result.Nodes) { current.Nodes.RemoveAll(n => n.Id == node.Id); current.Nodes.Add(node); }
        foreach (var edge in result.Edges) { current.Edges.RemoveAll(e => e.Id == edge.Id); current.Edges.Add(edge); }
        current.Observations.AddRange(result.Observations);
        foreach (var certificate in result.Certificates)
        {
            current.Certificates.RemoveAll(c => c.Id == certificate.Id);
            current.Certificates.Add(certificate);
            if (certificate.NotAfter < now.AddDays(30)) current.Changes.Add(new() { Kind = "Certificate expiration", EntityId = certificate.Id, Summary = $"{certificate.Subject} expires {certificate.NotAfter:yyyy-MM-dd}", Source = source });
        }
        current.UpdatedAt = now;
    }

    private void RecordScore(EnvironmentSnapshot snapshot, string source)
    {
        var score = _risk.Calculate(snapshot).GlobalScore;
        var prior = snapshot.ScoreHistory.LastOrDefault()?.Score;
        snapshot.ScoreHistory.Add(new() { At = DateTimeOffset.UtcNow, Score = score, Source = source });
        if (prior is not null && Math.Abs(score - prior.Value) >= 0.1)
            snapshot.Changes.Add(new() { Kind = "Security score change", Summary = $"Modeled security score: {prior:0.0} → {score:0.0}", Source = source });
    }
    private static EnvironmentSnapshot Clone(EnvironmentSnapshot snapshot) => JsonSerializer.Deserialize<EnvironmentSnapshot>(JsonSerializer.Serialize(snapshot))!;
    private static string EventId() => Guid.NewGuid().ToString("N")[..12];
}

public static class ErrorTranslator
{
    public static UserError FromException(Exception exception)
    {
        var eventId = Guid.NewGuid().ToString("N")[..12];
        var message = exception switch
        {
            OperationCanceledException => "The operation was cancelled safely.",
            ArgumentException => exception.Message.Split('\n')[0],
            UnauthorizedAccessException => "SENTINEL cannot access this file or resource. Check its permissions and try again.",
            InvalidDataException => "The supplied evidence or saved data could not be validated. Review the source and format.",
            IOException => "SENTINEL could not read or write the requested file. Check the location and available storage.",
            InvalidOperationException => exception.Message.Split('\n')[0],
            _ => "SENTINEL could not complete this operation. Review the event details and try again."
        };
        return new(message, $"{exception.GetType().Name}; event {eventId}. Technical logs contain operation context without credentials.", eventId, exception is not OperationCanceledException);
    }
}
