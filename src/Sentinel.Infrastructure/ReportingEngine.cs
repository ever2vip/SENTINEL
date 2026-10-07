using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.Infrastructure;

/// <summary>Builds traceable, evidence-derived reports without an online service or a PDF license.</summary>
public sealed class ReportingEngine : IReportingEngine
{
    private readonly IRiskEngine _risk;
    private readonly IRemediationEngine _remediation;
    private readonly IComplianceEngine _compliance;
    private readonly IAttackPathEngine _paths;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public ReportingEngine() : this(new RiskEngine(), new RemediationEngine(), new ComplianceEngine(), new AttackPathEngine()) { }

    public ReportingEngine(IRiskEngine risk, IRemediationEngine remediation, IComplianceEngine compliance, IAttackPathEngine paths)
    {
        _risk = risk ?? throw new ArgumentNullException(nameof(risk));
        _remediation = remediation ?? throw new ArgumentNullException(nameof(remediation));
        _compliance = compliance ?? throw new ArgumentNullException(nameof(compliance));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
    }

    public async Task<ReportArtifact> ExportAsync(EnvironmentSnapshot snapshot, ReportKind kind, ReportFormat format,
        string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (!Enum.IsDefined(format)) throw new ArgumentOutOfRangeException(nameof(format));
        cancellationToken.ThrowIfCancellationRequested();
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        // Computation and file generation happen away from the desktop UI thread.
        var document = await Task.Run(() => BuildDocument(snapshot, kind, cancellationToken), cancellationToken).ConfigureAwait(false);
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                switch (format)
                {
                    case ReportFormat.Json:
                        await JsonSerializer.SerializeAsync(stream, document, JsonOptions, cancellationToken).ConfigureAwait(false);
                        break;
                    case ReportFormat.Csv:
                        await WriteTextAsync(stream, BuildCsv(document, cancellationToken), true, cancellationToken).ConfigureAwait(false);
                        break;
                    case ReportFormat.Html:
                        await WriteTextAsync(stream, BuildHtml(document, cancellationToken), false, cancellationToken).ConfigureAwait(false);
                        break;
                    case ReportFormat.Pdf:
                        var bytes = await Task.Run(() => SimplePdfWriter.Create(document, cancellationToken), cancellationToken).ConfigureAwait(false);
                        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                        break;
                }
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            // Same-directory rename keeps an existing report intact until the complete export is ready.
            File.Move(temporaryPath, fullPath, overwrite: true);
            return new ReportArtifact(fullPath, kind, format, document.GeneratedAt);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private ReportDocument BuildDocument(EnvironmentSnapshot snapshot, ReportKind kind, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var risk = _risk.Calculate(snapshot, now);
        token.ThrowIfCancellationRequested();
        // Use the remediation engine's deterministic priority rule for every report section,
        // including selection of the executive top ten and its first-priority narrative.
        var actions = _remediation.Plan(snapshot).OrderByDescending(a => a.ModeledRiskReduction)
            .ThenBy(a => a.Id, StringComparer.Ordinal).ToArray();
        var paths = _paths.Analyze(snapshot);
        var compliance = _compliance.Assess(snapshot);
        token.ThrowIfCancellationRequested();
        var document = new ReportDocument
        {
            ReportId = Guid.NewGuid().ToString("N"),
            Title = Title(kind),
            Kind = kind,
            GeneratedAt = now,
            EnvironmentId = snapshot.Id,
            EnvironmentName = snapshot.Name,
            EnvironmentMode = snapshot.Mode,
            SnapshotUpdatedAt = snapshot.UpdatedAt,
            GlobalSecurityScore = risk.CategoryScores.Count == 0 ? null : risk.GlobalScore,
            AssessedCategoryCount = risk.CategoryScores.Count,
            TotalModeledRisk = risk.TotalRisk,
            Disclaimer = snapshot.Mode == EnvironmentMode.Demo
                ? "DEMO ORGANIZATION — all environment evidence is synthetic training data. This report does not assess a real organization."
                : "Assessment of the stored environment snapshot. The operator is responsible for authorization of collection. Results describe collected evidence and modeled risk; they are not proof of compromise or a guarantee of security."
        };
        switch (kind)
        {
            case ReportKind.Executive:
                AddExecutive(document, snapshot, risk, actions, paths, compliance);
                break;
            case ReportKind.Technical:
                AddExecutive(document, snapshot, risk, actions, paths, compliance);
                AddFindings(document, snapshot, risk, token);
                AddAssets(document, snapshot, token);
                AddEvidence(document, snapshot, token);
                AddIdentity(document, snapshot, token);
                break;
            case ReportKind.Vulnerability:
                AddRiskSummary(document, snapshot, risk);
                AddFindings(document, snapshot, risk, token, vulnerabilityOnly: true);
                AddActions(document, actions.Where(a => a.FindingIds.Any(id => snapshot.Findings.Any(f => f.Id == id && IsVulnerability(f)))).ToArray(), risk.TotalRisk);
                break;
            case ReportKind.AssetInventory:
                AddAssets(document, snapshot, token);
                AddIdentity(document, snapshot, token);
                AddCertificates(document, snapshot, token);
                break;
            case ReportKind.Remediation:
                AddRiskSummary(document, snapshot, risk);
                AddActions(document, actions, risk.TotalRisk);
                AddPaths(document, paths, snapshot);
                break;
            case ReportKind.Compliance:
                AddCompliance(document, compliance, snapshot);
                AddActions(document, actions.Where(a => a.FindingIds.Any(id => snapshot.Findings.Any(f => f.Id == id && f.ControlIds.Count > 0))).ToArray(), risk.TotalRisk);
                break;
            case ReportKind.SecurityProgress:
                AddRiskSummary(document, snapshot, risk);
                AddProgress(document, snapshot, token);
                break;
        }
        AddProvenance(document, snapshot, token);
        return document;
    }

    private static void AddExecutive(ReportDocument report, EnvironmentSnapshot snapshot, RiskAssessment risk,
        IReadOnlyList<RemediationAction> actions, IReadOnlyList<AttackPath> paths, IReadOnlyList<ComplianceResult> compliance)
    {
        AddRiskSummary(report, snapshot, risk);
        var prioritizedActions = actions.Take(10).ToArray();
        var section = report.Section("Business risk and recommended focus");
        if (risk.RankedFindings.Count == 0)
            section.Paragraphs.Add("No active scored findings are present in this snapshot. This does not establish that all assets, identities, or controls have been assessed. Review collection coverage before making an assurance decision.");
        else
        {
            if (prioritizedActions.FirstOrDefault() is { } first)
                section.Paragraphs.Add($"The first remediation priority is '{first.Title}' [{first.Id}], matching priority 1 in the remediation plan. This grouped action addresses {first.FindingIds.Distinct(StringComparer.Ordinal).Count()} finding(s) across {first.AssetIds.Count} recorded asset(s), with an estimated direct reduction of {Number(first.ModeledRiskReduction)} currently modeled risk units and {Percent(first.Confidence)} evidence confidence. The estimate is not a guaranteed reduction in business loss; verify the underlying observations after remediation.");
            else
                section.Paragraphs.Add("No currently actionable remediation group can be derived from the scored findings. Review their dispositions and any current risk acceptances; modeled risk remains present.");
            var highest = risk.RankedFindings.OrderByDescending(f => f.Risk).ThenBy(f => f.Finding.Id, StringComparer.Ordinal).First();
            section.Paragraphs.Add($"The highest-risk individual finding is '{highest.Finding.Title}'. Its contextual risk is {Number(highest.Risk)} modeled risk units, with {Percent(highest.Finding.Confidence)} evidence confidence. It affects {highest.Finding.AssetIds.Distinct().Count()} recorded asset(s). Individual finding risk is distinct from the grouped remediation priorities. Addressing supported causes can reduce potential service disruption, unauthorized access, or data exposure; no attack has been executed.");
            section.Paragraphs.Add($"{paths.Count} defensive path(s) connect recorded relationships to critical assets. These are evidence-based scenarios, with confidence shown for each path; a path is not proof that compromise has occurred.");
        }
        AddActions(report, prioritizedActions, risk.TotalRisk);
        AddPaths(report, paths.OrderByDescending(p => p.Risk).Take(10).ToArray(), snapshot);
        AddCompliance(report, compliance, snapshot, summaryOnly: report.Kind == ReportKind.Executive);
    }

    private static void AddRiskSummary(ReportDocument report, EnvironmentSnapshot snapshot, RiskAssessment risk)
    {
        var section = report.Section("Security posture");
        section.Paragraphs.Add("The global score is a contextual model on a 0–100 scale, where higher is better. Modeled risk combines severity, legitimate exploitability intelligence, exposure, asset importance, privileges, identity reach, defensive paths and compensating controls. It is not a probability of breach or a monetary loss estimate.");
        var table = section.Table("Measure", "Value");
        table.Row("Global security score", risk.CategoryScores.Count == 0 ? "Not assessed" : Number(risk.GlobalScore) + " / 100");
        table.Row("Categories with assessment evidence", risk.CategoryScores.Count.ToString(CultureInfo.InvariantCulture) + " / " + Enum.GetValues<SecurityCategory>().Length.ToString(CultureInfo.InvariantCulture));
        table.Row("Total modeled risk", Number(risk.TotalRisk) + " units");
        table.Row("Recorded assets", snapshot.Assets.Count.ToString(CultureInfo.InvariantCulture));
        table.Row("Business-critical assets", snapshot.Assets.Count(a => a.IsCritical).ToString(CultureInfo.InvariantCulture));
        table.Row("Recorded identities", snapshot.Identities.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Informational })
            table.Row(severity + " open findings", snapshot.Findings.Count(f => f.Status == FindingStatus.Open && f.Severity == severity).ToString(CultureInfo.InvariantCulture));
        var categories = section.Table("Category", "Score / 100", "Recorded findings", "Coverage note");
        foreach (var category in Enum.GetValues<SecurityCategory>())
        {
            var count = snapshot.Findings.Count(f => f.Category == category);
            categories.Row(category.ToString(), risk.CategoryScores.TryGetValue(category, out var score) ? Number(score) : "Not calculated",
                count.ToString(CultureInfo.InvariantCulture), count == 0 ? "No findings recorded; assessment coverage is not established by this score." : "Based on recorded findings; review collection scope.");
        }
    }

    private static void AddFindings(ReportDocument report, EnvironmentSnapshot snapshot, RiskAssessment risk, CancellationToken token, bool vulnerabilityOnly = false)
    {
        var section = report.Section(vulnerabilityOnly ? "Correlated vulnerability register" : "Technical finding register");
        section.Paragraphs.Add("Findings are ordered by contextual modeled risk. Fixed, accepted-risk and false-positive dispositions remain visible for traceability; their treatment is determined by the risk engine. CVE identifiers and references are included only when they exist in the snapshot.");
        var scores = risk.RankedFindings.GroupBy(f => f.Finding.Id).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var assets = snapshot.Assets.GroupBy(a => a.Id).ToDictionary(g => g.Key, g => g.First().Name, StringComparer.Ordinal);
        var table = section.Table("Finding ID", "Title", "Root cause key", "Severity", "Category", "Status", "Modeled risk", "Confidence", "CVE", "CVSS", "Exploitability factor", "Privilege impact", "Identity reach", "Compensating control", "Software / version", "Affected assets", "Description", "Risk reasons", "Remediation", "Verification", "Evidence IDs", "Control IDs", "Source", "References", "First seen", "Last seen", "Fixed at", "Accepted until", "Disposition reason");
        foreach (var finding in snapshot.Findings.Where(f => !vulnerabilityOnly || IsVulnerability(f))
            .OrderByDescending(f => scores.TryGetValue(f.Id, out var value) ? value.Risk : 0).ThenBy(f => f.Title, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            scores.TryGetValue(finding.Id, out var scored);
            table.Row(finding.Id, finding.Title, OrUnknown(finding.RootCauseKey), finding.Severity.ToString(), finding.Category.ToString(), finding.Status.ToString(),
                scored is null ? "Not scored / inactive" : Number(scored.Risk), Percent(finding.Confidence), finding.Cve ?? "Not recorded",
                Number(finding.Cvss), Percent(finding.Exploitability), Percent(finding.PrivilegeImpact), Percent(finding.IdentityReach), Percent(finding.CompensatingControl), Join(finding.Software, finding.Version),
                string.Join("; ", finding.AssetIds.Distinct().Select(id => assets.TryGetValue(id, out var name) ? $"{name} [{id}]" : $"Unresolved asset [{id}]")),
                finding.Description, scored is null ? "No current scored-risk contribution" : string.Join("; ", scored.Reasons),
                OrUnknown(finding.Remediation), OrUnknown(finding.Verification), string.Join("; ", finding.EvidenceIds),
                string.Join("; ", finding.ControlIds), OrUnknown(finding.Source), string.Join("; ", finding.References),
                Date(finding.FirstSeen), Date(finding.LastSeen), Date(finding.FixedAt), Date(finding.AcceptedUntil), finding.DispositionReason);
        }
        AddEmptyNote(section, table, "No matching findings are recorded. This is not a statement that the environment is vulnerability-free.");
    }

    private static void AddAssets(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Asset inventory");
        var table = section.Table("Asset ID", "Name", "Type", "Address", "Operating system", "Owner", "Environment", "Business criticality / 5", "Exposure", "First seen", "Last seen", "Observed properties");
        foreach (var asset in snapshot.Assets.OrderByDescending(a => a.BusinessCriticality).ThenBy(a => a.Name, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            table.Row(asset.Id, asset.Name, asset.Kind.ToString(), asset.Address, asset.OperatingSystem, asset.Owner,
                asset.Environment, asset.BusinessCriticality.ToString(CultureInfo.InvariantCulture), Percent(asset.Exposure),
                Date(asset.FirstSeen), Date(asset.LastSeen), string.Join("; ", asset.Properties.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + p.Value)));
        }
        AddEmptyNote(section, table, "No assets have been recorded in this environment snapshot.");
    }

    private static void AddIdentity(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Identity posture inventory");
        var table = section.Table("Identity ID", "Display name", "Principal", "Provider", "Privileged", "MFA posture", "Last sign-in", "Groups", "Permissions");
        foreach (var identity in snapshot.Identities.OrderByDescending(i => i.IsPrivileged).ThenBy(i => i.DisplayName, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            table.Row(identity.Id, identity.DisplayName, identity.PrincipalName, identity.Provider, identity.IsPrivileged ? "Yes" : "No",
                identity.MfaEnabled.HasValue ? (identity.MfaEnabled.Value ? "Enabled" : "Not enabled") : "Not observed",
                Date(identity.LastSignIn), string.Join("; ", identity.Groups), string.Join("; ", identity.Permissions));
        }
        AddEmptyNote(section, table, "No identities are recorded; MFA and privilege coverage is unknown.");
    }

    private static void AddCertificates(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Certificate inventory");
        var table = section.Table("Certificate ID", "Asset ID", "Subject", "Issuer", "Expires", "Thumbprint");
        foreach (var certificate in snapshot.Certificates.OrderBy(c => c.NotAfter))
        {
            token.ThrowIfCancellationRequested();
            table.Row(certificate.Id, certificate.AssetId, certificate.Subject, certificate.Issuer, Date(certificate.NotAfter), certificate.Thumbprint);
        }
        AddEmptyNote(section, table, "No certificates have been recorded.");
    }

    private static void AddEvidence(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Evidence graph and observations");
        var nodes = section.Table("Evidence ID", "Type", "Label", "Source", "Confidence", "Observed at", "Properties");
        foreach (var node in snapshot.Nodes.OrderBy(n => n.Id, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            nodes.Row(node.Id, node.Kind.ToString(), node.Label, OrUnknown(node.Source), Percent(node.Confidence), Date(node.ObservedAt),
                string.Join("; ", node.Properties.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + p.Value)));
        }
        AddEmptyNote(section, nodes, "No evidence graph nodes are recorded.");
        var edges = section.Table("Relationship ID", "Source ID", "Target ID", "Relationship", "Enables defensive path", "Confidence", "Finding IDs", "Defensive break");
        foreach (var edge in snapshot.Edges.OrderBy(e => e.Id, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            edges.Row(edge.Id, edge.SourceId, edge.TargetId, edge.Relationship, edge.EnablesPath ? "Yes" : "No", Percent(edge.Confidence),
                string.Join("; ", edge.FindingIds), edge.DefensiveBreak);
        }
        var observations = section.Table("Observation ID", "Asset ID", "Engine", "Property", "Observed value", "Source", "Observed at");
        foreach (var observation in snapshot.Observations.OrderBy(o => o.ObservedAt))
        {
            token.ThrowIfCancellationRequested();
            observations.Row(observation.Id, observation.AssetId, observation.EngineId, observation.Property, observation.Value, OrUnknown(observation.Source), Date(observation.ObservedAt));
        }
        AddCertificates(report, snapshot, token);
    }

    private static void AddActions(ReportDocument report, IReadOnlyList<RemediationAction> actions, double totalRisk)
    {
        var section = report.Section("Prioritized remediation plan");
        section.Paragraphs.Add("Risk reduction is an estimate from the current evidence model. Actions may overlap; their risk reductions must not be added as independent predictions. Reassess after each change to verify the remaining risk. Confidence describes support in the collected evidence.");
        var table = section.Table("Action ID", "Priority", "Action", "Business reason", "Affected asset IDs", "Finding IDs", "Evidence IDs", "Modeled reduction", "Share of current modeled risk", "Confidence", "Instructions", "Verification");
        var priority = 0;
        foreach (var action in actions)
            table.Row(action.Id, (++priority).ToString(CultureInfo.InvariantCulture), action.Title, action.Why,
                string.Join("; ", action.AssetIds), string.Join("; ", action.FindingIds), string.Join("; ", action.EvidenceIds),
                Number(action.ModeledRiskReduction) + " units", totalRisk > 0 ? Percent(Math.Clamp(action.ModeledRiskReduction / totalRisk, 0, 1)) + " (estimate)" : "Not applicable",
                Percent(action.Confidence), OrUnknown(action.Instructions), OrUnknown(action.Verification));
        AddEmptyNote(section, table, "No remediation actions can currently be derived from recorded findings.");
    }

    private static void AddPaths(ReportDocument report, IReadOnlyList<AttackPath> paths, EnvironmentSnapshot snapshot)
    {
        var section = report.Section("Defensive attack-path scenarios");
        section.Paragraphs.Add("These scenarios follow recorded evidence relationships and permissions. They are not executed, and they do not imply successful exploitation. BREAK THIS PATH describes the defensive change to the recommended breakpoint.");
        var labels = snapshot.Nodes.GroupBy(n => n.Id).ToDictionary(g => g.Key, g => g.First().Label, StringComparer.Ordinal);
        var table = section.Table("Path ID", "Scenario", "Evidence path", "Critical asset ID", "Modeled severity / risk", "Confidence", "Breakpoint", "BREAK THIS PATH", "Finding IDs", "Relationship IDs");
        foreach (var path in paths.OrderByDescending(p => p.Risk))
            table.Row(path.Id, path.Title, string.Join(" → ", path.NodeIds.Select(id => labels.TryGetValue(id, out var label) ? $"{label} [{id}]" : $"Unresolved evidence [{id}]")),
                path.CriticalAssetId, Number(path.Risk), Percent(path.Confidence), path.BreakPoint, path.RecommendedAction,
                string.Join("; ", path.FindingIds), string.Join("; ", path.EdgeIds));
        AddEmptyNote(section, table, "No supported defensive paths are currently modeled. Incomplete relationship collection can limit path coverage.");
    }

    private static void AddCompliance(ReportDocument report, IReadOnlyList<ComplianceResult> results, EnvironmentSnapshot snapshot, bool summaryOnly = false)
    {
        var section = report.Section("Defensive framework mapping");
        section.Paragraphs.Add("NIST CSF 2.0 and CIS mappings support defensive improvement planning. A mapped finding is evidence of a gap; absence of a finding does not establish control effectiveness. This report is not a compliance certification or an independent audit opinion.");
        if (summaryOnly)
        {
            var summary = section.Table("Framework", "Recorded controls", "Controls with recorded active gaps", "Controls not assessed");
            foreach (var group in results.GroupBy(r => r.Control.Framework).OrderBy(g => g.Key, StringComparer.Ordinal))
                summary.Row(group.Key, group.Count().ToString(CultureInfo.InvariantCulture),
                    group.Count(r => r.FindingIds.Count > 0).ToString(CultureInfo.InvariantCulture),
                    group.Count(r => r.Status == "Not assessed").ToString(CultureInfo.InvariantCulture));
            section.Paragraphs.Add("The Compliance Report provides control-level evidence and gaps. A percentage of compliant controls is not reported because missing evidence cannot establish compliance.");
            return;
        }
        var table = section.Table("Framework", "Control ID", "Control", "Description", "Recorded status", "Finding IDs", "Evidence IDs");
        foreach (var result in results.OrderBy(r => r.Control.Framework, StringComparer.Ordinal).ThenBy(r => r.Control.Id, StringComparer.Ordinal))
        {
            var ids = result.FindingIds.ToHashSet(StringComparer.Ordinal);
            table.Row(result.Control.Framework, result.Control.Id, result.Control.Title, result.Control.Description, result.Status,
                string.Join("; ", result.FindingIds), string.Join("; ", snapshot.Findings.Where(f => ids.Contains(f.Id)).SelectMany(f => f.EvidenceIds).Distinct(StringComparer.Ordinal)));
        }
        AddEmptyNote(section, table, "No framework control results are available in this snapshot.");
    }

    private static void AddProgress(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Security progress and recorded changes");
        var history = snapshot.ScoreHistory.OrderBy(s => s.At).ToArray();
        if (history.Length > 1)
        {
            var before = history[^2];
            var after = history[^1];
            section.Paragraphs.Add($"The last two recorded scores changed from {Number(before.Score)} to {Number(after.Score)} ({Number(after.Score - before.Score)} points), between {Date(before.At)} and {Date(after.At)}. Scores are model outputs; the events below provide recorded context. Causation is not inferred from timing alone.");
        }
        else section.Paragraphs.Add("At least two recorded assessments are needed to calculate a historical score change. No prior score has been invented.");
        var scores = section.Table("Recorded at", "Security score / 100", "Source");
        foreach (var score in history)
        {
            token.ThrowIfCancellationRequested();
            scores.Row(Date(score.At), Number(score.Score), OrUnknown(score.Source));
        }
        var changes = section.Table("Event ID", "Recorded at", "Change type", "Summary", "Entity ID", "Source");
        foreach (var change in snapshot.Changes.OrderByDescending(c => c.At))
        {
            token.ThrowIfCancellationRequested();
            changes.Row(change.Id, Date(change.At), change.Kind, change.Summary, change.EntityId, OrUnknown(change.Source));
        }
        AddEmptyNote(section, changes, "No historical change events are recorded.");
    }

    private static void AddProvenance(ReportDocument report, EnvironmentSnapshot snapshot, CancellationToken token)
    {
        var section = report.Section("Scope, provenance and limitations");
        section.Paragraphs.Add(report.Disclaimer);
        section.Paragraphs.Add($"Report {report.ReportId} was generated at {Date(report.GeneratedAt)} from environment '{snapshot.Name}' [{snapshot.Id}], snapshot schema {snapshot.SchemaVersion}, last updated {Date(snapshot.UpdatedAt)}. The report does not perform new collection or change the environment.");
        section.Paragraphs.Add($"The snapshot contains {snapshot.Assets.Count} assets, {snapshot.Findings.Count} findings, {snapshot.Nodes.Count} evidence nodes, {snapshot.Edges.Count} relationships, {snapshot.Observations.Count} observations and {snapshot.Scans.Count} scan runs. Sources and timestamps are preserved where available. Missing data is shown as not recorded or not observed, rather than assumed secure.");
        section.Paragraphs.Add("Collection scope, permissions and engine availability limit coverage. Stored inventory can be stale. Validate fixes through the stated verification procedure and a new authorized assessment. Reports may contain sensitive asset and identity information; handle them under the organization's data policy.");
        var scans = section.Table("Scan ID", "Engine", "Recorded scope", "Status", "Started", "Finished", "Event / correlation ID", "Result message");
        foreach (var scan in snapshot.Scans.OrderByDescending(s => s.StartedAt))
        {
            token.ThrowIfCancellationRequested();
            scans.Row(scan.Id, scan.EngineId, OrUnknown(scan.ScopeSummary), scan.Status.ToString(), Date(scan.StartedAt), Date(scan.FinishedAt), scan.EventId, scan.Message);
        }
        AddEmptyNote(section, scans, snapshot.Mode == EnvironmentMode.Demo
            ? "No live scans are recorded. Demo evidence is synthetic and fully offline."
            : "No scan history is recorded. An inventory without scan history does not establish completed assessment coverage.");
    }

    private static string BuildHtml(ReportDocument report, CancellationToken token)
    {
        static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
        var output = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\"><title>");
        output.Append(E(report.Title)).Append(" — SENTINEL</title><style>");
        output.Append("body{margin:0;background:#f1f5f9;color:#172033;font:15px/1.6 'Segoe UI',Arial,sans-serif}main{max-width:1240px;margin:32px auto;background:white;border:1px solid #d9e1eb;border-radius:16px;padding:40px}header{border-bottom:3px solid #1766c0;padding-bottom:24px}.brand{letter-spacing:3px;color:#1766c0;font-weight:700}h1{font-size:30px;margin:12px 0}h2{font-size:22px;color:#123963;margin-top:36px}p{max-width:1100px}.meta{color:#556275}.notice{background:#eef5ff;border-left:4px solid #1766c0;padding:14px 18px;border-radius:6px}.table-wrap{overflow-x:auto;margin:20px 0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:10px 12px;border:1px solid #dce3ec;vertical-align:top;text-align:left;overflow-wrap:anywhere;min-width:100px;white-space:pre-line}th{background:#eaf0f8;color:#193653}tr:nth-child(even){background:#f7f9fc}footer{border-top:1px solid #dce3ec;margin-top:32px;padding-top:20px;color:#66758a;font-size:12px}@media print{body{background:white}main{margin:0;border:0;padding:8px}.table-wrap{overflow:visible}table{font-size:9px}th,td{padding:5px;min-width:0}thead{display:table-header-group}tr{break-inside:avoid}h2{break-after:avoid}a{color:inherit}} </style></head><body><main><header><div class=\"brand\">SENTINEL ENTERPRISE</div><h1>");
        output.Append(E(report.Title)).Append("</h1><p class=\"meta\">").Append(E(report.EnvironmentName)).Append(" · ")
            .Append(E(report.EnvironmentMode.ToString())).Append(" · Generated ").Append(E(Date(report.GeneratedAt))).Append("</p></header><p class=\"notice\">")
            .Append(E(report.Disclaimer)).Append("</p>");
        foreach (var section in report.Sections)
        {
            token.ThrowIfCancellationRequested();
            output.Append("<section><h2>").Append(E(section.Title)).Append("</h2>");
            foreach (var paragraph in section.Paragraphs) output.Append("<p>").Append(E(paragraph)).Append("</p>");
            foreach (var table in section.Tables)
            {
                output.Append("<div class=\"table-wrap\"><table><thead><tr>");
                foreach (var column in table.Columns) output.Append("<th scope=\"col\">").Append(E(column)).Append("</th>");
                output.Append("</tr></thead><tbody>");
                foreach (var row in table.Rows)
                {
                    token.ThrowIfCancellationRequested();
                    output.Append("<tr>");
                    foreach (var cell in row) output.Append("<td>").Append(E(cell)).Append("</td>");
                    output.Append("</tr>");
                }
                output.Append("</tbody></table></div>");
            }
            output.Append("</section>");
        }
        return output.Append("<footer>Report ID: ").Append(E(report.ReportId)).Append(" · Snapshot: ").Append(E(report.EnvironmentId))
            .Append(" · Local evidence export. PDF uses standard Western-European fonts; JSON, CSV and HTML preserve Unicode names.</footer></main></body></html>").ToString();
    }

    private static string BuildCsv(ReportDocument report, CancellationToken token)
    {
        var output = new StringBuilder();
        void Line(params string[] cells) => output.AppendJoin(',', cells.Select(CsvCell)).Append("\r\n");
        Line("Report ID", "Section", "Record", "Field", "Value");
        var metadata = new Dictionary<string, string>
        {
            ["Title"] = report.Title, ["Kind"] = report.Kind.ToString(), ["Environment ID"] = report.EnvironmentId,
            ["Environment"] = report.EnvironmentName, ["Mode"] = report.EnvironmentMode.ToString(), ["Generated at"] = Date(report.GeneratedAt),
            ["Snapshot updated at"] = Date(report.SnapshotUpdatedAt), ["Global score"] = report.GlobalSecurityScore.HasValue ? Number(report.GlobalSecurityScore.Value) : "Not assessed",
            ["Assessed category count"] = report.AssessedCategoryCount.ToString(CultureInfo.InvariantCulture),
            ["Total modeled risk"] = Number(report.TotalModeledRisk), ["Limitations"] = report.Disclaimer
        };
        foreach (var pair in metadata) Line(report.ReportId, "Metadata", "Metadata", pair.Key, pair.Value);
        foreach (var section in report.Sections)
        {
            token.ThrowIfCancellationRequested();
            for (var p = 0; p < section.Paragraphs.Count; p++) Line(report.ReportId, section.Title, $"Note {p + 1}", "Narrative", section.Paragraphs[p]);
            for (var t = 0; t < section.Tables.Count; t++)
            {
                var table = section.Tables[t];
                for (var r = 0; r < table.Rows.Count; r++)
                {
                    token.ThrowIfCancellationRequested();
                    for (var c = 0; c < table.Columns.Count; c++)
                        Line(report.ReportId, section.Title, $"Table {t + 1} / row {r + 1}", table.Columns[c], table.Rows[r][c]);
                }
            }
        }
        return output.ToString();
    }

    private static string CsvCell(string value)
    {
        value ??= "";
        // Quoting is insufficient to stop spreadsheet evaluation. Prefix dangerous text cells.
        var trimmed = value.AsSpan().TrimStart();
        if ((trimmed.Length > 0 && "=+-@\t\r\n".Contains(trimmed[0])) || (value.Length > 0 && value[0] is '\t' or '\r' or '\n'))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task WriteTextAsync(Stream stream, string text, bool byteOrderMark, CancellationToken token)
    {
        var encoding = new UTF8Encoding(byteOrderMark);
        if (byteOrderMark) await stream.WriteAsync(encoding.GetPreamble(), token).ConfigureAwait(false);
        await stream.WriteAsync(encoding.GetBytes(text), token).ConfigureAwait(false);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private static bool IsVulnerability(Finding finding) => finding.Category == SecurityCategory.Vulnerability || !string.IsNullOrWhiteSpace(finding.Cve);
    private static string Number(double value) => double.IsFinite(value) ? value.ToString("0.0", CultureInfo.InvariantCulture) : "Not calculated";
    private static string Percent(double value) => double.IsFinite(value) ? Math.Clamp(value, 0, 1).ToString("P0", CultureInfo.InvariantCulture) : "Unknown";
    private static string Date(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? "Not recorded";
    private static string Join(string first, string second) => string.Join(" / ", new[] { first, second }.Where(s => !string.IsNullOrWhiteSpace(s)));
    private static string OrUnknown(string value) => string.IsNullOrWhiteSpace(value) ? "Not recorded" : value;
    private static void AddEmptyNote(ReportSection section, ReportTable table, string note) { if (table.Rows.Count == 0) section.Paragraphs.Add(note); }
    private static string Title(ReportKind kind) => kind switch
    {
        ReportKind.Executive => "Executive Security Report", ReportKind.Technical => "Technical Assessment Report",
        ReportKind.Vulnerability => "Vulnerability Report", ReportKind.AssetInventory => "Asset Inventory",
        ReportKind.Remediation => "Remediation Report", ReportKind.Compliance => "Compliance Report",
        ReportKind.SecurityProgress => "Security Progress Report", _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}

internal sealed class ReportDocument
{
    public string SchemaVersion { get; init; } = "sentinel.report.v1";
    public string ReportId { get; init; } = "";
    public string Title { get; init; } = "";
    public ReportKind Kind { get; init; }
    public DateTimeOffset GeneratedAt { get; init; }
    public string EnvironmentId { get; init; } = "";
    public string EnvironmentName { get; init; } = "";
    public EnvironmentMode EnvironmentMode { get; init; }
    public DateTimeOffset SnapshotUpdatedAt { get; init; }
    public double? GlobalSecurityScore { get; init; }
    public int AssessedCategoryCount { get; init; }
    public double TotalModeledRisk { get; init; }
    public string Disclaimer { get; init; } = "";
    public List<ReportSection> Sections { get; } = [];
    public ReportSection Section(string title) { var section = new ReportSection(title); Sections.Add(section); return section; }
}

internal sealed class ReportSection(string title)
{
    public string Title { get; } = title;
    public List<string> Paragraphs { get; } = [];
    public List<ReportTable> Tables { get; } = [];
    public ReportTable Table(params string[] columns) { var table = new ReportTable(columns); Tables.Add(table); return table; }
}

internal sealed class ReportTable(string[] columns)
{
    public IReadOnlyList<string> Columns { get; } = columns;
    public List<string[]> Rows { get; } = [];
    public void Row(params string[] values)
    {
        if (values.Length != Columns.Count) throw new ArgumentException("The report row does not match its schema.", nameof(values));
        Rows.Add(values);
    }
}
