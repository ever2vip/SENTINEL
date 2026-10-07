using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Sentinel.Core;

namespace Sentinel.Desktop;

public partial class MainWindow
{
    private void RenderCommandCenter()
    {
        var risk = _coordinator.Risk;
        var open = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open).ToList();
        var history = Snapshot.ScoreHistory.OrderBy(s => s.At).ToList();
        var assessed = risk.CategoryScores.Count > 0;
        var delta = history.Count >= 2 ? history[^1].Score - history[^2].Score : (double?)null;
        var score = Ui.Stack(Ui.Text("GLOBAL SECURITY SCORE", 12, "MutedBrush", true),
            Ui.Text(assessed ? $"{risk.GlobalScore:0} / 100" : "Not assessed", 40, "TextBrush", true),
            Ui.Badge(!assessed ? "Coverage unknown" : risk.GlobalScore < 50 ? "High exposure" : risk.GlobalScore < 75 ? "Elevated exposure" : "Stronger modeled posture", !assessed ? "MutedBrush" : risk.GlobalScore < 50 ? "HighBrush" : "AccentBrush"),
            Ui.Text(delta is double value ? $"{value:+0.0;-0.0;0.0} points since previous recorded assessment" : "Trend starts after two assessments", 14, "MutedBrush"));
        var context = Ui.Stack(Ui.Text("Security posture", 20, bold: true), Ui.Text("Evidence, context and a defensible order of action.", 15),
            Ui.Text($"{risk.CategoryScores.Count} of 8 categories have posture evidence · {Snapshot.UpdatedAt.LocalDateTime:g}", 12, "MutedBrush"),
            Ui.Text(open.Count > 0 ? $"Mean open-finding confidence {open.Average(f => f.Confidence):P0}. Coverage may be incomplete." : "No open findings in collected scope. Unassessed systems remain unknown.", 12, "MutedBrush"),
            Ui.Toolbar(Ui.Button("Review prioritized findings", () => { Navigate("Vulnerabilities"); PageContent.Children.Clear(); RenderFindings(Snapshot.Findings); }), Ui.Button("Open remediation plan", () => Navigate("Remediation"), true)));
        PageContent.Children.Add(Ui.Columns(Ui.Card(score), Ui.Card(context)));
        PageContent.Children.Add(Ui.Columns(
            Ui.Metric("CRITICAL", open.Count(f => f.Severity == Severity.Critical).ToString(), "Open findings", "CriticalBrush"),
            Ui.Metric("HIGH", open.Count(f => f.Severity == Severity.High).ToString(), "Open findings", "HighBrush"),
            Ui.Metric("ASSETS IN SCOPE", Snapshot.Assets.Count.ToString(), "Recorded inventory")));
        PageContent.Children.Add(Ui.Columns(
            Ui.Metric("CRITICAL ASSETS", Snapshot.Assets.Count(a => a.IsCritical).ToString(), "Business importance 4–5/5"),
            Ui.Metric("DEFENSIVE PATHS", _coordinator.AttackPaths.Count.ToString(), "Supported evidence chains", "HighBrush"),
            Ui.Metric("EXPOSURE CHANGES", Snapshot.Changes.Count(c => c.Kind.Contains("exposure", StringComparison.OrdinalIgnoreCase) && c.At >= Snapshot.UpdatedAt.AddDays(-1)).ToString(), "Last 24h of evidence history")));
        PageContent.Children.Add(Ui.Columns(Ui.Card(BuildTrend()), Ui.Card(FindingDistribution(open))));
        var actions = _coordinator.Remediations.Take(3).ToList();
        var associated = risk.TotalRisk > 0 ? Math.Min(100, actions.Sum(a => a.ModeledRiskReduction) / risk.TotalRisk * 100) : 0;
        var priorities = Ui.Section("Priority remediation", $"First {actions.Count} actions address approximately {associated:0}% of current modeled finding risk. Benefit depends on verification.");
        foreach (var action in actions) priorities.Children.Add(ActionSummary(action));
        if (actions.Count == 0) priorities.Children.Add(Ui.Empty("No actionable remediation", "Collect posture evidence to establish a work order.", "Remediation"));
        priorities.Children.Add(Ui.Button("Review remediation workflow", () => Navigate("Remediation"), true));
        PageContent.Children.Add(Ui.Card(priorities));
        var pathSection = Ui.Section("Critical attack path", "Modeled from exposure and permissions; no path is executed.");
        if (_coordinator.AttackPaths.FirstOrDefault() is AttackPath path)
            pathSection.Children.Add(new AttackPathView(Snapshot, path, OpenAsset, OpenFinding, ReviewPath, OpenPathGraph, true, _coordinator.Remediations, risk));
        else pathSection.Children.Add(Ui.Empty("No supported path", "The collected graph does not support a complete path. Coverage may be incomplete.", "Attack Paths"));
        PageContent.Children.Add(Ui.Card(pathSection));
        var recent = Ui.Section("Recent security changes");
        foreach (var change in Snapshot.Changes.OrderByDescending(c => c.At).Take(4)) recent.Children.Add(ChangeSummary(change));
        if (Snapshot.Changes.Count == 0) recent.Children.Add(Ui.Text("No recorded changes yet.", brush: "MutedBrush"));
        recent.Children.Add(Ui.Button("Open monitoring timeline", () => Navigate("Monitoring")));
        var surface = Ui.Section("Attack surface snapshot", "Recorded exposure, never a claim of complete external discovery.");
        surface.Children.Add(Ui.Text($"{Snapshot.Assets.Count(a => a.Exposure >= .8)} high-exposure assets · {Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Service)} observed service nodes", 15));
        surface.Children.Add(Ui.Text($"{Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Domain)} domains · {Snapshot.Certificates.Count} certificates · {Snapshot.Certificates.Count(c => c.NotAfter < Snapshot.UpdatedAt.AddDays(30))} expiring within 30 days", 14, "MutedBrush"));
        surface.Children.Add(Ui.Button("Explore attack surface", () => Navigate("Attack Surface")));
        PageContent.Children.Add(Ui.Columns(Ui.Card(recent), Ui.Card(surface)));
        var critical = Ui.Section("Critical assets", "Business context determines the potential organizational impact.");
        foreach (var asset in Snapshot.Assets.Where(a => a.IsCritical).OrderByDescending(AssetRisk).Take(5))
            critical.Children.Add(Ui.Toolbar(Ui.Button(asset.Name, () => OpenAsset(asset.Id)), Ui.Badge($"Importance {asset.BusinessCriticality}/5"), Ui.Text($"Highest linked finding risk {AssetRisk(asset):0.0}/100", 12, "MutedBrush")));
        if (!Snapshot.Assets.Any(a => a.IsCritical)) critical.Children.Add(Ui.Text("No critical assets are classified in the current inventory.", brush: "MutedBrush"));
        var compliance = Ui.Section("Compliance evidence", "Control mappings support review; they do not establish certification.");
        foreach (var group in _coordinator.Compliance.GroupBy(c => c.Control.Framework))
            compliance.Children.Add(Ui.Text($"{group.Key}: {group.Count(c => c.FindingIds.Count > 0)} controls with findings / {group.Count()} mapped", 14));
        compliance.Children.Add(Ui.Button("Review control evidence", () => Navigate("Compliance")));
        PageContent.Children.Add(Ui.Columns(Ui.Card(critical), Ui.Card(compliance)));
        if (Snapshot.Assets.Count == 0) AddEmpty("Your live environment is unassessed", "Authorize an exact scope or import attested evidence. Unknown coverage is never displayed as a perfect score.");
    }

    private double AssetRisk(Asset asset) => _coordinator.Risk.RankedFindings.Where(f => f.Finding.AssetIds.Contains(asset.Id)).Select(f => f.Risk).DefaultIfEmpty(0).Max();

    private StackPanel BuildTrend()
    {
        var panel = Ui.Section("Security score trend", "Recorded history · higher is stronger");
        if (Snapshot.ScoreHistory.Count == 0) { panel.Children.Add(Ui.Empty("Trend not available", "History starts after a completed assessment.", "Monitoring")); return panel; }
        panel.Children.Add(new ScoreTrendView(Snapshot.ScoreHistory.OrderBy(s => s.At).TakeLast(16).ToList()));
        return panel;
    }

    private StackPanel FindingDistribution(IReadOnlyList<Finding> open)
    {
        var panel = Ui.Section("Finding distribution", "Open findings by severity");
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            var count = open.Count(f => f.Severity == severity);
            var line = new Grid { Margin = new Thickness(0, 6, 0, 6) };
            line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(104) });
            line.ColumnDefinitions.Add(new ColumnDefinition());
            line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(76) });
            line.Children.Add(Ui.Badge(severity.ToString(), SeverityBrush(severity)));
            var bar = new ProgressBar { Minimum = 0, Maximum = Math.Max(1, open.Count), Value = count, Height = 8, Margin = new Thickness(12, 8, 12, 8), VerticalAlignment = VerticalAlignment.Center };
            bar.SetResourceReference(Control.ForegroundProperty, SeverityBrush(severity));
            Grid.SetColumn(bar, 1); line.Children.Add(bar);
            var amount = Ui.Text($"{count} open", 14); Grid.SetColumn(amount, 2); line.Children.Add(amount);
            panel.Children.Add(line);
        }
        panel.Children.Add(Ui.Button("Review findings", () => { Navigate("Vulnerabilities"); PageContent.Children.Clear(); RenderFindings(Snapshot.Findings); }));
        return panel;
    }

    private void RenderNetwork()
    {
        var nodes = Snapshot.Nodes.Where(n => n.Kind == EvidenceKind.Service).ToList();
        var directExposure = Snapshot.Edges.Where(e => Snapshot.Nodes.Any(n => n.Id == e.SourceId && n.Kind == EvidenceKind.Internet)).Select(e => e.TargetId).ToHashSet();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("OBSERVED SERVICES", nodes.Count.ToString(), "Collected service evidence"), Ui.Metric("EXPOSURE RELATIONSHIPS", directExposure.Count.ToString(), "Known external boundary edges", "HighBrush"), Ui.Metric("NETWORK FINDINGS", Snapshot.Findings.Count(f => f.Category == SecurityCategory.Network && f.Status == FindingStatus.Open).ToString(), "Open posture issues")));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Network posture", "Exact authorized target observations, configuration and change evidence."), Ui.Toolbar(Ui.Button("View topology", () => Navigate("Evidence Graph"), true), Ui.Button("Assess authorized targets", ScanButton_Click)), Ui.Text("Assessment scope is explicitly confirmed for each run. Service reachability alone does not prove internet exposure or vulnerability.", 12, "MutedBrush"))));
        var tabs = new TabControl();
        var services = Ui.Table(nodes.Select(n => new { n.Label, Type = "Recorded service", Exposure = directExposure.Contains(n.Id) ? "External relationship" : "Not established", n.Source, Confidence = n.Confidence.ToString("P0"), Observed = n.ObservedAt.LocalDateTime.ToString("g"), n.Id }), ("Observed service", "Label", 0), ("Exposure", "Exposure", 180), ("Source", "Source", 170), ("Confidence", "Confidence", 100));
        services.SelectionChanged += (_, _) => { if (services.SelectedItem is not null) { var id = services.SelectedItem.GetType().GetProperty("Id")?.GetValue(services.SelectedItem)?.ToString(); if (id is not null) OpenEvidence(id); } };
        tabs.Items.Add(new TabItem { Header = "Observed services", Content = nodes.Count > 0 ? services : Ui.Empty("No service evidence", "Run a scoped network assessment to collect observable services.", "Network") });
        var assets = Snapshot.Assets.Where(a => a.Kind is AssetKind.NetworkDevice or AssetKind.Server || a.Properties.ContainsKey("OpenPorts")).ToList();
        tabs.Items.Add(new TabItem { Header = "Infrastructure", Content = AssetList(assets) });
        tabs.Items.Add(new TabItem { Header = "Exposure", Content = AssetList(Snapshot.Assets.Where(a => a.Exposure >= .8)) });
        tabs.Items.Add(new TabItem { Header = "Changes", Content = Timeline(Snapshot.Changes.Where(c => c.Kind.Contains("exposure", StringComparison.OrdinalIgnoreCase) || c.Source.Contains("network", StringComparison.OrdinalIgnoreCase))) });
        PageContent.Children.Add(Ui.Card(tabs));
        AddCategoryFindings(SecurityCategory.Network);
    }

    private UIElement AssetList(IEnumerable<Asset> assets)
    {
        var list = assets.ToList();
        if (list.Count == 0) return Ui.Empty("No matching assets", "No inventory evidence matches this view.", "Assets");
        var table = Ui.Table(list, ("Asset", "Name", 0), ("Address", "Address", 160), ("OS", "OperatingSystem", 180), ("Owner", "Owner", 140));
        table.SelectionChanged += (_, _) => { if (table.SelectedItem is Asset asset) OpenAsset(asset.Id); };
        return table;
    }

    private void RenderEndpoints()
    {
        var endpoints = Snapshot.Assets.Where(a => a.Kind is AssetKind.Endpoint or AssetKind.Server).ToList();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("ENDPOINTS + SERVERS", endpoints.Count.ToString(), "Recorded endpoint inventory"), Ui.Metric("POSTURE OBSERVATIONS", Snapshot.Observations.Count(o => endpoints.Any(a => a.Id == o.AssetId)).ToString(), "Accessible measurements"), Ui.Metric("OPEN ENDPOINT FINDINGS", Snapshot.Findings.Count(f => f.Category == SecurityCategory.Endpoint && f.Status == FindingStatus.Open).ToString(), "Configuration and patch posture", "HighBrush")));
        PageContent.Children.Add(Ui.Card(Ui.Section("Endpoint security", "Firewall, encryption, protection and patch observations. Access-denied measurements remain unknown; remote collection requires authorized evidence.")));
        RenderAssets(endpoints);
        AddCategoryFindings(SecurityCategory.Endpoint);
    }

    private void RenderActiveDirectory()
    {
        var directory = Snapshot.Identities.Where(i => i.Provider.Contains("Directory", StringComparison.OrdinalIgnoreCase) || i.Provider.Equals("AD", StringComparison.OrdinalIgnoreCase)).ToList();
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Directory access posture", "Recorded groups, privileges and permission relationships."), Ui.Toolbar(Ui.Badge("Defensive configuration review", "AccentBrush"), Ui.Button("Explore directory relationships", () => Navigate("Evidence Graph"))), Ui.Text($"{directory.SelectMany(i => i.Groups).Distinct().Count()} recorded groups · {directory.Count(i => i.LastSignIn.HasValue && i.LastSignIn < Snapshot.UpdatedAt.AddDays(-90))} identities with sign-in older than 90 days", 14))));
        RenderIdentities(directory);
        AddCategoryFindings(SecurityCategory.Identity);
    }

    private void RenderCloud()
    {
        var resources = Snapshot.Assets.Where(a => a.Kind == AssetKind.CloudResource).ToList();
        var panels = new List<UIElement>();
        foreach (var provider in new[] { "Azure", "Microsoft 365", "AWS", "Google Cloud" })
        {
            var count = resources.Count(a => a.Properties.GetValueOrDefault("provider", "").Equals(provider, StringComparison.OrdinalIgnoreCase));
            panels.Add(Ui.Metric(provider.ToUpperInvariant(), count.ToString(), count == 0 ? "No resource evidence" : Snapshot.Mode == EnvironmentMode.Demo ? "Synthetic resource inventory" : "Imported resource evidence"));
        }
        PageContent.Children.Add(Ui.Columns(panels.ToArray()));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Cloud configuration and IAM", "Inventory, exposure and relationships from authorized evidence."), Ui.Text("Provider connectors are extension contracts in this release. Imported records retain source provenance; no provider is shown as connected without an authenticated implementation.", 14, "MutedBrush"), Ui.Button("Review integration availability", () => Navigate("Integrations")))));
        RenderAssets(resources); AddCategoryFindings(SecurityCategory.Cloud);
    }

    private void RenderWeb()
    {
        PageContent.Children.Add(Ui.Columns(Ui.Metric("WEB PROPERTIES", Snapshot.Assets.Count(a => a.Kind == AssetKind.WebApplication).ToString(), "Authorized inventory"), Ui.Metric("CERTIFICATES", Snapshot.Certificates.Count.ToString(), "Observed TLS certificates"), Ui.Metric("EXPIRING / EXPIRED", Snapshot.Certificates.Count(c => c.NotAfter <= Snapshot.UpdatedAt.AddDays(30)).ToString(), "Within 30 days of evidence timestamp", "HighBrush")));
        PageContent.Children.Add(Ui.Card(Ui.Section("Web, TLS and email posture", "Non-destructive transport/header/cookie and SPF/DMARC/DKIM evidence. No crawling, authentication or exploitation.")));
        RenderAssets(Snapshot.Assets.Where(a => a.Kind == AssetKind.WebApplication));
        var certificates = Ui.Section("Certificate inventory");
        certificates.Children.Add(Snapshot.Certificates.Count == 0 ? Ui.Empty("No certificate evidence", "Assess authorized HTTPS properties to observe certificates.", "Certificate") : Ui.Table(Snapshot.Certificates.Select(c => new { c.Subject, c.Issuer, Expires = c.NotAfter.LocalDateTime.ToString("g"), State = c.NotAfter < Snapshot.UpdatedAt ? "Expired" : c.NotAfter < Snapshot.UpdatedAt.AddDays(30) ? "Expiring soon" : "Within recorded validity", c.AssetId }), ("Subject", "Subject", 0), ("Issuer", "Issuer", 200), ("Expires", "Expires", 160), ("State", "State", 160)));
        PageContent.Children.Add(Ui.Card(certificates));
        AddCategoryFindings(SecurityCategory.Web, SecurityCategory.Email);
    }

    private void RenderAttackSurface()
    {
        var exposed = Snapshot.Assets.Where(a => a.Exposure > 0).ToList();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("EXPOSURE RECORDED", exposed.Count.ToString(), "Partial evidence-based model"), Ui.Metric("HIGH EXPOSURE", exposed.Count(a => a.Exposure >= .8).ToString(), "Model exposure >=80%", "HighBrush"), Ui.Metric("EXPOSED CRITICAL ASSETS", exposed.Count(a => a.IsCritical && a.Exposure >= .8).ToString(), "Business-critical context", "CriticalBrush")));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("External and internal exposure", "Identify the recorded relationships that increase business risk."), Ui.Text($"{Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Service)} services · {Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Domain)} domains · {Snapshot.Certificates.Count} certificates", 14), Ui.Toolbar(Ui.Button("Explore exposure graph", () => Navigate("Evidence Graph"), true), Ui.Button("Review defensive paths", () => Navigate("Attack Paths"))))));
        RenderAssets(exposed);
    }

    private void RenderAttackPaths()
    {
        var paths = _coordinator.AttackPaths;
        PageContent.Children.Add(Ui.Card(Ui.Section("Evidence-based defensive paths", "Typed relationships connect recorded exposure to critical assets. Confidence describes evidence quality; modeled paths do not establish exploit success.")));
        if (paths.Count == 0) { AddEmpty("No supported paths are currently modeled", "A complete evidence chain has not met the existing path rules. Incomplete coverage may conceal other paths."); return; }
        foreach (var path in paths.OrderByDescending(p => p.Risk)) PageContent.Children.Add(Ui.Card(new AttackPathView(Snapshot, path, OpenAsset, OpenFinding, ReviewPath, OpenPathGraph, false, _coordinator.Remediations, _coordinator.Risk)));
    }

    private void RenderGraph() => PageContent.Children.Add(new EvidenceGraphView(Snapshot, _coordinator.AttackPaths, _coordinator.Risk, OpenAsset, OpenFinding, ReviewPath));

    private void RenderCompliance()
    {
        var results = _coordinator.Compliance;
        PageContent.Children.Add(Ui.Columns(Ui.Metric("MAPPED CONTROLS", results.Count.ToString(), "NIST CSF 2.0 + CIS Controls"), Ui.Metric("WITH FINDINGS", results.Count(c => c.FindingIds.Count > 0).ToString(), "Evidence requiring review", "HighBrush"), Ui.Metric("UNASSESSED", results.Count(c => c.Status.Equals("Not assessed", StringComparison.OrdinalIgnoreCase)).ToString(), "No compliance claim")));
        var framework = Ui.Select(new[] { "All frameworks" }.Concat(results.Select(c => c.Control.Framework).Distinct()), "All frameworks");
        var search = Ui.Search("Search controls");
        var rows = results.Select(c => new { c.Control.Id, c.Control.Framework, c.Control.Title, c.Status, Findings = c.FindingIds.Count }).ToList();
        var grid = Ui.Table(rows, ("Control", "Id", 160), ("Framework", "Framework", 145), ("Outcome", "Title", 0), ("Evidence state", "Status", 180), ("Findings", "Findings", 90));
        void Filter() => grid.ItemsSource = rows.Where(c => (framework.SelectedItem?.ToString() == "All frameworks" || c.Framework == framework.SelectedItem?.ToString()) && $"{c.Id} {c.Title} {c.Status}".Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToList();
        framework.SelectionChanged += (_, _) => Filter(); search.TextChanged += (_, _) => Filter();
        var details = new StackPanel();
        grid.SelectionChanged += (_, _) =>
        {
            details.Children.Clear();
            var id = grid.SelectedItem?.GetType().GetProperty("Id")?.GetValue(grid.SelectedItem)?.ToString();
            var result = results.FirstOrDefault(c => c.Control.Id == id);
            if (result is null) return;
            details.Children.Add(Ui.Text(result.Control.Description, 15));
            foreach (var findingId in result.FindingIds) details.Children.Add(Ui.Button(Snapshot.Findings.FirstOrDefault(f => f.Id == findingId)?.Title ?? findingId, () => OpenFinding(findingId)));
        };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Control evidence workspace", "Unobserved controls remain unassessed. Mapping is not certification."), Ui.Toolbar(search, framework), grid, details)));
    }

    private void RenderMonitoring()
    {
        PageContent.Children.Add(Ui.Columns(Ui.Metric("ASSESSMENT RUNS", Snapshot.Scans.Count.ToString(), "Exact scope retained"), Ui.Metric("RECORDED CHANGES", Snapshot.Changes.Count.ToString(), "Evidence history"), Ui.Metric("MAINTENANCE", "Local service", "No autonomous scanning")));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Assessment history", "Completed comparable scopes support change detection. Interrupted scans do not establish findings were fixed."), Snapshot.Scans.Count == 0 ? Ui.Empty("No assessment runs", "Authorize a scope to start live history; demo timelines remain synthetic.", "Monitoring") : Ui.Table(Snapshot.Scans.OrderByDescending(s => s.StartedAt).Select(s => new { s.EngineId, s.ScopeSummary, s.Status, Started = s.StartedAt.LocalDateTime.ToString("g"), s.EventId }), ("Engine", "EngineId", 140), ("Authorized scope", "ScopeSummary", 0), ("Status", "Status", 100), ("Started", "Started", 160), ("Event ID", "EventId", 150)))));
        var search = Ui.Search("Search security changes", 320);
        var kind = Ui.Select(new[] { "All event types" }.Concat(Snapshot.Changes.Select(c => c.Kind).Distinct()), "All event types");
        var events = new StackPanel();
        void Filter()
        {
            events.Children.Clear();
            events.Children.Add(Timeline(Snapshot.Changes.Where(c => (kind.SelectedItem?.ToString() == "All event types" || c.Kind == kind.SelectedItem?.ToString()) && $"{c.Kind} {c.Summary} {c.Source}".Contains(search.Text, StringComparison.OrdinalIgnoreCase))));
        }
        search.TextChanged += (_, _) => Filter(); kind.SelectionChanged += (_, _) => Filter(); Filter();
        PageContent.Children.Add(Ui.Section("Security timeline", "Timestamp, provenance and supporting records for each retained event."));
        PageContent.Children.Add(Ui.Toolbar(search, kind)); PageContent.Children.Add(events);
    }

    private UIElement Timeline(IEnumerable<ChangeEvent> changes)
    {
        var all = changes.OrderByDescending(c => c.At).ToList();
        if (all.Count == 0) return Ui.Empty("No matching changes", "The current retained timeline contains no matching events.", "Monitoring");
        var panel = new StackPanel();
        foreach (var change in all.Take(150)) panel.Children.Add(Ui.Card(ChangeSummary(change), 16));
        if (all.Count > 150) panel.Children.Add(Ui.Text($"Showing latest 150 of {all.Count} matching changes. Filter to narrow the timeline.", 12, "MutedBrush"));
        return panel;
    }

    private UIElement ChangeSummary(ChangeEvent change)
    {
        var finding = Snapshot.Findings.FirstOrDefault(f => f.Id == change.EntityId || f.EvidenceIds.Contains(change.EntityId));
        var asset = Snapshot.Assets.FirstOrDefault(a => a.Id == change.EntityId || finding?.AssetIds.Contains(a.Id) == true);
        var panel = Ui.Stack(Ui.Toolbar(Ui.Badge(change.Kind, finding is null ? "InfoBrush" : SeverityBrush(finding.Severity)), Ui.Text(change.At.LocalDateTime.ToString("g"), 12, "MutedBrush")), Ui.Text(change.Summary, 15, bold: true), Ui.Text($"Source: {change.Source}" + (asset is null ? "" : $" · Asset: {asset.Name}"), 12, "MutedBrush"));
        if (finding is not null) panel.Children.Add(Ui.Button("Review finding evidence", () => OpenFinding(finding.Id)));
        else if (Snapshot.Nodes.Any(n => n.Id == change.EntityId)) panel.Children.Add(Ui.Button("Inspect evidence", () => OpenEvidence(change.EntityId)));
        else if (asset is not null) panel.Children.Add(Ui.Button("Open asset", () => OpenAsset(asset.Id)));
        return panel;
    }
}
