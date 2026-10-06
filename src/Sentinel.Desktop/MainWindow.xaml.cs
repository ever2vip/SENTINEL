using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Infrastructure;

namespace Sentinel.Desktop;

public partial class MainWindow : Window
{
    private static readonly string[] Routes = ["Command Center", "Assets", "Network", "Endpoints", "Vulnerabilities", "Identity", "Active Directory", "Cloud", "Web Security", "Attack Surface", "Attack Paths", "Evidence Graph", "Compliance", "Monitoring", "Incidents", "Remediation", "Reports", "AI Analyst", "Integrations", "Settings"];
    private readonly string _dataDirectory;
    private readonly SQLiteEnvironmentRepository _repository;
    private readonly ApplicationCoordinator _coordinator;
    private AppSettings _settings = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _initialized;
    private bool _busy;
    private string _route = "Command Center";
    private EnvironmentSnapshot Snapshot => _coordinator.Current ?? throw new InvalidOperationException("Choose an environment before using this page.");

    public MainWindow()
    {
        InitializeComponent();
        _dataDirectory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");
        Directory.CreateDirectory(_dataDirectory);
        _repository = new SQLiteEnvironmentRepository(System.IO.Path.Combine(_dataDirectory, "sentinel.db"));
        _coordinator = new ApplicationCoordinator(_repository, [new NetworkPostureEngine(), new LocalEndpointEngine(), new WebPostureEngine(), new EmailPostureEngine()]);
        foreach (var route in Routes)
        {
            var icon = new System.Windows.Shapes.Path { Data = Geometry.Parse(IconFor(route)), Width = 16, Height = 16, Stretch = Stretch.Uniform, StrokeThickness = 1.4, Margin = new Thickness(0, 0, 12, 0) };
            icon.SetResourceReference(Shape.StrokeProperty, "MutedBrush");
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(icon);
            row.Children.Add(new TextBlock { Text = route, FontSize = 13 });
            Navigation.Items.Add(new ListBoxItem { Content = row, Tag = route });
        }
        Loaded += async (_, _) => await InitializeAsync();
        Closing += Window_Closing;
    }

    private async Task InitializeAsync()
    {
        await GuardAsync(async () =>
        {
            await _coordinator.InitializeAsync();
            _settings = await _coordinator.GetSettingsAsync();
            ThemeManager.Apply(_settings.Theme);
            _initialized = true;
            if (_settings.LastEnvironment is EnvironmentMode mode) await OpenEnvironmentAsync(mode);
            else ShowEnvironmentChoice();
        });
    }

    private async Task OpenEnvironmentAsync(EnvironmentMode mode)
    {
        await _coordinator.OpenAsync(mode);
        _settings.LastEnvironment = mode;
        await _coordinator.SaveSettingsAsync(_settings);
        OrganizationText.Text = Snapshot.Name;
        ModeText.Text = mode == EnvironmentMode.Demo ? "DEMO · Synthetic, offline evidence" : "LIVE · Operator authorized scope";
        StatusText.Text = mode == EnvironmentMode.Demo ? "Offline demo · Actual risk calculations from synthetic evidence · No network traffic" : "Live workspace · No scans run until scope is explicitly authorized";
        ScanButton.Content = mode == EnvironmentMode.Demo ? "Assessment info" : "New assessment";
        Navigate("Command Center");
    }

    private void ShowEnvironmentChoice()
    {
        PageTitle.Text = "Welcome to SENTINEL";
        PageSubtitle.Text = "Evidence, context, and a clear order of action.";
        PageContent.Children.Clear();
        var intro = Ui.Stack(Ui.Text("Know what matters. Defend what matters.", 32, bold: true), Ui.Text("SENTINEL connects your assets, identities, findings, and permissions to explain business risk and prioritize the next defensible action.", 16, "MutedBrush"), Ui.Text("Select your workspace. Each environment has separate local evidence.", 14, "MutedBrush"));
        PageContent.Children.Add(Ui.Card(intro, 32));
        var demo = Ui.Stack(Ui.Text("DEMO ORGANIZATION", 12, "AccentBrush", true), Ui.Text("Explore the full product offline", 24, bold: true), Ui.Text("A realistic synthetic organization with 250 endpoints, servers, identities, cloud resources, vulnerabilities, and defensive attack paths. The demo uses the same storage, graph, reporting, and risk engines as live assessments.", 15, "MutedBrush"), Ui.Button("Open Demo Organization", () => _ = GuardAsync(() => OpenEnvironmentAsync(EnvironmentMode.Demo)), true));
        var live = Ui.Stack(Ui.Text("LIVE ENVIRONMENT", 12, "AccentBrush", true), Ui.Text("Assess an authorized environment", 24, bold: true), Ui.Text("Begin with an empty inventory and collect evidence from targets you own or have written authorization to assess. Assessments show exact scope, require operator confirmation, and support safe cancellation.", 15, "MutedBrush"), Ui.Button("Open Live Environment", () => _ = GuardAsync(() => OpenEnvironmentAsync(EnvironmentMode.Live)), true));
        PageContent.Children.Add(Ui.Columns(Ui.Card(demo, 28), Ui.Card(live, 28)));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Your data stays local", 18, bold: true), Ui.Text("Standalone operation uses SQLite. No cloud account or AI provider is required. Connector credentials use Windows protected storage; ordinary use does not require administrative privileges.", brush: "MutedBrush"))));
        StatusText.Text = "First launch · Choose Demo Organization or Live Environment";
    }

    private void Navigate(string route)
    {
        _route = route;
        var index = Array.IndexOf(Routes, route);
        if (Navigation.SelectedIndex != index) Navigation.SelectedIndex = index;
        else RenderPage();
    }

    private void Navigation_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_initialized || _coordinator.Current is null) return;
        if (Navigation.SelectedItem is ListBoxItem item) { _route = (string)item.Tag; RenderPage(); }
    }

    private void RenderPage()
    {
        if (_coordinator.Current is null) { ShowEnvironmentChoice(); return; }
        PageContent.Children.Clear();
        PageScroll.ScrollToTop();
        PageTitle.Text = _route;
        PageSubtitle.Text = Subtitle(_route);
        if (Snapshot.Mode == EnvironmentMode.Demo) PageContent.Children.Add(Ui.Text("DEMO ORGANIZATION  ·  All observations are synthetic. Risk, paths, and reports are calculated from the evidence below.", 11, "MutedBrush"));
        switch (_route)
        {
            case "Command Center": RenderCommandCenter(); break;
            case "Assets": RenderAssets(Snapshot.Assets); break;
            case "Network": RenderNetwork(); break;
            case "Endpoints": RenderEndpoints(); break;
            case "Vulnerabilities": RenderFindings(Snapshot.Findings.Where(f => f.Category == SecurityCategory.Vulnerability)); break;
            case "Identity": RenderIdentities(Snapshot.Identities); break;
            case "Active Directory": RenderActiveDirectory(); break;
            case "Cloud": RenderCloud(); break;
            case "Web Security": RenderWeb(); break;
            case "Attack Surface": RenderAttackSurface(); break;
            case "Attack Paths": RenderAttackPaths(); break;
            case "Evidence Graph": RenderGraph(); break;
            case "Compliance": RenderCompliance(); break;
            case "Monitoring": RenderMonitoring(); break;
            case "Incidents": RenderIncidents(); break;
            case "Remediation": RenderRemediation(); break;
            case "Reports": RenderReports(); break;
            case "AI Analyst": RenderAnalyst(); break;
            case "Integrations": RenderIntegrations(); break;
            case "Settings": RenderSettings(); break;
        }
    }

    private void RenderCommandCenter()
    {
        var risk = _coordinator.Risk;
        var open = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open).ToList();
        var hasAssessedEvidence = risk.CategoryScores.Count > 0;
        var score = hasAssessedEvidence ? $"{risk.GlobalScore:0}" : "—";
        PageContent.Children.Add(Ui.Columns(Ui.Metric("GLOBAL SECURITY SCORE", score, hasAssessedEvidence ? "0–100 · higher is stronger" : "Not assessed · no posture evidence", "AccentBrush"), Ui.Metric("OPEN CRITICAL FINDINGS", open.Count(f => f.Severity == Severity.Critical).ToString(), "Contextual priority, not CVSS alone", "CriticalBrush"), Ui.Metric("ASSETS IN SCOPE", Snapshot.Assets.Count.ToString(), $"{Snapshot.Assets.Count(a => a.IsCritical)} business critical assets"), Ui.Metric("DEFENSIVE ATTACK PATHS", _coordinator.AttackPaths.Count.ToString(), "Known evidence · paths are never executed", "HighBrush")));
        PageContent.Children.Add(Ui.Text("Scores reflect assessed evidence; coverage may be incomplete. An inventory record alone does not establish security posture.", 12, "MutedBrush"));
        if (Snapshot.Assets.Count == 0) AddEmpty("Your live environment has not been assessed", "Run an explicitly scoped assessment or import authorized evidence to begin. A score of 100 would suggest certainty where no evidence exists.");
        var counts = Ui.Stack(Ui.Text("Finding distribution", 19, bold: true));
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            var count = open.Count(f => f.Severity == severity);
            counts.Children.Add(Ui.Row(Ui.Text(severity.ToString(), 14, SeverityBrush(severity)), Ui.Text($"{count} open", 14, bold: true)));
        }
        counts.Children.Add(Ui.Button("Review all findings", () => { _route = "Vulnerabilities"; PageTitle.Text = "All Findings"; PageContent.Children.Clear(); RenderFindings(Snapshot.Findings); }));
        PageContent.Children.Add(Ui.Columns(Ui.Card(counts), Ui.Card(BuildTrend())));
        var actions = _coordinator.Remediations.Take(3).ToList();
        var modeled = risk.TotalRisk > 0 ? actions.Sum(a => a.ModeledRiskReduction) / risk.TotalRisk * 100 : 0;
        var actionSection = Ui.Stack(Ui.Text("What to fix first", 21, bold: true), Ui.Text($"The first {actions.Count} actions target approximately {Math.Min(100, modeled):0}% of currently modeled risk. Estimates depend on collected evidence and assume successful verification.", brush: "MutedBrush"));
        foreach (var action in actions) actionSection.Children.Add(ActionSummary(action));
        actionSection.Children.Add(Ui.Button("Open remediation plan", () => Navigate("Remediation")));
        PageContent.Children.Add(Ui.Card(actionSection));
        var categories = Ui.Stack(Ui.Text("Posture by category", 19, bold: true));
        foreach (var category in Enum.GetValues<SecurityCategory>())
        {
            var assessed = risk.CategoryScores.TryGetValue(category, out var categoryScore);
            categories.Children.Add(Ui.Row(Ui.Text(category.ToString(), 14), Ui.Text(assessed ? $"{categoryScore:0}/100" : "Not assessed", 14, assessed ? "AccentBrush" : "MutedBrush")));
        }
        var recent = Ui.Stack(Ui.Text("Recent changes", 19, bold: true));
        foreach (var change in Snapshot.Changes.OrderByDescending(c => c.At).Take(5)) recent.Children.Add(Ui.Stack(Ui.Text(change.Summary, 14, bold: true), Ui.Text($"{change.At.LocalDateTime:g} · {change.Source}", 11, "MutedBrush")));
        if (Snapshot.Changes.Count == 0) recent.Children.Add(Ui.Text("No recorded changes yet.", brush: "MutedBrush"));
        recent.Children.Add(Ui.Button("Open timeline", () => Navigate("Monitoring")));
        PageContent.Children.Add(Ui.Columns(Ui.Card(categories), Ui.Card(recent)));
        var controls = _coordinator.Compliance;
        var failures = controls.Count(c => c.Status.Contains("Fail", StringComparison.OrdinalIgnoreCase) || c.Status.Contains("Gap", StringComparison.OrdinalIgnoreCase));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Compliance evidence", 19, bold: true), Ui.Text($"{controls.Count} mapped controls · {failures} with recorded gaps. Mapping supports NIST CSF 2.0 and CIS Controls; assessment evidence does not establish certification.", brush: "MutedBrush"), Ui.Button("Review control mappings", () => Navigate("Compliance")))));
    }

    private StackPanel BuildTrend()
    {
        var panel = Ui.Stack(Ui.Text("Security score trend", 19, bold: true));
        var history = Snapshot.ScoreHistory.OrderBy(s => s.At).TakeLast(16).ToList();
        if (history.Count == 0) { panel.Children.Add(Ui.Text("Trend begins after the first completed assessment.", brush: "MutedBrush")); return panel; }
        var canvas = new Canvas { Height = 155, ClipToBounds = true, Margin = new Thickness(0, 10, 0, 10) };
        canvas.SizeChanged += (_, _) =>
        {
            canvas.Children.Clear();
            var width = Math.Max(20, canvas.ActualWidth - 20);
            foreach (var tick in new[] { 25, 50, 75, 100 }) canvas.Children.Add(new Line { X1 = 0, X2 = width, Y1 = 145 - tick * 1.3, Y2 = 145 - tick * 1.3, Stroke = Ui.Brush("BorderBrush"), StrokeThickness = 1 });
            var points = new PointCollection(history.Select((s, i) => new Point(10 + (history.Count == 1 ? width / 2 : i * (width - 20) / (history.Count - 1)), 145 - Math.Clamp(s.Score, 0, 100) * 1.3)));
            canvas.Children.Add(new Polyline { Points = points, Stroke = Ui.Brush("AccentBrush"), StrokeThickness = 3, StrokeLineJoin = PenLineJoin.Round });
            foreach (var point in points) { var dot = new Ellipse { Width = 7, Height = 7, Fill = Ui.Brush("AccentBrush") }; Canvas.SetLeft(dot, point.X - 3); Canvas.SetTop(dot, point.Y - 3); canvas.Children.Add(dot); }
        };
        panel.Children.Add(canvas);
        panel.Children.Add(Ui.Text($"{history[0].At.LocalDateTime:d} → {history[^1].At.LocalDateTime:d} · {history[^1].Score - history[0].Score:+0.0;-0.0;0} points", 12, "MutedBrush"));
        return panel;
    }

    private void RenderAssets(IEnumerable<Asset> assets)
    {
        var list = assets.ToList();
        var search = Ui.Input(width: 340);
        search.ToolTip = "Filter by name, address, OS, owner, or environment";
        var kind = Ui.Select(new[] { "All asset types" }.Concat(Enum.GetNames<AssetKind>()), "All asset types");
        var summary = Ui.Text($"{list.Count} assets · select a row for evidence and history", brush: "MutedBrush");
        var grid = Ui.Table(list, ("Asset", "Name", 0), ("Type", "Kind", 125), ("Address", "Address", 155), ("Operating system", "OperatingSystem", 175), ("Owner", "Owner", 145), ("Criticality", "BusinessCriticality", 100));
        var details = new StackPanel();
        void Filter() { var text = search.Text.Trim(); var selected = kind.SelectedItem?.ToString(); var filtered = list.Where(a => (selected == "All asset types" || a.Kind.ToString() == selected) && $"{a.Name} {a.Address} {a.OperatingSystem} {a.Owner} {a.Environment}".Contains(text, StringComparison.OrdinalIgnoreCase)).ToList(); grid.ItemsSource = filtered; summary.Text = $"{filtered.Count} of {list.Count} assets · select a row for evidence and history"; }
        search.TextChanged += (_, _) => Filter(); kind.SelectionChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) =>
        {
            details.Children.Clear();
            if (grid.SelectedItem is not Asset asset) return;
            var evidence = Snapshot.Observations.Where(o => o.AssetId == asset.Id).OrderByDescending(o => o.ObservedAt).ToList();
            var body = Ui.Stack(Ui.Text(asset.Name, 22, bold: true), Ui.Text($"{asset.Environment} · Business criticality {asset.BusinessCriticality}/5 · Exposure {asset.Exposure:P0}", brush: "MutedBrush"), Ui.Text($"First seen {asset.FirstSeen.LocalDateTime:g} · Last observed {asset.LastSeen.LocalDateTime:g}", 12, "MutedBrush"));
            foreach (var property in asset.Properties.Take(20)) body.Children.Add(Ui.Text($"{property.Key}: {property.Value}", 13));
            body.Children.Add(Ui.Text("Observed posture", 17, bold: true));
            if (evidence.Count == 0) body.Children.Add(Ui.Text("No engine observations were collected for this asset.", brush: "MutedBrush"));
            else body.Children.Add(Ui.Table(evidence, ("Property", "Property", 180), ("Observed value", "Value", 0), ("Source", "Source", 150), ("Observed", "ObservedAt", 170)));
            body.Children.Add(Ui.Button("View findings for this asset", () => { PageContent.Children.Clear(); RenderFindings(Snapshot.Findings.Where(f => f.AssetIds.Contains(asset.Id))); }));
            var owner = Ui.Input(asset.Owner, 250);
            var criticality = Ui.Select(Enumerable.Range(1, 5), asset.BusinessCriticality);
            var contextReason = Ui.Input(); contextReason.ToolTip = "Record the business-context change reason";
            var retired = new CheckBox { Content = "Mark as operator-retired (existing risk evidence remains)", IsChecked = asset.Properties.GetValueOrDefault("lifecycle") == "Operator retired" };
            body.Children.Add(Ui.Text("Edit business context", 17, bold: true));
            body.Children.Add(Ui.Row(Ui.Text("Owner", 13), owner, Ui.Text("Criticality 1–5", 13), criticality));
            body.Children.Add(contextReason); body.Children.Add(retired);
            body.Children.Add(Ui.Button("Save business context", () => _ = GuardAsync(async () =>
            {
                await _coordinator.UpdateAssetAsync(asset.Id, owner.Text, (int)criticality.SelectedItem, contextReason.Text, retired.IsChecked == true);
                RenderPage(); ShowNotice("Asset business context saved", "The change was audited and contextual risk recalculated. Retirement does not remove unresolved security evidence.");
            }), true));
            details.Children.Add(Ui.Card(body));
        };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Row(search, kind), summary, grid)));
        PageContent.Children.Add(details);
        if (list.Count == 0) AddEmpty("No assets collected", "Run a supported authorized assessment or import evidence. Inventory never implies successful posture assessment.");
    }

    private void RenderFindings(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        var search = Ui.Input(width: 330);
        search.ToolTip = "Filter title, CVE, software, source, or description";
        var severity = Ui.Select(new[] { "All severities" }.Concat(Enum.GetNames<Severity>()), "All severities");
        var status = Ui.Select(new[] { "All states" }.Concat(Enum.GetNames<FindingStatus>()), "All states");
        var riskLookup = _coordinator.Risk.RankedFindings.ToDictionary(f => f.Finding.Id, f => f);
        var rows = list.Select(f => new FindingRow(f, riskLookup.GetValueOrDefault(f.Id)?.Risk ?? 0)).OrderByDescending(f => f.Risk).ToList();
        var grid = Ui.Table(rows, ("Finding", "Title", 0), ("Severity", "Severity", 100), ("Contextual risk", "RiskDisplay", 115), ("CVE", "Cve", 145), ("Assets", "AssetCount", 85), ("State", "Status", 125), ("Confidence", "Confidence", 100));
        var count = Ui.Text($"{list.Count} findings · select a row for evidence, remediation, and disposition", brush: "MutedBrush");
        var details = new StackPanel();
        void Filter() { var filtered = rows.Where(r => (severity.SelectedItem?.ToString() == "All severities" || r.Finding.Severity.ToString() == severity.SelectedItem?.ToString()) && (status.SelectedItem?.ToString() == "All states" || r.Finding.Status.ToString() == status.SelectedItem?.ToString()) && $"{r.Finding.Title} {r.Finding.Description} {r.Finding.Cve} {r.Finding.Software} {r.Finding.Source}".Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase)).ToList(); grid.ItemsSource = filtered; count.Text = $"{filtered.Count} of {list.Count} findings · select a row to inspect or disposition"; }
        search.TextChanged += (_, _) => Filter(); severity.SelectionChanged += (_, _) => Filter(); status.SelectionChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) => { details.Children.Clear(); if (grid.SelectedItem is FindingRow row) details.Children.Add(FindingDetail(row.Finding)); };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Row(search, severity, status), count, grid)));
        PageContent.Children.Add(details);
        if (list.Count == 0) AddEmpty("No findings in this view", Snapshot.Assets.Count == 0 ? "This category is unassessed until evidence is collected." : "No matching findings are recorded. Coverage and scope determine what this conclusion means.");
    }

    private Border FindingDetail(Finding finding)
    {
        var scored = _coordinator.Risk.RankedFindings.FirstOrDefault(s => s.Finding.Id == finding.Id);
        var body = Ui.Stack(Ui.Text(finding.Title, 22, SeverityBrush(finding.Severity), true), Ui.Text(finding.Description, 15), Ui.Text($"{finding.Category} · {finding.Severity} · CVSS {finding.Cvss:0.0} · Contextual risk {scored?.Risk ?? 0:0.0} · Confidence {finding.Confidence:P0}", 13, "MutedBrush"), Ui.Text($"Source: {finding.Source} · First seen {finding.FirstSeen.LocalDateTime:g} · Last seen {finding.LastSeen.LocalDateTime:g}", 12, "MutedBrush"));
        if (scored is not null) body.Children.Add(Ui.Text("Why this matters: " + string.Join(" · ", scored.Reasons), brush: "MutedBrush"));
        body.Children.Add(Ui.Text("Affected assets", 16, bold: true));
        body.Children.Add(Ui.Text(string.Join(", ", Snapshot.Assets.Where(a => finding.AssetIds.Contains(a.Id)).Select(a => a.Name))));
        body.Children.Add(Ui.Text("Remediation", 16, bold: true)); body.Children.Add(Ui.Text(finding.Remediation));
        body.Children.Add(Ui.Text("Verify the fix", 16, bold: true)); body.Children.Add(Ui.Text(finding.Verification));
        body.Children.Add(Ui.Text("Evidence IDs: " + (finding.EvidenceIds.Count == 0 ? "No graph evidence references; see source and observations." : string.Join(", ", finding.EvidenceIds)), 12, "MutedBrush"));
        if (finding.References.Count > 0) body.Children.Add(Ui.Text("References: " + string.Join("\n", finding.References), 12, "MutedBrush"));
        body.Children.Add(Ui.Text("Finding disposition", 16, bold: true));
        var state = Ui.Select(Enum.GetValues<FindingStatus>(), finding.Status);
        var reason = Ui.Input(finding.DispositionReason); reason.ToolTip = "Required reason for risk acceptance, false positive, or fixed disposition";
        var expiry = new DatePicker { SelectedDate = finding.AcceptedUntil?.LocalDateTime.Date ?? DateTime.Today.AddDays(30), Margin = new Thickness(0, 0, 8, 8), Width = 160 };
        var save = Ui.Button("Save disposition", () => _ = GuardAsync(async () =>
        {
            var selected = (FindingStatus)state.SelectedItem;
            if (selected != FindingStatus.Open && string.IsNullOrWhiteSpace(reason.Text)) throw new ArgumentException("Record a reason before changing the finding disposition.");
            if (selected == FindingStatus.AcceptedRisk && (expiry.SelectedDate is null || expiry.SelectedDate.Value.Date <= DateTime.Today)) throw new ArgumentException("Accepted risk requires a future review date.");
            await _coordinator.UpdateFindingAsync(finding.Id, selected, reason.Text.Trim(), selected == FindingStatus.AcceptedRisk ? new DateTimeOffset(expiry.SelectedDate!.Value.Date.AddHours(23)) : null);
            RenderPage(); ShowNotice("Finding disposition saved", "The audit trail and contextual risk calculations have been updated.");
        }), true);
        body.Children.Add(Ui.Row(state, Ui.Text("Risk review by", 12, "MutedBrush"), expiry, save));
        body.Children.Add(reason);
        body.Children.Add(Ui.Text("A fixed disposition is an operator assertion; verify using the instructions above and reassess the affected scope. Accepted risk remains visible and is reviewed on its expiry date.", 12, "MutedBrush"));
        return Ui.Card(body);
    }

    private void RenderNetwork()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Network posture", 21, bold: true), Ui.Text("Exact authorized targets are checked for observable TCP services. Open services do not establish vulnerability or permission to access them. No exploitation is performed.", brush: "MutedBrush"), Ui.Row(Ui.Button("View topology", () => Navigate("Evidence Graph")), Ui.Button("Assess authorized targets", ScanButton_Click)) )));
        RenderAssets(Snapshot.Assets.Where(a => a.Kind is AssetKind.NetworkDevice or AssetKind.Server || a.Properties.ContainsKey("OpenPorts")));
        AddCategoryFindings(SecurityCategory.Network);
    }

    private void RenderEndpoints()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Endpoint assessment coverage", 20, bold: true), Ui.Text("Local Windows posture uses observable OS, firewall, encryption, update, and endpoint protection evidence where available. Access-denied or unavailable observations remain unknown. Remote endpoint evidence requires an authorized connector or import.", brush: "MutedBrush"))));
        RenderAssets(Snapshot.Assets.Where(a => a.Kind is AssetKind.Endpoint or AssetKind.Server));
        AddCategoryFindings(SecurityCategory.Endpoint);
    }

    private void RenderIdentities(IEnumerable<Identity> identities)
    {
        var list = identities.ToList();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("IDENTITIES", list.Count.ToString(), "Recorded from authorized source evidence"), Ui.Metric("PRIVILEGED", list.Count(i => i.IsPrivileged).ToString(), "Review reach and permissions", "HighBrush"), Ui.Metric("MFA NOT OBSERVED", list.Count(i => i.MfaEnabled is null).ToString(), "Unknown is not compliant")));
        var search = Ui.Input(width: 350); search.ToolTip = "Filter identity, principal name, or provider";
        var rows = list.Select(i => new IdentityRow(i)).ToList();
        var grid = Ui.Table(rows, ("Identity", "DisplayName", 0), ("Principal", "PrincipalName", 240), ("Provider", "Provider", 145), ("Privileged", "Privileged", 105), ("MFA", "Mfa", 110), ("Last sign in", "LastSignIn", 160));
        search.TextChanged += (_, _) => grid.ItemsSource = rows.Where(i => $"{i.DisplayName} {i.PrincipalName} {i.Provider}".Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToList();
        var detail = new StackPanel();
        grid.SelectionChanged += (_, _) => { detail.Children.Clear(); if (grid.SelectedItem is IdentityRow row) detail.Children.Add(Ui.Card(Ui.Stack(Ui.Text(row.DisplayName, 20, bold: true), Ui.Text("Groups: " + string.Join(", ", row.Identity.Groups)), Ui.Text("Permissions: " + string.Join(", ", row.Identity.Permissions)), Ui.Text("Dormancy requires sign-in evidence. MFA unknown must be verified with the identity provider.", brush: "MutedBrush"), Ui.Button("Explore relationships", () => Navigate("Evidence Graph"))))); };
        PageContent.Children.Add(Ui.Card(Ui.Stack(search, grid))); PageContent.Children.Add(detail);
        if (list.Count == 0) AddEmpty("Identity posture is unassessed", "No identity records have been collected. Microsoft Entra and Active Directory connectors require separate least-privilege access; offline imports do not create active API connections.");
    }

    private void RenderActiveDirectory()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Active Directory defensive evidence", 20, bold: true), Ui.Text("Group membership and permission relationships support privilege and dormant-account review. SENTINEL does not collect passwords, dump credentials, or execute domain attack paths. Live LDAP collection is available only through a configured authorized connector.", brush: "MutedBrush"))));
        RenderIdentities(Snapshot.Identities.Where(i => i.Provider.Contains("Directory", StringComparison.OrdinalIgnoreCase) || i.Provider.Equals("AD", StringComparison.OrdinalIgnoreCase)));
        AddCategoryFindings(SecurityCategory.Identity);
    }

    private void RenderCloud()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Cloud posture from authorized evidence", 20, bold: true), Ui.Text("Azure, Microsoft 365, AWS, and Google Cloud integrations expose inventory and configuration through official APIs. This release provides connector contracts and evidence imports; a provider is never shown as connected without an implemented authenticated connector.", brush: "MutedBrush"), Ui.Button("Review integration availability", () => Navigate("Integrations")))));
        RenderAssets(Snapshot.Assets.Where(a => a.Kind == AssetKind.CloudResource)); AddCategoryFindings(SecurityCategory.Cloud);
    }

    private void RenderWeb()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Non-destructive web and email posture", 20, bold: true), Ui.Text("Authorized HTTPS properties are assessed for transport, certificate, response-header, and cookie posture. Email checks inspect SPF, DMARC, and configured DKIM selectors. These checks do not crawl, authenticate, or exploit web applications.", brush: "MutedBrush"))));
        RenderAssets(Snapshot.Assets.Where(a => a.Kind == AssetKind.WebApplication));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Certificates", 18, bold: true), Ui.Table(Snapshot.Certificates.Select(c => new { c.Subject, c.Issuer, Expires = c.NotAfter.LocalDateTime.ToString("g"), Days = (int)(c.NotAfter - DateTimeOffset.UtcNow).TotalDays, c.AssetId }), ("Subject", "Subject", 0), ("Issuer", "Issuer", 200), ("Expires", "Expires", 180), ("Days remaining", "Days", 120)))));
        AddCategoryFindings(SecurityCategory.Web, SecurityCategory.Email);
    }

    private void RenderAttackSurface()
    {
        var exposed = Snapshot.Assets.Where(a => a.Exposure > 0).ToList();
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Observed exposure", 21, bold: true), Ui.Text($"{exposed.Count} assets have recorded exposure. Exposure is evidence-based and may be partial; it is not a complete internet discovery claim.", brush: "MutedBrush"), Ui.Text($"{Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Service)} service nodes · {Snapshot.Nodes.Count(n => n.Kind == EvidenceKind.Domain)} domains · {Snapshot.Certificates.Count} certificates", 14))));
        RenderAssets(exposed);
    }

    private void RenderAttackPaths()
    {
        var paths = _coordinator.AttackPaths;
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Known evidence. Defensive action.", 22, bold: true), Ui.Text("Paths connect recorded exposure, configuration, and permissions to business critical resources. Confidence reflects evidence quality. SENTINEL never executes a path; relationships alone do not prove exploit success.", brush: "MutedBrush"))));
        if (paths.Count == 0) { AddEmpty("No supported paths are currently modeled", "This means no complete evidence chain meets the path rules. It does not establish the absence of attack paths."); return; }
        foreach (var path in paths.OrderByDescending(p => p.Risk))
        {
            var labels = path.NodeIds.Select(id => Snapshot.Nodes.FirstOrDefault(n => n.Id == id)?.Label ?? id);
            var panel = Ui.Stack(Ui.Text(path.Title, 20, bold: true), Ui.Text(string.Join("  →  ", labels), 15), Ui.Text($"Contextual path risk {path.Risk:0.0} · Confidence {path.Confidence:P0} · Critical resource {Snapshot.Assets.FirstOrDefault(a => a.Id == path.CriticalAssetId)?.Name ?? path.CriticalAssetId}", 13, "HighBrush"));
            var detail = Ui.Stack(Ui.Text("Recommended break point", 16, bold: true), Ui.Text(path.BreakPoint), Ui.Text(path.RecommendedAction), Ui.Text("Evidence: " + string.Join(", ", path.EdgeIds), 12, "MutedBrush"), Ui.Text("After remediation, collect the same evidence again and confirm that the enabling relationship is removed. Estimated risk reduction is not proof of prevention.", 12, "MutedBrush"));
            detail.Visibility = Visibility.Collapsed;
            panel.Children.Add(Ui.Row(Ui.Button("BREAK THIS PATH", () => detail.Visibility = detail.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible, true), Ui.Button("View evidence graph", () => Navigate("Evidence Graph"))));
            panel.Children.Add(detail);
            PageContent.Children.Add(Ui.Card(panel));
        }
    }

    private void RenderGraph()
    {
        PageContent.Children.Add(new EvidenceGraphView(Snapshot));
    }

    private void RenderCompliance()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Control evidence, not a certification claim", 21, bold: true), Ui.Text("NIST CSF 2.0 and CIS Controls mappings connect findings to defensive outcomes. Unobserved controls stay unassessed; a finding may affect multiple controls. Framework additions use the compliance architecture.", brush: "MutedBrush"))));
        var frameworks = Ui.Select(new[] { "All frameworks" }.Concat(_coordinator.Compliance.Select(c => c.Control.Framework).Distinct()), "All frameworks");
        var rows = _coordinator.Compliance.Select(c => new { c.Control.Id, c.Control.Framework, c.Control.Title, c.Status, Findings = c.FindingIds.Count }).ToList();
        var grid = Ui.Table(rows, ("Control", "Id", 150), ("Framework", "Framework", 155), ("Outcome", "Title", 0), ("Evidence state", "Status", 180), ("Findings", "Findings", 90));
        frameworks.SelectionChanged += (_, _) => grid.ItemsSource = rows.Where(c => frameworks.SelectedItem?.ToString() == "All frameworks" || c.Framework == frameworks.SelectedItem?.ToString()).ToList();
        PageContent.Children.Add(Ui.Card(Ui.Stack(frameworks, grid)));
    }

    private void RenderMonitoring()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Continuous monitoring history", 21, bold: true), Ui.Text("Assessment runs record evidence and detect observed changes. This release does not silently schedule scans. Missing assets are interpreted only within comparable completed scan scope.", brush: "MutedBrush"), Ui.Table(Snapshot.Scans.OrderByDescending(s => s.StartedAt).Select(s => new { s.EngineId, s.ScopeSummary, s.Status, Started = s.StartedAt.LocalDateTime.ToString("g"), s.Message, s.EventId }), ("Engine", "EngineId", 150), ("Authorized scope", "ScopeSummary", 0), ("Status", "Status", 100), ("Started", "Started", 170), ("Event ID", "EventId", 170)))));
        var filter = Ui.Input(width: 350); filter.ToolTip = "Filter change timeline";
        var timeline = new StackPanel();
        void RenderEvents()
        {
            timeline.Children.Clear();
            foreach (var change in Snapshot.Changes.OrderByDescending(c => c.At).Where(c => $"{c.Kind} {c.Summary} {c.Source}".Contains(filter.Text, StringComparison.OrdinalIgnoreCase)).Take(150)) timeline.Children.Add(Ui.Card(Ui.Stack(Ui.Text(change.Summary, 16, bold: true), Ui.Text($"{change.At.LocalDateTime:g} · {change.Kind} · {change.Source} · Evidence {change.EntityId}", 12, "MutedBrush")), 14));
            if (timeline.Children.Count == 0) timeline.Children.Add(Ui.Text("No recorded changes match this view.", brush: "MutedBrush"));
        }
        filter.TextChanged += (_, _) => RenderEvents(); RenderEvents();
        PageContent.Children.Add(Ui.Text("Evidence timeline", 20, bold: true)); PageContent.Children.Add(filter); PageContent.Children.Add(timeline);
    }

    private void RenderIncidents()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Operator-managed investigations", 21, bold: true), Ui.Text("Create an investigation from recorded findings and track its owner, status, and notes. A posture finding alone does not establish a confirmed security incident. These actions update local records and perform no remote containment.", brush: "MutedBrush"))));
        var title = Ui.Input(); title.ToolTip = "Investigation title";
        var owner = Ui.Input(Environment.UserName, 240);
        var candidates = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open).ToList();
        var finding = new ComboBox { ItemsSource = candidates, DisplayMemberPath = "Title", SelectedIndex = candidates.Count > 0 ? 0 : -1, MinWidth = 340 };
        var create = Ui.Button("Create investigation", () => _ = GuardAsync(async () =>
        {
            if (finding.SelectedItem is not Finding selected) throw new ArgumentException("Select a supporting finding.");
            await _coordinator.CreateIncidentAsync(title.Text, owner.Text, [selected.Id]); RenderPage(); ShowNotice("Investigation created", "Owner and supporting evidence were recorded in the audit trail.");
        }), true);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("New investigation", 18, bold: true), title, Ui.Row(owner, finding), create)));
        foreach (var incident in Snapshot.Incidents.OrderByDescending(i => i.UpdatedAt))
        {
            var state = Ui.Select(new[] { "Open", "Investigating", "Contained", "Resolved" }, incident.Status);
            var incidentOwner = Ui.Input(incident.Owner, 240);
            var note = Ui.Input(); note.ToolTip = "Record investigation evidence or a status-change reason";
            var body = Ui.Stack(Ui.Text(incident.Title, 20, bold: true), Ui.Text($"Created {incident.CreatedAt.LocalDateTime:g} · Updated {incident.UpdatedAt.LocalDateTime:g} · {incident.FindingIds.Count} supporting findings", 12, "MutedBrush"), Ui.Text(string.Join("\n", Snapshot.Findings.Where(f => incident.FindingIds.Contains(f.Id)).Select(f => f.Title)), 14), Ui.Row(state, incidentOwner), note);
            body.Children.Add(Ui.Button("Save investigation update", () => _ = GuardAsync(async () =>
            {
                await _coordinator.UpdateIncidentAsync(incident.Id, state.SelectedItem?.ToString() ?? "Open", incidentOwner.Text, note.Text); RenderPage(); ShowNotice("Investigation updated", "The status, owner, and note were recorded. No remote remediation or containment was executed.");
            }), true));
            foreach (var entry in incident.Notes.OrderByDescending(n => n.At).Take(8)) body.Children.Add(Ui.Text($"{entry.At.LocalDateTime:g} · {entry.Summary}", 12, "MutedBrush"));
            PageContent.Children.Add(Ui.Card(body));
        }
        PageContent.Children.Add(Ui.Text("Priority finding triage", 20, bold: true));
        RenderFindings(Snapshot.Findings.Where(f => f.Status == FindingStatus.Open && f.Severity >= Severity.High));
    }

    private void RenderRemediation()
    {
        var risk = _coordinator.Risk.TotalRisk;
        var actions = _coordinator.Remediations;
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Remove causes. Reduce modeled risk.", 22, bold: true), Ui.Text($"{actions.Count} actions group related findings by root cause. Risk reduction is a contextual estimate, capped by current modeled risk; dependent or overlapping fixes must be verified before counting the combined effect.", brush: "MutedBrush"))));
        if (actions.Count == 0) { AddEmpty("No remediation actions available", "Collect or import evidence to establish a defensible priority order."); return; }
        foreach (var action in actions.OrderByDescending(a => a.ModeledRiskReduction))
        {
            var detail = Ui.Stack(Ui.Text("Affected assets", 16, bold: true), Ui.Text(string.Join(", ", Snapshot.Assets.Where(a => action.AssetIds.Contains(a.Id)).Select(a => a.Name))), Ui.Text("Implementation", 16, bold: true), Ui.Text(action.Instructions), Ui.Text("Verification", 16, bold: true), Ui.Text(action.Verification), Ui.Text("Evidence references: " + string.Join(", ", action.EvidenceIds), 12, "MutedBrush"));
            detail.Visibility = Visibility.Collapsed;
            var body = Ui.Stack(Ui.Text(action.Title, 21, bold: true), Ui.Text(action.Why), Ui.Text($"{action.AssetIds.Count} assets · {action.FindingIds.Count} findings · approximately {(risk > 0 ? action.ModeledRiskReduction / risk * 100 : 0):0.0}% modeled risk reduction · confidence {action.Confidence:P0}", 13, "AccentBrush"), Ui.Row(Ui.Button("Show fix and verification", () => detail.Visibility = detail.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible, true), Ui.Button("Review source findings", () => { PageContent.Children.Clear(); RenderFindings(Snapshot.Findings.Where(f => action.FindingIds.Contains(f.Id))); })), detail);
            PageContent.Children.Add(Ui.Card(body));
        }
    }

    private UIElement ActionSummary(RemediationAction action)
    {
        var risk = _coordinator.Risk.TotalRisk;
        return Ui.Stack(Ui.Text(action.Title, 16, bold: true), Ui.Text($"{action.AssetIds.Count} affected assets · approximately {(risk > 0 ? action.ModeledRiskReduction / risk * 100 : 0):0}% modeled risk · {action.Confidence:P0} confidence", 12, "AccentBrush"), Ui.Text(action.Why, 13, "MutedBrush"));
    }

    private void RenderReports()
    {
        var kind = Ui.Select(Enum.GetValues<ReportKind>(), ReportKind.Executive);
        var format = Ui.Select(Enum.GetValues<ReportFormat>(), ReportFormat.Pdf);
        var result = Ui.Text("Reports are generated from the current environment and include provenance, confidence, scope, and limitations.", brush: "MutedBrush");
        var export = Ui.Button("Export report", () => _ = GuardAsync(async () =>
        {
            var selectedFormat = (ReportFormat)format.SelectedItem;
            var extension = selectedFormat.ToString().ToLowerInvariant();
            var dialog = new SaveFileDialog { FileName = $"SENTINEL-{kind.SelectedItem}-{DateTime.Today:yyyy-MM-dd}.{extension}", Filter = $"{selectedFormat} report|*.{extension}", AddExtension = true, DefaultExt = extension, OverwritePrompt = true };
            if (dialog.ShowDialog(this) != true) return;
            var artifact = await _coordinator.ExportReportAsync((ReportKind)kind.SelectedItem, selectedFormat, dialog.FileName);
            result.Text = $"Report saved: {artifact.Path}"; ShowNotice("Report exported", $"{artifact.Kind} · {artifact.Format} · {artifact.CreatedAt.LocalDateTime:g}");
        }), true);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Professional evidence-based reporting", 23, bold: true), Ui.Text("Executive reports translate exposure into business risk. Technical exports preserve findings, assets, control mappings, and remediation context for authorized review.", brush: "MutedBrush"), Ui.Row(kind, format, export), result)));
        foreach (var report in Enum.GetValues<ReportKind>()) PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text(ReportTitle(report), 17, bold: true), Ui.Text(ReportDescription(report), brush: "MutedBrush")), 16));
    }

    private void RenderAnalyst()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("An analyst grounded in your evidence", 22, bold: true), Ui.Text("The offline evidence analyst works without AI or network access. Answers cite collected records and identify inference separately. Optional AI providers implement IAiProvider; no external provider is connected by default.", brush: "MutedBrush"))));
        var question = Ui.Input("What should we fix first?"); question.MinHeight = 48;
        var answer = new StackPanel();
        void Ask(string prompt)
        {
            question.Text = prompt;
            var response = new EvidenceAnalyst().Answer(Snapshot, prompt);
            answer.Children.Clear();
            answer.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Evidence analyst", 19, "AccentBrush", true), Ui.Text(response.Answer, 16), Ui.Text("Evidence references: " + (response.EvidenceIds.Count == 0 ? "No supporting records were found." : string.Join(", ", response.EvidenceIds)), 12, "MutedBrush"), Ui.Text("Inference and limitations", 16, bold: true), Ui.Text(response.Inferences.Count == 0 ? "No additional inference supplied." : string.Join("\n", response.Inferences), 13, "MutedBrush"), Ui.Text(response.UsedAi ? "Configured AI provider was used." : "Offline analysis · no AI provider or external request", 11, "MutedBrush"))));
        }
        var suggestions = new WrapPanel { Margin = new Thickness(0, 8, 0, 16) };
        foreach (var prompt in new[] { "Why did our security score decrease?", "Which assets represent the highest risk?", "Which remediation removes the most modeled risk?", "What changed since the previous assessment?" }) suggestions.Children.Add(Ui.Button(prompt, () => Ask(prompt)));
        PageContent.Children.Add(question); PageContent.Children.Add(Ui.Button("Ask evidence analyst", () => { try { Ask(question.Text); } catch (Exception ex) { ShowFailure(ex); } }, true)); PageContent.Children.Add(suggestions); PageContent.Children.Add(answer);
    }

    private void RenderIntegrations()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Extensible engines and connectors", 22, bold: true), Ui.Text("Assessment engines and provider connectors use versioned typed contracts. Connector implementations must declare required permissions, authenticate through official APIs, and store secrets with Windows protected storage. Imported evidence retains its source.", brush: "MutedBrush"))));
        foreach (var engine in _coordinator.Engines) PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text(engine.Name, 18, bold: true), Ui.Text(engine.Description), Ui.Text(engine.IsAvailable ? "Available · explicit authorization and scope required" : "Unavailable · " + engine.AvailabilityReason, 12, engine.IsAvailable ? "AccentBrush" : "MutedBrush")), 16));
        foreach (var connector in new ConnectorRegistry().Descriptors) PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text(connector.Name, 18, bold: true), Ui.Text(connector.Status, 12, "MutedBrush"), Ui.Text("Least-privilege permissions: " + string.Join("; ", connector.RequiredPermissions), 13), Ui.Text(connector.DocumentationUrl, 12, "MutedBrush")), 16));
        var source = Ui.Select(new[] { "azure", "m365", "aws", "gcp", "ad", "vulnerability-intel" }, "azure");
        var organization = Ui.Input(); organization.ToolTip = "Exact tenant, account, or organization ID from the export";
        var operatorName = Ui.Input(Environment.UserName); operatorName.ToolTip = "Authorizing operator";
        var authorized = new CheckBox { Content = "I am authorized to import and assess this environment's evidence." };
        var import = Ui.Button("Import validated evidence JSON", () => _ = GuardAsync(async () =>
        {
            if (Snapshot.Mode == EnvironmentMode.Demo) throw new InvalidOperationException("Imports are available in Live Environment. Demo evidence remains isolated.");
            if (authorized.IsChecked != true || string.IsNullOrWhiteSpace(organization.Text) || string.IsNullOrWhiteSpace(operatorName.Text)) throw new ArgumentException("Confirm authorization and record the exact organization ID and operator before importing.");
            var dialog = new OpenFileDialog { Filter = "SENTINEL engine evidence|*.json", CheckFileExists = true };
            if (dialog.ShowDialog(this) != true) return;
            await using var stream = File.OpenRead(dialog.FileName);
            var imported = await new ExportedEvidenceImporter().ImportAsync(stream, new EvidenceImportAuthorization { AuthorizationConfirmed = true, AuthorizedBy = operatorName.Text.Trim(), AuthorizedAt = DateTimeOffset.UtcNow, SourceId = source.SelectedItem?.ToString() ?? "", OrganizationId = organization.Text.Trim() });
            await _coordinator.ImportAsync(imported.Result, "import:" + imported.SourceId, imported.Identities); RenderPage(); ShowNotice("Authorized evidence imported", $"Exact organization {imported.OrganizationId} · source {imported.SourceId} · SHA256 {imported.Sha256}. Provenance is operator supplied; no live provider connection was made.");
        }), true);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Authorized offline evidence import", 19, bold: true), Ui.Text("Choose a schema-v1 evidence export. Source and exact organization must match the attested scope; IDs, relationships, timestamps, scoring, and size are validated. Identity records are imported with source provenance.", brush: "MutedBrush"), Ui.Text("Export source", 13, bold: true), source, Ui.Text("Exact organization ID", 13, bold: true), organization, Ui.Text("Authorizing operator", 13, bold: true), operatorName, authorized, import)));
    }

    private void RenderSettings()
    {
        var theme = Ui.Select(new[] { "System", "Dark", "Light" }, _settings.Theme);
        var retention = Ui.Input(_settings.RetentionDays.ToString(), 150);
        var save = Ui.Button("Save preferences", () => _ = GuardAsync(async () =>
        {
            if (!int.TryParse(retention.Text, out var days) || days < 7 || days > 3650) throw new ArgumentException("Retention must be between 7 and 3650 days.");
            _settings.Theme = theme.SelectedItem?.ToString() ?? "System"; _settings.RetentionDays = days;
            await _coordinator.SaveSettingsAsync(_settings); ThemeManager.Apply(_settings.Theme); RenderPage(); ShowNotice("Preferences saved", "Theme and retention are persisted in the local workspace.");
        }), true);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Appearance and data retention", 22, bold: true), Ui.Text("Theme follows Windows when System is selected. Retention trims historical observations, changes, scans, scores, and audit history; current asset and finding evidence is preserved.", brush: "MutedBrush"), Ui.Row(Ui.Text("Appearance", 14), theme, Ui.Text("Retention days", 14), retention, save))));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Local security and privacy", 20, bold: true), Ui.Text("Data location: " + _dataDirectory, 13, "MutedBrush"), Ui.Text("The desktop runs as the current user. Local connector secrets use DPAPI and are not included in reports. Scan authorization is recorded per exact scope. Automatic assessment scheduling is disabled.", 14), Ui.Text(ServiceState(), 12, "MutedBrush"))));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Optional AI provider", 20, bold: true), Ui.Text("No external AI provider is connected. The offline analyst is available in every installation. IAiProvider implementations can add a configured provider with explicit evidence handling; enabling a preference alone does not establish a connection.", brush: "MutedBrush"))));
        var audit = new StackPanel();
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Audit trail", 20, bold: true), audit)));
        _ = GuardAsync(async () =>
        {
            var entries = await _repository.ReadAuditAsync(100);
            if (_route != "Settings") return;
            audit.Children.Add(Ui.Table(entries.Select(a => new { At = a.At.LocalDateTime.ToString("g"), a.Action, a.EntityId, a.Detail, a.EventId }), ("Time", "At", 165), ("Action", "Action", 165), ("Detail", "Detail", 0), ("Event ID", "EventId", 190)));
        });
    }

    private string ServiceState()
    {
        try
        {
            var path = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "ServiceState", "health.json");
            if (!File.Exists(path)) return "Windows service: no health evidence available. Install SENTINEL Setup to register the required maintenance service.";
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            var heartbeat = root.GetProperty("heartbeatAtUtc").GetDateTimeOffset();
            if ((DateTimeOffset.UtcNow - heartbeat).TotalSeconds > 90) return $"Windows service: health record is stale (last heartbeat {heartbeat.LocalDateTime:g}). Check the service with your administrator.";
            return $"Windows service: {root.GetProperty("status").GetString()} · {root.GetProperty("message").GetString()} · No automatic scans";
        }
        catch { return "Windows service: health evidence could not be read. The desktop remains available; check service permissions and logs."; }
    }

    private void AddCategoryFindings(params SecurityCategory[] categories)
    {
        var list = Snapshot.Findings.Where(f => categories.Contains(f.Category)).ToList();
        PageContent.Children.Add(Ui.Text("Recorded posture findings", 20, bold: true)); RenderFindings(list);
    }

    private void AddEmpty(string title, string description) => PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text(title, 20, bold: true), Ui.Text(description, 14, "MutedBrush"))));

    private void ScanButton_Click(object sender, RoutedEventArgs e) => ScanButton_Click();
    private void ScanButton_Click()
    {
        if (_coordinator.Current is null) { ShowEnvironmentChoice(); return; }
        if (_busy) return;
        if (Snapshot.Mode == EnvironmentMode.Demo) { ShowNotice("Demo assessments are fully offline", "The sample organization uses the same persisted evidence, graph, contextual risk, and reporting engines. Switch to Live Environment to authorize an actual assessment."); return; }
        var dialog = new AuthorizedScopeDialog(_coordinator.Engines) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Scope is not null) _ = RunScanAsync(dialog.EngineId, dialog.Scope);
    }

    private async Task RunScanAsync(string engineId, ScanScope scope)
    {
        _scanCancellation = new CancellationTokenSource();
        _busy = true; ScanButton.IsEnabled = false; Navigation.IsEnabled = false; CancelScanButton.IsEnabled = true; CancelScanButton.Visibility = Visibility.Visible; Progress.Visibility = Visibility.Visible;
        try
        {
            var progress = new Progress<string>(message => StatusText.Text = message);
            StatusText.Text = "Starting authorized assessment…";
            await _coordinator.RunScanAsync(engineId, scope, progress, _scanCancellation.Token);
            var scan = Snapshot.Scans.OrderByDescending(s => s.StartedAt).FirstOrDefault();
            StatusText.Text = scan is null ? "Assessment finished" : $"{scan.Status} · {scan.Message} · Event {scan.EventId}";
            RenderPage(); ShowNotice("Assessment finished", StatusText.Text);
        }
        catch (OperationCanceledException) { StatusText.Text = "Assessment cancelled safely. No additional targets will be contacted."; RenderPage(); }
        catch (Exception ex) { ShowFailure(ex); RenderPage(); }
        finally { _busy = false; ScanButton.IsEnabled = true; Navigation.IsEnabled = true; CancelScanButton.Visibility = Visibility.Collapsed; Progress.Visibility = Visibility.Collapsed; _scanCancellation.Dispose(); _scanCancellation = null; }
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCancellation?.Cancel(); CancelScanButton.IsEnabled = false; StatusText.Text = "Cancellation requested. Waiting for active probes to release their resources…";
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy) return;
        e.Cancel = true;
        _scanCancellation?.Cancel(); StatusText.Text = "Cancelling the assessment before closing. Close the window again when cancellation completes.";
    }

    private void SwitchEnvironment_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) { ShowNotice("Assessment is running", "Cancel or finish the current assessment before switching environments."); return; }
        ShowEnvironmentChoice();
    }

    private async Task GuardAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception ex) { ShowFailure(ex); }
    }

    public void ShowFailure(Exception exception)
    {
        var eventId = Guid.NewGuid().ToString("N")[..12];
        var message = exception is ArgumentException or InvalidOperationException ? exception.Message : "SENTINEL could not complete this action. Verify access and configuration, then retry.";
        var technical = $"{exception.GetType().Name}: {exception.Message}";
        try
        {
            var logDirectory = System.IO.Path.Combine(_dataDirectory, "Logs"); Directory.CreateDirectory(logDirectory);
            File.AppendAllText(System.IO.Path.Combine(logDirectory, $"desktop-{DateTime.UtcNow:yyyy-MM-dd}.jsonl"), JsonSerializer.Serialize(new { At = DateTimeOffset.UtcNow, EventId = eventId, Action = _route, Message = exception.Message, TechnicalDetails = exception.ToString() }) + Environment.NewLine);
        }
        catch { }
        ShowNotice(message, $"Event ID {eventId} · Technical details: {technical} · Logs: {_dataDirectory}\\Logs");
        StatusText.Text = $"Action failed · Event {eventId} · Retry the action after reviewing access and configuration.";
    }

    private void ShowNotice(string message, string detail = "") { NoticeText.Text = message; NoticeDetail.Text = detail; NoticeBorder.Visibility = Visibility.Visible; }
    private void DismissNotice_Click(object sender, RoutedEventArgs e) => NoticeBorder.Visibility = Visibility.Collapsed;
    private static string SeverityBrush(Severity severity) => severity switch { Severity.Critical => "CriticalBrush", Severity.High => "HighBrush", Severity.Medium => "MediumBrush", _ => "MutedBrush" };
    private static string Subtitle(string route) => route switch
    {
        "Command Center" => "Know what can hurt the organization. Fix what matters first.", "Assets" => "Authorized inventory, ownership, criticality, and historical observations.", "Attack Paths" => "Explain the evidence chain and choose a defensive break point.", "Evidence Graph" => "Explore how assets, identities, findings, and permissions connect.", "Remediation" => "Prioritize root causes by the modeled risk they can remove.", "AI Analyst" => "Evidence-based answers with explicit confidence and inference.", "Reports" => "Translate technical evidence into clear decisions.", "Monitoring" => "Understand what changed and where the evidence came from.", "Settings" => "Local operation, appearance, retention, and audit history.", _ => "Recorded evidence, contextual priority, and verifiable defensive action."
    };
    private static string IconFor(string route) => route switch
    {
        "Command Center" => "M1,1 H7 V7 H1 Z M11,1 H17 V7 H11 Z M1,11 H7 V17 H1 Z M11,11 H17 V17 H11 Z",
        "Assets" or "Endpoints" => "M1,2 H17 V13 H1 Z M9,13 V17 M5,17 H13",
        "Network" or "Evidence Graph" or "Attack Paths" => "M9,2 A2,2 0 1 0 9,6 A2,2 0 1 0 9,2 M3,12 A2,2 0 1 0 3,16 A2,2 0 1 0 3,12 M15,12 A2,2 0 1 0 15,16 A2,2 0 1 0 15,12 M8,6 L4,12 M10,6 L14,12 M5,14 H13",
        "Identity" or "Active Directory" => "M9,1 A4,4 0 1 0 9,9 A4,4 0 1 0 9,1 M2,17 C2,10 16,10 16,17",
        "Cloud" => "M4,14 C-2,14 0,6 5,7 C5,0 15,0 15,7 C20,7 20,14 14,14 Z",
        "Settings" => "M9,1 V5 M9,13 V17 M1,9 H5 M13,9 H17 M3,3 L6,6 M12,12 L15,15 M3,15 L6,12 M12,6 L15,3 M9,5 A4,4 0 1 0 9,13 A4,4 0 1 0 9,5",
        "Reports" or "Compliance" => "M3,1 H12 L16,5 V17 H3 Z M11,1 V6 H16 M6,9 H12 M6,13 H12",
        _ => "M9,1 L17,4 V11 L9,17 L1,11 V4 Z M9,5 V10 M9,12 V13"
    };
    private static string ReportTitle(ReportKind kind) => kind switch { ReportKind.AssetInventory => "Asset Inventory", ReportKind.SecurityProgress => "Security Progress Report", _ => kind + " Security Report" };
    private static string ReportDescription(ReportKind kind) => kind switch { ReportKind.Executive => "Business impact, global posture, critical exposure, and the next actions.", ReportKind.Technical => "Scope, observations, evidence, findings, paths, and verification steps.", ReportKind.Vulnerability => "Affected software, CVE intelligence, contextual risk, and finding disposition.", ReportKind.AssetInventory => "Owned assets, criticality, observed services, operating systems, and provenance.", ReportKind.Remediation => "Grouped actions, affected assets, estimated benefit, confidence, and fix verification.", ReportKind.Compliance => "NIST CSF 2.0 and CIS mappings with evidenced gaps and coverage limitations.", _ => "Assessment history, score trend, change timeline, and remaining modeled risk." };

    private sealed record FindingRow(Finding Finding, double Risk)
    {
        public string Title => Finding.Title; public string Severity => Finding.Severity.ToString(); public string RiskDisplay => Risk.ToString("0.0"); public string Cve => Finding.Cve ?? "—"; public int AssetCount => Finding.AssetIds.Count; public string Status => Finding.Status.ToString(); public string Confidence => Finding.Confidence.ToString("P0");
    }
    private sealed record IdentityRow(Identity Identity)
    {
        public string DisplayName => Identity.DisplayName; public string PrincipalName => Identity.PrincipalName; public string Provider => Identity.Provider; public string Privileged => Identity.IsPrivileged ? "Yes" : "No"; public string Mfa => Identity.MfaEnabled is null ? "Unknown" : Identity.MfaEnabled.Value ? "Enabled" : "Not enabled"; public string LastSignIn => Identity.LastSignIn?.LocalDateTime.ToString("g") ?? "Unknown";
    }
}
