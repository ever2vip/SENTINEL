using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
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
    private readonly DesktopWorkflowStore _workflow;
    private readonly Dictionary<string, Button> _navigationButtons = [];
    private readonly List<(TextBlock Label, Expander Group)> _navigationGroups = [];
    private bool _compactNavigation;
    private bool _manualCompact;
    private TrayNotifications? _tray;
    private AppSettings _settings = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _initialized;
    private bool _busy;
    private string _route = "Command Center";
    private EnvironmentSnapshot Snapshot => _coordinator.Current ?? throw new InvalidOperationException("Choose an environment before using this page.");

    public MainWindow() : this(null) { }

    public MainWindow(string? dataDirectory)
    {
        InitializeComponent();
        Width = Math.Max(MinWidth, Math.Min(Width, SystemParameters.WorkArea.Width - 24));
        Height = Math.Max(MinHeight, Math.Min(Height, SystemParameters.WorkArea.Height - 24));
        _dataDirectory = dataDirectory ?? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");
        Directory.CreateDirectory(_dataDirectory);
        _repository = new SQLiteEnvironmentRepository(System.IO.Path.Combine(_dataDirectory, "sentinel.db"));
        _coordinator = new ApplicationCoordinator(_repository, [new NetworkPostureEngine(), new LocalEndpointEngine(), new WebPostureEngine(), new EmailPostureEngine()]);
        _workflow = new DesktopWorkflowStore(_dataDirectory);
        BuildNavigation();
        Loaded += async (_, _) => await InitializeAsync();
        SourceInitialized += (_, _) => { if (dataDirectory is null) _tray = new TrayNotifications(this, () => Navigate("Monitoring")); };
        SizeChanged += (_, _) => ApplyNavigationLayout();
        ShellRoot.SizeChanged += (_, _) => ApplyNavigationLayout();
        Closing += Window_Closing;
        Closed += (_, _) => { _tray?.Dispose(); _repository.Dispose(); };
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
        await _workflow.LoadAsync(Snapshot.Id);
        Navigation.IsEnabled = true;
        ScanButton.IsEnabled = true;
        _settings.LastEnvironment = mode;
        await _coordinator.SaveSettingsAsync(_settings);
        OrganizationText.Text = mode == EnvironmentMode.Demo ? "Northstar Industries" : Snapshot.Name;
        ModeText.Text = mode == EnvironmentMode.Demo ? "DEMO" : "LIVE";
        EnvironmentContextText.Text = mode == EnvironmentMode.Demo ? "Synthetic evidence · offline lab" : "Authorized assessment · explicit scope";
        AssessmentText.Text = $"Evidence updated {Snapshot.UpdatedAt.LocalDateTime:g}";
        StatusText.Text = mode == EnvironmentMode.Demo ? "Offline demo · Actual risk calculations from synthetic evidence · No network traffic" : "Live workspace · No scans run until scope is explicitly authorized";
        ScanButton.Content = mode == EnvironmentMode.Demo ? "Assessment info" : "New assessment";
        Navigate("Command Center");
    }

    private void ShowEnvironmentChoice()
    {
        Navigation.IsEnabled = false;
        ScanButton.IsEnabled = false;
        ModeText.Text = "SELECT";
        OrganizationText.Text = "Choose an environment";
        EnvironmentContextText.Text = "Separate local evidence workspaces";
        AssessmentText.Text = "No assessment is started by selection";
        PageContextText.Text = "";
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
        if (!Routes.Contains(route)) throw new ArgumentException("Unknown SENTINEL page.", nameof(route));
        _route = route;
        foreach (var pair in _navigationButtons)
        {
            pair.Value.Style = (Style)Application.Current.FindResource(pair.Key == route ? "SelectedNavigationButton" : "NavigationButton");
        }
        RenderPage();
    }

    private void RenderPage()
    {
        if (_coordinator.Current is null) { ShowEnvironmentChoice(); return; }
        PageContent.Children.Clear();
        PageScroll.ScrollToTop();
        PageTitle.Text = _route;
        PageSubtitle.Text = Subtitle(_route);
        PageContextText.Text = Snapshot.Mode == EnvironmentMode.Demo ? "Synthetic evidence" : "Operator authorized scope";
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

    private void RenderIntegrations()
    {
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Extensible engines and connectors", 22, bold: true), Ui.Text("Assessment engines and provider connectors use versioned typed contracts. Connector implementations must declare required permissions, authenticate through official APIs, and store secrets with Windows protected storage. Imported evidence retains its source.", brush: "MutedBrush"))));
        var engineCards = _coordinator.Engines.Select(engine => (UIElement)Ui.Card(Ui.Stack(Ui.Toolbar(Ui.Icon(engine.Name, 20), Ui.Text(engine.Name, 17, bold: true)), Ui.Badge(engine.IsAvailable ? "Available · authorized scope required" : "Unavailable", engine.IsAvailable ? "SuccessBrush" : "MutedBrush"), Ui.Text(engine.Description), Ui.Text(engine.IsAvailable ? "On-demand collection" : engine.AvailabilityReason, 12, "MutedBrush")), 20)).ToList();
        for (var i = 0; i < engineCards.Count; i += 2) PageContent.Children.Add(Ui.Columns(engineCards.Skip(i).Take(2).ToArray()));
        var connectorCards = new ConnectorRegistry().Descriptors.Select(connector => (UIElement)Ui.Card(Ui.Stack(Ui.Toolbar(Ui.Icon("Cloud", 20), Ui.Text(connector.Name, 17, bold: true)), Ui.Badge("Connector contract · not connected"), Ui.Text(connector.Status, 14, "MutedBrush"), Ui.Text("Least-privilege permissions: " + string.Join("; ", connector.RequiredPermissions), 13), Ui.Text(connector.DocumentationUrl, 12, "MutedBrush")), 20)).ToList();
        PageContent.Children.Add(Ui.Section("Provider and future integrations", "Availability is declared honestly; imported evidence does not create an API connection."));
        for (var i = 0; i < connectorCards.Count; i += 2) PageContent.Children.Add(Ui.Columns(connectorCards.Skip(i).Take(2).ToArray()));
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
        AutomationProperties.SetName(theme, "Theme");
        theme.SelectionChanged += (_, _) => _ = GuardAsync(async () =>
        {
            _settings.Theme = theme.SelectedItem?.ToString() ?? "System";
            ThemeManager.Apply(_settings.Theme);
        await _coordinator.SaveSettingsAsync(_settings);
        });
        var retention = Ui.Input(_settings.RetentionDays.ToString(), 150);
        var save = Ui.Button("Save preferences", () => _ = GuardAsync(async () =>
        {
            if (!int.TryParse(retention.Text, out var days) || days < 7 || days > 3650) throw new ArgumentException("Retention must be between 7 and 3650 days.");
            _settings.Theme = theme.SelectedItem?.ToString() ?? "System"; _settings.RetentionDays = days;
            await _coordinator.SaveSettingsAsync(_settings); ThemeManager.Apply(_settings.Theme); RenderPage(); ShowNotice("Preferences saved", "Theme and retention are persisted in the local workspace.");
        }), true);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Appearance and data retention", "Theme updates immediately and persists. Retention trims history while preserving current asset and finding evidence."), Ui.Toolbar(Ui.Text("Appearance", 14), theme, Ui.Text("Retention days", 14), retention, save))));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Windows application", "The tray icon shows on-demand assessment status. Closing SENTINEL exits the desktop."), Ui.Button("Minimize to tray", () => { if (_tray is null) { ShowNotice("Tray unavailable", "Use the standard Windows taskbar to minimize this session."); return; } Hide(); ShowNotice("SENTINEL is in the system tray", "Double-click the shield icon to reopen the workspace."); }))));
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

    private void AddEmpty(string title, string description) => PageContent.Children.Add(Ui.Empty(title, description));

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
        var existingPriorities = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open && f.Severity >= Severity.High).Select(f => f.Id).ToHashSet();
        _scanCancellation = new CancellationTokenSource();
        _busy = true; ScanButton.IsEnabled = false; Navigation.IsEnabled = false; CancelScanButton.IsEnabled = true; CancelScanButton.Visibility = Visibility.Visible; Progress.Visibility = Visibility.Visible;
        try
        {
            var progress = new Progress<string>(message => StatusText.Text = message);
            StatusText.Text = "Starting authorized assessment…";
            await _coordinator.RunScanAsync(engineId, scope, progress, _scanCancellation.Token);
            var scan = Snapshot.Scans.OrderByDescending(s => s.StartedAt).FirstOrDefault();
            var newPriorities = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open && f.Severity >= Severity.High && !existingPriorities.Contains(f.Id)).ToList();
            if (newPriorities.FirstOrDefault() is Finding alert) _tray?.Notify("SENTINEL Security Alert", $"{newPriorities.Count} new high/critical findings · {alert.Title}. Open SENTINEL to review collected evidence.");
            AssessmentText.Text = $"Evidence updated {Snapshot.UpdatedAt.LocalDateTime:g}";
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

}
