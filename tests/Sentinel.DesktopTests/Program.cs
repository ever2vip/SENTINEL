using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Sentinel.DesktopTests;

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("FAIL Desktop acceptance requires Windows x64 and a real WPF dispatcher.");
            return 1;
        }
        DesktopAcceptance? acceptance = null;
        try
        {
            var options = Options.Parse(arguments);
            acceptance = new DesktopAcceptance(options);
            var application = acceptance.LoadApplication();
            application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            application.DispatcherUnhandledException += (_, eventArgs) =>
            {
                acceptance.RecordDispatcherFailure(eventArgs.Exception);
                eventArgs.Handled = true;
            };
            _ = application.Dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await acceptance.RunAsync(); }
                catch (Exception exception) { acceptance.RecordFatalFailure(exception); }
                finally
                {
                    acceptance.DisposeRenderingHost();
                    acceptance.WriteResults();
                    application.Dispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
                }
            }), DispatcherPriority.ApplicationIdle);
            Dispatcher.Run();
            return acceptance.Failed ? 1 : 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"FAIL Desktop acceptance startup: {exception.GetType().Name}: {exception.Message}");
            acceptance?.RecordFatalFailure(exception);
            acceptance?.WriteResults();
            return 1;
        }
    }
}

internal sealed record Options(string DesktopDirectory, string EvidenceDirectory, bool Quick)
{
    public static Options Parse(string[] arguments)
    {
        string? desktop = null;
        string? evidence = null;
        var quick = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            switch (arguments[index])
            {
                case "--desktop-directory" when index + 1 < arguments.Length: desktop = arguments[++index]; break;
                case "--evidence-directory" when index + 1 < arguments.Length: evidence = arguments[++index]; break;
                case "--quick": quick = true; break;
                default: throw new ArgumentException("Unknown or incomplete desktop acceptance argument: " + arguments[index]);
            }
        }
        if (string.IsNullOrWhiteSpace(desktop) || string.IsNullOrWhiteSpace(evidence))
            throw new ArgumentException("Specify --desktop-directory <actual Desktop payload> and --evidence-directory <QA output>.");
        return new(Path.GetFullPath(desktop), Path.GetFullPath(evidence), quick);
    }
}

internal sealed class DesktopAcceptance(Options options)
{
    private static readonly string[] Routes = ["Command Center", "Assets", "Network", "Endpoints", "Vulnerabilities", "Identity", "Active Directory", "Cloud", "Web Security", "Attack Surface", "Attack Paths", "Evidence Graph", "Compliance", "Monitoring", "Incidents", "Remediation", "Reports", "AI Analyst", "Integrations", "Settings"];
    private static readonly (int Width, int Height)[] Resolutions = [(1366, 768), (1920, 1080), (2560, 1440)];
    private static readonly double[] Scales = [1, 1.25, 1.5];
    private readonly List<CheckResult> _checks = [];
    private readonly List<RenderResult> _renders = [];
    private readonly List<string> _dispatcherFailures = [];
    private readonly string _profileDirectory = Path.Combine(Path.GetTempPath(), "sentinel-desktop-qa-" + Guid.NewGuid().ToString("N"));
    private Assembly _desktopAssembly = null!;
    private Window _window = null!;
    private FrameworkElement _root = null!;
    private JsonElement _snapshot;
    private string _assemblyHash = "";
    private uint _nativeDpi;
    private HwndSource? _renderSource;
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    public bool Failed => _checks.Any(check => check.Status == "failed") || _dispatcherFailures.Count > 0;

    public Application LoadApplication()
    {
        var assemblyPath = Path.Combine(options.DesktopDirectory, "Sentinel.Desktop.dll");
        if (!File.Exists(assemblyPath)) throw new FileNotFoundException("The actual SENTINEL Desktop assembly is missing.", assemblyPath);
        Directory.CreateDirectory(options.EvidenceDirectory);
        Directory.CreateDirectory(_profileDirectory);
        _assemblyHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath))).ToLowerInvariant();
        var resolver = new AssemblyDependencyResolver(assemblyPath);
        AssemblyLoadContext.Default.Resolving += (_, name) =>
        {
            var path = resolver.ResolveAssemblyToPath(name);
            path ??= File.Exists(Path.Combine(options.DesktopDirectory, name.Name + ".dll"))
                ? Path.Combine(options.DesktopDirectory, name.Name + ".dll") : null;
            return path is null ? null : AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
        };
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += (_, name) =>
        {
            var path = resolver.ResolveUnmanagedDllToPath(name);
            return path is null ? IntPtr.Zero : NativeLibrary.Load(path);
        };
        _desktopAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        var appType = _desktopAssembly.GetType("Sentinel.Desktop.App", throwOnError: true)!;
        var application = (Application)Activator.CreateInstance(appType)!;
        appType.GetMethod("InitializeComponent", BindingFlags.Public | BindingFlags.Instance)!.Invoke(application, null);
        // Dispatcher.Run below intentionally avoids App.OnStartup creating an operator-profile
        // window. The tested MainWindow is the production class with an isolated profile.
        Console.WriteLine($"Desktop assembly: {assemblyPath}");
        Console.WriteLine($"Desktop assembly SHA-256: {_assemblyHash}");
        Console.WriteLine($"Isolated operator profile: {_profileDirectory}");
        return application;
    }

    public async Task RunAsync()
    {
        _window = NewWindow();
        _window.Show();
        _root = (FrameworkElement)_window.Content;
        _nativeDpi = GetDpiForWindow(new WindowInteropHelper(_window).Handle);
        await Check("first-launch-initializes-SQLite-and-workspace-selector", async () =>
        {
            await ProbeAsync("WaitForTestingReadyAsync");
            Assert(!ProbeProperty<bool>("HasEnvironmentForTesting"), "An isolated first launch must offer a workspace choice before loading evidence.");
            Assert(AllText().Contains("Demo", StringComparison.OrdinalIgnoreCase) && AllText().Contains("Live", StringComparison.OrdinalIgnoreCase), "First launch does not expose both Demo and Live choices.");
            Assert(File.Exists(Path.Combine(_profileDirectory, "sentinel.db")), "First launch did not physically create the SQLite database.");
        });
        await Check("Demo-Organization-loads-real-offline-evidence-and-analytics", async () =>
        {
            var openDemo = FindButton("Open Demo Organization", "Open demo", "Demo Organization");
            InvokeButton(openDemo);
            await WaitUntil(() => ProbeProperty<bool>("HasEnvironmentForTesting"), "The Demo Organization button did not load an environment.");
            await WaitUntil(() => (_window.FindName("ModeText") as TextBlock)?.Text == "DEMO", "Demo loading did not finish updating the global environment indicator.");
            _snapshot = ParseProbe("SnapshotJsonForTesting");
            Assert(_snapshot.GetProperty("Mode").GetInt32() == 0, "The selected workspace is not Demo.");
            Assert(_snapshot.GetProperty("Assets").GetArrayLength() >= 289, "The stored Northstar fixture is incomplete.");
            Assert(_snapshot.GetProperty("Identities").GetArrayLength() >= 220, "The stored synthetic identities are incomplete.");
            Assert(_snapshot.GetProperty("Findings").GetArrayLength() > 0, "The stored synthetic findings are missing.");
            var analytics = ParseProbe("AnalyticsJsonForTesting");
            Assert(analytics.GetProperty("AttackPaths").GetArrayLength() > 0, "The actual defensive path engine did not analyze Demo evidence.");
            Assert(analytics.GetProperty("Remediations").GetArrayLength() > 0, "The actual remediation engine did not analyze Demo evidence.");
            Assert(analytics.GetProperty("Risk").GetProperty("GlobalScore").GetDouble() is >= 0 and <= 100, "The actual risk engine did not produce a valid score.");
            Assert(AllText().Contains("DEMO", StringComparison.OrdinalIgnoreCase), "The global environment context does not identify synthetic Demo evidence.");
        });
        if (!ProbeProperty<bool>("HasEnvironmentForTesting"))
            throw new InvalidOperationException("The Demo Organization is unavailable; downstream UI acceptance cannot run.");
        Probe("ApplyThemeForTesting", "Dark");
        await SetViewport(1920, 1080, 1);
        await CheckAssetWorkflow();
        await CheckFindingWorkflow();
        await CheckGraphWorkflow();
        await CheckAttackPathWorkflow();
        await CheckAnalystWorkflow();
        await CheckReportStudio();
        await CheckReportScopeIsolation();
        await CheckPlanningMetadata();
        await CheckVerificationSemantics();
        await CheckRemediationWorkflow();
        await CheckAuthorizedScopeDialog();
        await Check("notification-header-navigates-recorded-monitoring", async () =>
        {
            InvokeButton(FindButton("Notifications"));
            await WaitUntil(() => ProbeProperty<string>("CurrentRouteForTesting") == "Monitoring", "The application notification action did not navigate to actual recorded monitoring evidence.");
        });
        await CheckSettingsPersistence();
        await Check("Live-selector-remains-separate-and-unassessed", async () =>
        {
            await ProbeAsync("OpenEnvironmentForTestingAsync", "Live");
            var live = ParseProbe("SnapshotJsonForTesting");
            Assert(live.GetProperty("Mode").GetInt32() == 1, "Live selection did not open a separate workspace.");
            Assert(live.GetProperty("Assets").GetArrayLength() == 0 && live.GetProperty("Findings").GetArrayLength() == 0, "Synthetic Demo evidence leaked into the Live workspace.");
            var risk = ParseProbe("AnalyticsJsonForTesting").GetProperty("Risk");
            Assert(risk.GetProperty("CategoryScores").EnumerateObject().Count() == 0, "Unassessed Live inventory must not manufacture posture coverage.");
            Assert(AllText().Contains("LIVE", StringComparison.OrdinalIgnoreCase), "The global context does not identify the Live workspace.");
            await ProbeAsync("OpenEnvironmentForTestingAsync", "Demo");
            Assert(ParseProbe("SnapshotJsonForTesting").GetProperty("Assets").GetArrayLength() == _snapshot.GetProperty("Assets").GetArrayLength(), "Switching environments modified the stored Demo inventory.");
        });
        await CheckReadableFailure();
        await RenderMatrix();
        await Check("no-unhandled-dispatcher-errors", () =>
        {
            Assert(_dispatcherFailures.Count == 0, "WPF dispatcher failures occurred: " + string.Join("; ", _dispatcherFailures));
            return Task.CompletedTask;
        });
        DisposeRenderingHost();
        _window.Close();
        Probe("DisposeRepositoryForTesting");
    }

    private Window NewWindow()
    {
        var type = _desktopAssembly.GetType("Sentinel.Desktop.MainWindow", throwOnError: true)!;
        var constructor = type.GetConstructor([typeof(string)])
            ?? throw new MissingMethodException("The production desktop is missing its isolated-profile constructor required by Windows acceptance.");
        var window = (Window)constructor.Invoke([_profileDirectory]);
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = 0;
        window.Top = 0;
        return window;
    }

    private async Task CheckAssetWorkflow() => await Check("Assets-real-search-filter-selection-and-evidence-detail", async () =>
    {
        await Navigate("Assets");
        var grid = FirstGrid();
        Assert(grid.Items.Count >= 289, "Assets table does not expose the stored inventory.");
        Assert(grid.EnableRowVirtualization, "Asset row virtualization was lost.");
        var search = FindTextBox("Search assets", "Asset search");
        search.Text = "sentinel-no-match-" + Guid.NewGuid().ToString("N");
        await Flush();
        Assert(grid.Items.Count == 0, "Asset search does not filter unmatched records.");
        search.Text = "NS-DC01";
        await Flush();
        Assert(grid.Items.Count == 1, "Exact asset search did not select the synthetic domain controller.");
        grid.SelectedIndex = 0;
        await Flush();
        Assert(AllText().Contains("NS-DC01", StringComparison.Ordinal), "Asset selection did not preserve the actual asset label.");
        Assert(AllText().Contains("Evidence", StringComparison.OrdinalIgnoreCase) || AllText().Contains("Observed posture", StringComparison.OrdinalIgnoreCase), "Selected asset does not expose its evidence workspace.");
        search.Text = "";
        var type = FindCombo("Asset type", "Type");
        var serverOption = type.Items.Cast<object>().FirstOrDefault(item => ItemText(item).Contains("Server", StringComparison.OrdinalIgnoreCase));
        Assert(serverOption is not null, "The asset type filter is missing its server choice.");
        type.SelectedItem = serverOption;
        await Flush();
        Assert(grid.Items.Count == 12, "The server filter did not use the 12 stored server records.");
        await CaptureInteraction("Assets-selected", "Dark");
    });

    private async Task CheckFindingWorkflow() => await Check("Vulnerabilities-real-search-selection-and-confidence-evidence", async () =>
    {
        await Navigate("Vulnerabilities");
        var grid = FirstGrid();
        Assert(grid.Items.Count > 0, "The vulnerability table is empty despite stored vulnerability evidence.");
        var search = FindTextBox("Search findings", "Search vulnerabilities", "Finding search");
        search.Text = "sentinel-no-match-" + Guid.NewGuid().ToString("N");
        await Flush();
        Assert(grid.Items.Count == 0, "Finding search does not filter unmatched records.");
        search.Text = "";
        await Flush();
        grid.SelectedIndex = 0;
        await Flush();
        var text = AllText();
        Assert(text.Contains("Evidence", StringComparison.OrdinalIgnoreCase) && text.Contains("Confidence", StringComparison.OrdinalIgnoreCase), "Finding selection did not expose evidence and confidence.");
        await SelectTab("Evidence");
        Assert(AllText().Contains("Source", StringComparison.OrdinalIgnoreCase) || AllText().Contains("Provenance", StringComparison.OrdinalIgnoreCase), "The real evidence detail tab does not identify collected provenance.");
        await SelectTab("Remediation");
        text = AllText();
        Assert(text.Contains("Verification", StringComparison.OrdinalIgnoreCase), "Finding selection does not provide verification guidance.");
        await CaptureInteraction("Vulnerabilities-selected", "Dark");
    });

    private async Task CheckGraphWorkflow() => await Check("Evidence-Graph-real-search-zoom-reset-and-node-inspector", async () =>
    {
        await Navigate("Evidence Graph");
        var text = AllText();
        Assert(text.Contains("Legend", StringComparison.OrdinalIgnoreCase) || text.Contains("Node types", StringComparison.OrdinalIgnoreCase), "The graph does not expose an intelligible node-type legend.");
        var search = FindTextBox("Search evidence node labels or identifiers", "Search node", "Search nodes", "Search graph");
        search.Text = "NS-DC01";
        var graph = Descendants(PageRoot()).FirstOrDefault(element => element.GetType().FullName == "Sentinel.Desktop.EvidenceGraphView")
            ?? throw new InvalidOperationException("The actual interactive graph control is missing.");
        await WaitUntil(() => ((IEnumerable<string>)Get(graph, "DisplayedNodeIds")!).Contains("server-dc01"), "Debounced graph search did not render the actual matching evidence node.");
        Matrix MatrixForGraph() => (Matrix)graph.GetType().GetField("_matrix", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(graph)!;
        var zoomBefore = MatrixForGraph().M11;
        InvokeButton(FindButton("Zoom in"));
        await Flush();
        Assert(MatrixForGraph().M11 > zoomBefore, "The graph zoom-in control did not change its actual rendered transform.");
        var zoomed = MatrixForGraph().M11;
        InvokeButton(FindButton("Zoom out"));
        await Flush();
        Assert(MatrixForGraph().M11 < zoomed, "The graph zoom-out control did not change its actual rendered transform.");
        InvokeButton(FindButton("Fit graph", "Fit to view", "Fit"));
        await Flush();
        var node = Descendants(_root).OfType<Button>().FirstOrDefault(button => AccessibleText(button).Contains("NS-DC01", StringComparison.Ordinal));
        Assert(node is not null, "The searched evidence node is not selectable through an accessible real graph control.");
        InvokeButton(node!);
        await Flush();
        Assert((string?)Get(graph, "SelectedNodeId") == "server-dc01", "The selected graph control did not inspect the actual requested evidence record.");
        text = AllText();
        Assert(text.Contains("NS-DC01", StringComparison.Ordinal) && (text.Contains("Provenance", StringComparison.OrdinalIgnoreCase) || text.Contains("Source", StringComparison.OrdinalIgnoreCase)), "Node selection did not populate the graph inspector with provenance.");
        await CaptureInteraction("Evidence-Graph-selected", "Dark");
        InvokeButton(FindButton("Reset view", "Reset"));
        search.Text = "";
        await WaitUntil(() => (bool)Get(graph, "IsClusterOverview")!, "Graph reset did not restore its bounded evidence overview.");
    });

    private async Task CheckAttackPathWorkflow() => await Check("Attack-Paths-real-visual-chain-and-defensive-breakpoint", async () =>
    {
        await Navigate("Attack Paths");
        var text = AllText();
        Assert(text.Contains("Confidence", StringComparison.OrdinalIgnoreCase), "Defensive paths do not display evidence confidence.");
        InvokeButton(FindButton("BREAK THIS PATH", "Break this path"));
        await Flush();
        text = AllText();
        Assert(text.Contains("Verify", StringComparison.OrdinalIgnoreCase) || text.Contains("Verification", StringComparison.OrdinalIgnoreCase), "The defensive breakpoint workspace does not explain how to verify remediation.");
        Assert(text.Contains("Remediation", StringComparison.OrdinalIgnoreCase) || text.Contains("break point", StringComparison.OrdinalIgnoreCase), "The defensive path action did not open its remediation explanation.");
        await CaptureInteraction("Attack-Paths-breakpoint", "Dark");
    });

    private async Task CheckAnalystWorkflow() => await Check("AI-Analyst-offline-answer-evidence-inference-and-record-navigation", async () =>
    {
        await Navigate("AI Analyst");
        var input = FindTextBox("Question", "Ask the analyst", "Analyst question");
        input.Text = "What should we fix first?";
        InvokeButton(FindButton("Ask analyst", "Ask", "Send question", "Send"));
        await WaitUntil(() => AllText().Contains("ANALYST RESPONSE", StringComparison.Ordinal) &&
            Descendants(_root).OfType<Button>().Any(button => AccessibleText(button).StartsWith("Finding:", StringComparison.OrdinalIgnoreCase)
                || AccessibleText(button).StartsWith("Asset:", StringComparison.OrdinalIgnoreCase)),
            "The offline analyst did not render an actual evidence-cited conversation answer.");
        var text = AllText();
        Assert(text.Contains("Evidence", StringComparison.OrdinalIgnoreCase), "The analyst answer does not identify evidence sources.");
        Assert(text.Contains("Inference", StringComparison.OrdinalIgnoreCase), "The analyst answer does not distinguish inference.");
        var citation = Descendants(_root).OfType<Button>().FirstOrDefault(button => AccessibleText(button).StartsWith("Finding:", StringComparison.OrdinalIgnoreCase)
            || AccessibleText(button).StartsWith("Asset:", StringComparison.OrdinalIgnoreCase));
        Assert(citation is not null, "The analyst answer does not provide an actionable evidence citation.");
        await CaptureInteraction("AI-Analyst-answer", "Dark");
        InvokeButton(citation!);
        await Flush();
        Assert(ProbeProperty<string>("CurrentRouteForTesting") is "Assets" or "Vulnerabilities", "An analyst citation did not navigate to its real evidence record.");
    });

    private async Task CheckReportStudio() => await Check("Report-Studio-controls-and-real-PDF-structured-export", async () =>
    {
        await Navigate("Reports");
        var text = AllText();
        Assert(text.Contains("Preview", StringComparison.OrdinalIgnoreCase), "Reports has no live evidence-based preview.");
        Assert(text.Contains("PDF", StringComparison.OrdinalIgnoreCase), "Report Studio has no PDF export control.");
        Assert(Descendants(_root).OfType<CheckBox>().Any(), "Report Studio has no configuration controls.");
        var reportType = FindCombo("Report types");
        Assert(reportType.Items.Count == 7, "Report Studio does not preserve all seven report kinds.");
        var scope = FindCombo("Report scope");
        scope.SelectedItem = scope.Items.Cast<object>().Single(item => ItemText(item) == "Servers");
        await WaitUntil(() => AllText().Contains("12 assets", StringComparison.Ordinal) && AllText().Contains("Preview generated by the reporting engine", StringComparison.Ordinal),
            "Report Studio scope selection did not generate its real 12-server evidence preview.");
        reportType.SelectedIndex = 1;
        await WaitUntil(() => AllText().Contains("Technical", StringComparison.OrdinalIgnoreCase) && AllText().Contains("Preview generated by the reporting engine", StringComparison.Ordinal),
            "Report Studio type selection did not generate the actual technical preview.");
        var pdf = Path.Combine(options.EvidenceDirectory, "executive-demo.pdf");
        var json = Path.Combine(options.EvidenceDirectory, "technical-demo.json");
        // Execute the same coordinator export used by the production button; avoid automating
        // a native SaveFileDialog or accepting input outside the isolated QA directory.
        await ProbeAsync("ExportReportForTestingAsync", "Executive", "Pdf", pdf);
        await ProbeAsync("ExportReportForTestingAsync", "Technical", "Json", json);
        Assert(File.Exists(pdf) && new FileInfo(pdf).Length > 500, "The real coordinator did not produce a PDF report.");
        Assert(System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(pdf), 0, 5) == "%PDF-", "The exported report is not a PDF.");
        using var structured = JsonDocument.Parse(File.ReadAllText(json));
        Assert(structured.RootElement.ValueKind == JsonValueKind.Object, "The real structured report is not valid JSON.");
        await CaptureInteraction("Report-Studio-preview", "Dark");
    });

    private async Task CheckSettingsPersistence() => await Check("Settings-real-control-save-and-theme-retention-restart-persistence", async () =>
    {
        await Navigate("Settings");
        var theme = FindCombo("Theme", "Appearance");
        var light = theme.Items.Cast<object>().FirstOrDefault(item => ItemText(item) == "Light");
        Assert(light is not null, "Settings does not offer the designed Light theme.");
        theme.SelectedItem = light;
        var retention = FindTextBox("Retention days", "Retention");
        retention.Text = "180";
        InvokeButton(FindButton("Save preferences", "Save settings"));
        await WaitUntil(async () =>
        {
            var json = (string)(await ProbeAsync("SettingsJsonForTestingAsync"))!;
            using var settings = JsonDocument.Parse(json);
            return settings.RootElement.GetProperty("Theme").GetString() == "Light" && settings.RootElement.GetProperty("RetentionDays").GetInt32() == 180;
        }, "Settings controls did not persist theme and retention.");
        DisposeRenderingHost();
        _window.Close();
        Probe("DisposeRepositoryForTesting");
        _window = NewWindow();
        _window.Show();
        _root = (FrameworkElement)_window.Content;
        await ProbeAsync("WaitForTestingReadyAsync");
        await WaitUntil(() => ProbeProperty<bool>("HasEnvironmentForTesting"), "Restart did not restore the stored Demo workspace.");
        await WaitUntil(() => (_window.FindName("ModeText") as TextBlock)?.Text == "DEMO", "Restart did not finish restoring the Demo environment context.");
        var persisted = (string)(await ProbeAsync("SettingsJsonForTestingAsync"))!;
        using var parsed = JsonDocument.Parse(persisted);
        Assert(parsed.RootElement.GetProperty("Theme").GetString() == "Light" && parsed.RootElement.GetProperty("RetentionDays").GetInt32() == 180, "The actual desktop restart lost saved preferences.");
        Assert(Application.Current.Resources["BackgroundBrush"] is SolidColorBrush brush && Luminance(brush.Color) > 0.5, "Restart did not apply the saved Light palette.");
        await SetViewport(1920, 1080, 1);
    });

    private async Task CheckReportScopeIsolation() => await Check("Report-Studio-scope-cloning-reference-integrity-and-history-honesty", () =>
    {
        var coordinator = _window.GetType().GetField("_coordinator", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(_window)!;
        var source = Get(coordinator, "Current")!;
        var sourceJson = JsonSerializer.Serialize(source, source.GetType());
        var transform = _window.GetType().GetMethod("BuildResponseReportSnapshot", BindingFlags.Static | BindingFlags.NonPublic)!;
        var copy = transform.Invoke(null, [source, "Servers", null, null])!;
        var assets = ((System.Collections.IEnumerable)Get(copy, "Assets")!).Cast<object>().ToList();
        Assert(assets.Count == 12 && assets.All(asset => Get(asset, "Kind")!.ToString() == "Server"), "The report scope did not select the actual 12-server inventory.");
        var assetIds = assets.Select(asset => (string)Get(asset, "Id")!).ToHashSet(StringComparer.Ordinal);
        var nodes = ((System.Collections.IEnumerable)Get(copy, "Nodes")!).Cast<object>().Select(node => (string)Get(node, "Id")!).ToHashSet(StringComparer.Ordinal);
        Assert(((System.Collections.IEnumerable)Get(copy, "Findings")!).Cast<object>().All(finding =>
            ((IEnumerable<string>)Get(finding, "AssetIds")!).All(assetIds.Contains)), "A scoped report finding retained an out-of-scope asset reference.");
        Assert(((System.Collections.IEnumerable)Get(copy, "Edges")!).Cast<object>().All(edge =>
            nodes.Contains((string)Get(edge, "SourceId")!) && nodes.Contains((string)Get(edge, "TargetId")!)), "A scoped report graph retained dangling relationships.");
        Assert(((System.Collections.IEnumerable)Get(copy, "ScoreHistory")!).Cast<object>().Count() == 0 &&
            ((System.Collections.IEnumerable)Get(copy, "Scans")!).Cast<object>().Count() == 0, "Global assessment history was incorrectly relabeled as scoped report coverage.");
        Set(assets[0], "Owner", "Isolated report copy only");
        Assert(JsonSerializer.Serialize(source, source.GetType()) == sourceJson, "Report scope transformation or clone mutation changed the authoritative evidence snapshot.");
        var future = transform.Invoke(null, [source, "Entire environment", (DateTimeOffset?)DateTimeOffset.UtcNow.AddDays(1), null])!;
        Assert(((System.Collections.IEnumerable)Get(future, "Assets")!).Cast<object>().Count() == _snapshot.GetProperty("Assets").GetArrayLength(), "History filtering incorrectly deleted current posture inventory.");
        Assert(((System.Collections.IEnumerable)Get(future, "ScoreHistory")!).Cast<object>().Count() == 0, "History date-range filtering did not honor the selected range.");
        return Task.CompletedTask;
    });

    private async Task CheckPlanningMetadata() => await Check("Desktop-planning-metadata-environment-isolation-atomic-persistence-and-verified-rejection", async () =>
    {
        var storeType = _desktopAssembly.GetType("Sentinel.Desktop.DesktopWorkflowStore", throwOnError: true)!;
        var planType = _desktopAssembly.GetType("Sentinel.Desktop.RemediationPlan", throwOnError: true)!;
        var directory = Path.Combine(_profileDirectory, "PlanningRegression");
        object NewStore() => Activator.CreateInstance(storeType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, [directory], null)!;
        var store = NewStore();
        await ReflectTask(store, "LoadAsync", "qa-demo", CancellationToken.None);
        var plan = Activator.CreateInstance(planType, nonPublic: true)!;
        Set(plan, "ActionId", "qa-action"); Set(plan, "Title", "Offline defensive planning regression");
        Set(plan, "EnvironmentId", "qa-demo");
        Set(plan, "Owner", "QA owner"); Set(plan, "Status", "Planned");
        Set(plan, "ModeledRiskReduction", 25d); Set(plan, "Confidence", .85d);
        var actualRiskBefore = ProbeProperty<string>("AnalyticsJsonForTesting");
        await ReflectTask(store, "SavePlanAsync", plan, CancellationToken.None);
        await ReflectTask(store, "SetUnderReviewAsync", "qa-finding", true, "Review requested from existing evidence.", CancellationToken.None);
        var file = Directory.EnumerateFiles(Path.Combine(directory, "Workflows"), "*.v1.json").Single();
        var bytesBefore = File.ReadAllBytes(file);
        Assert(!Directory.EnumerateFiles(Path.Combine(directory, "Workflows"), "*.tmp").Any(), "Atomic planning persistence left a temporary file behind.");
        var reopened = NewStore();
        await ReflectTask(reopened, "LoadAsync", "qa-demo", CancellationToken.None);
        var restored = Reflect(reopened, "GetPlan", "qa-action")!;
        Assert((string)Get(restored, "Owner")! == "QA owner" && (string)Get(restored, "Status")! == "Planned", "Planning owner/status did not survive reopening.");
        Assert((bool)Reflect(reopened, "IsUnderReview", "qa-finding")!, "Under-review metadata did not survive reopening.");
        Set(restored, "Owner", "Caller mutation must not alter the store");
        Assert((string)Get(Reflect(reopened, "GetPlan", "qa-action")!, "Owner")! == "QA owner", "Read-only planning access leaked a mutable stored object.");
        await ReflectTask(reopened, "LoadAsync", "qa-live", CancellationToken.None);
        Assert(Reflect(reopened, "GetPlan", "qa-action") is null && !(bool)Reflect(reopened, "IsUnderReview", "qa-finding")!, "Demo planning/review metadata leaked into Live.");
        try { await ReflectTask(reopened, "SavePlanAsync", plan, CancellationToken.None); throw new InvalidOperationException("A stale Demo action was accepted after switching to Live."); }
        catch (InvalidOperationException exception) when (exception.Message.Contains("environment changed", StringComparison.OrdinalIgnoreCase)) { }
        Assert(Directory.EnumerateFiles(Path.Combine(directory, "Workflows"), "*.v1.json").Count() == 1 && File.ReadAllBytes(file).SequenceEqual(bytesBefore), "An environment-mismatched plan created or modified persisted workflow evidence.");
        await ReflectTask(reopened, "LoadAsync", "qa-demo", CancellationToken.None);
        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            Set(plan, "Owner", "Cancelled mutation");
            try { await ReflectTask(reopened, "SavePlanAsync", plan, cancellation.Token); throw new InvalidOperationException("Cancelled planning changes were accepted."); }
            catch (OperationCanceledException) { }
        }
        Assert(File.ReadAllBytes(file).SequenceEqual(bytesBefore), "Cancelled planning changed the persisted file.");
        Set(plan, "Status", "Verified");
        try { await ReflectTask(reopened, "SavePlanAsync", plan, CancellationToken.None); throw new InvalidOperationException("A manually entered Verified planning status was accepted."); }
        catch (ArgumentException) { }
        Assert(File.ReadAllBytes(file).SequenceEqual(bytesBefore), "Rejected Verified planning changed the persisted file.");
        Assert(ProbeProperty<string>("AnalyticsJsonForTesting") == actualRiskBefore, "Planning metadata changed the authoritative evidence-derived risk.");
    });

    private async Task CheckVerificationSemantics() => await Check("Remediation-verification-requires-real-reassessment-evidence", () =>
    {
        var coordinator = _window.GetType().GetField("_coordinator", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(_window)!;
        var current = Get(coordinator, "Current")!;
        var snapshot = JsonSerializer.Deserialize(JsonSerializer.Serialize(current, current.GetType()), current.GetType())!;
        var findings = (System.Collections.IList)Get(snapshot, "Findings")!;
        var finding = findings[0]!;
        var planType = _desktopAssembly.GetType("Sentinel.Desktop.RemediationPlan", throwOnError: true)!;
        var verified = planType.GetMethod("IsEvidenceVerified", BindingFlags.Static | BindingFlags.NonPublic)!;
        var fixedAt = DateTimeOffset.UtcNow;
        Set(finding, "Status", Enum.Parse(finding.GetType().GetProperty("Status")!.PropertyType, "Fixed"));
        Set(finding, "FixedAt", (DateTimeOffset?)fixedAt);
        Set(finding, "LastSeen", fixedAt.AddSeconds(-2));
        Assert(!(bool)verified.Invoke(null, [snapshot, finding])!, "An operator Fixed disposition was mislabeled evidence-verified.");
        var source = (string)Get(finding, "Source")!;
        var id = (string)Get(finding, "Id")!;
        var scans = (System.Collections.IList)Get(snapshot, "Scans")!;
        var scanType = scans.GetType().GetGenericArguments()[0];
        var scan = Activator.CreateInstance(scanType)!;
        Set(scan, "EngineId", source); Set(scan, "Status", Enum.Parse(scanType.GetProperty("Status")!.PropertyType, "Completed"));
        Set(scan, "FinishedAt", (DateTimeOffset?)fixedAt.AddSeconds(1));
        scans.Add(scan);
        var changes = (System.Collections.IList)Get(snapshot, "Changes")!;
        var change = Activator.CreateInstance(changes.GetType().GetGenericArguments()[0])!;
        Set(change, "EntityId", id); Set(change, "Kind", "Resolved finding"); Set(change, "Source", source); Set(change, "At", fixedAt.AddSeconds(1));
        changes.Add(change);
        Assert(!(bool)verified.Invoke(null, [snapshot, finding])!, "A completed scan with no asset completion observations was mislabeled verified.");
        var observations = (System.Collections.IList)Get(snapshot, "Observations")!;
        var observationType = observations.GetType().GetGenericArguments()[0];
        foreach (var assetId in (IEnumerable<string>)Get(finding, "AssetIds")!)
        {
            var observation = Activator.CreateInstance(observationType)!;
            Set(observation, "AssetId", assetId); Set(observation, "EngineId", source);
            Set(observation, "Property", "AssessmentComplete"); Set(observation, "Value", "true"); Set(observation, "ObservedAt", fixedAt.AddSeconds(-1));
            observations.Add(observation);
        }
        Assert((bool)verified.Invoke(null, [snapshot, finding])!, "Matching completed reassessment, resolution event and asset completion evidence did not qualify as verified.");
        return Task.CompletedTask;
    });

    private async Task CheckRemediationWorkflow() => await Check("Remediation-real-planning-controls-persist-without-reducing-evidence-risk", async () =>
    {
        await Navigate("Remediation");
        var details = Descendants(PageRoot()).OfType<Expander>().FirstOrDefault(expander => AccessibleText(expander).Contains("Review remediation:", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The remediation workspace has no accessible action review drawer.");
        details.IsExpanded = true;
        await Flush();
        var status = FindCombo("Remediation planning status");
        status.SelectedItem = status.Items.Cast<object>().First(item => ItemText(item) == "Planned");
        FindTextBox("Remediation owner").Text = "QA defensive owner";
        FindTextBox("Remediation planning note").Text = "Plan recorded by offline installed-application acceptance; awaiting a new authorized verification assessment.";
        var riskBefore = ProbeProperty<string>("AnalyticsJsonForTesting");
        var evidenceBefore = ProbeProperty<string>("SnapshotJsonForTesting");
        InvokeButton(FindButton("Save remediation plan"));
        var workflow = _window.GetType().GetField("_workflow", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(_window)!;
        await WaitUntil(() => ((System.Collections.IEnumerable)Get(workflow, "Plans")!).Cast<object>()
            .Any(plan => (string)Get(plan, "Owner")! == "QA defensive owner" && (string)Get(plan, "Status")! == "Planned"),
            "The real remediation controls did not persist their planning state.");
        Assert(ProbeProperty<string>("SnapshotJsonForTesting") == evidenceBefore, "Planning controls changed authoritative finding evidence or disposition.");
        Assert(ProbeProperty<string>("AnalyticsJsonForTesting") == riskBefore, "Planning controls lowered evidence-derived risk before verification.");
        await Flush();
        details = Descendants(PageRoot()).OfType<Expander>().First(expander => AccessibleText(expander).Contains("Review remediation:", StringComparison.OrdinalIgnoreCase));
        details.IsExpanded = true;
        await Flush();
        Assert(AllText().Contains("Unresolved evidence", StringComparison.OrdinalIgnoreCase), "A planned action did not retain its unresolved verification state.");
        await CaptureInteraction("Remediation-planned-awaiting-evidence", "Dark");
    });

    private async Task CheckAuthorizedScopeDialog() => await Check("Authorized-scope-dialog-refuses-unconfirmed-assessment-and-renders-both-themes", async () =>
    {
        var coordinator = _window.GetType().GetField("_coordinator", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(_window)!;
        var engines = Get(coordinator, "Engines")!;
        var type = _desktopAssembly.GetType("Sentinel.Desktop.AuthorizedScopeDialog", throwOnError: true)!;
        var evidenceBefore = ProbeProperty<string>("SnapshotJsonForTesting");
        var mainRoot = _root;
        foreach (var theme in new[] { "Dark", "Light" })
        {
            Probe("ApplyThemeForTesting", theme);
            var dialog = (Window)Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null, [engines], null)!;
            dialog.Owner = _window;
            try
            {
                dialog.Show();
                _root = (FrameworkElement)dialog.Content;
                await Flush();
                var start = FindButton("Authorize and start assessment");
                InvokeButton(start);
                await Flush();
                Assert(Get(dialog, "Scope") is null, "Unconfirmed UI consent produced an authorized scan scope.");
                Assert(AllText().Contains("Confirm that you are authorized", StringComparison.OrdinalIgnoreCase), "The unconfirmed scope did not produce a readable authorization error.");
                var width = (int)Math.Ceiling(_root.ActualWidth);
                var height = (int)Math.Ceiling(_root.ActualHeight);
                var path = Path.Combine(options.EvidenceDirectory, "screenshots", "authorized-scope-" + theme.ToLowerInvariant() + ".png");
                var render = Capture(path, "Authorized scope dialog", theme, width, height, 1);
                _renders.Add(render);
                Assert(render.Errors.Count == 0, "The rendered authorization dialog has layout/accessibility errors: " + string.Join("; ", render.Errors.Take(8)));
            }
            finally { dialog.Close(); _root = mainRoot; }
        }
        Assert(ProbeProperty<string>("SnapshotJsonForTesting") == evidenceBefore, "Unauthorized dialog interaction committed assessment evidence.");
        Probe("ApplyThemeForTesting", "Dark");
    });

    private async Task CheckReadableFailure() => await Check("Desktop-readable-error-correlation-and-no-normal-stack-trace", async () =>
    {
        await Navigate("Settings");
        _window.GetType().GetMethod("ShowFailure", BindingFlags.Public | BindingFlags.Instance)!.Invoke(_window,
            [new ArgumentException("The selected authorized target is unavailable; review the exact scope and retry.")]);
        await Flush();
        var text = AllText();
        Assert(text.Contains("Event ID", StringComparison.OrdinalIgnoreCase) || text.Contains("Correlation", StringComparison.OrdinalIgnoreCase), "Readable desktop errors are missing a correlation identifier.");
        Assert(!text.Contains(" at Sentinel.", StringComparison.Ordinal) && !text.Contains("System.Reflection.RuntimeMethodInfo", StringComparison.Ordinal), "A raw stack trace was exposed in normal UI.");
        Assert(Directory.EnumerateFiles(Path.Combine(_profileDirectory, "Logs"), "*.jsonl").Any(), "The desktop did not write structured technical error evidence.");
        var dismiss = Descendants(_root).OfType<Button>().FirstOrDefault(button => AccessibleText(button).Contains("Dismiss", StringComparison.OrdinalIgnoreCase));
        if (dismiss is not null) InvokeButton(dismiss);
    });

    private async Task RenderMatrix()
    {
        (int Width, int Height)[] resolutions = options.Quick ? [(1366, 768)] : Resolutions;
        double[] scales = options.Quick ? [1d] : Scales;
        foreach (var theme in new[] { "Dark", "Light" })
        {
            Probe("ApplyThemeForTesting", theme);
            foreach (var route in Routes)
            {
                await Check($"render-{Slug(route)}-{theme}-all-required-viewports", async () =>
                {
                    await Navigate(route);
                    var viewportFailures = new List<string>();
                    foreach (var (width, height) in resolutions)
                        foreach (var scale in scales)
                        {
                            await SetViewport(width, height, scale);
                            var name = $"{Slug(route)}-{theme.ToLowerInvariant()}-{width}x{height}-effective-{scale * 100:0}pct.png";
                            var path = Path.Combine(options.EvidenceDirectory, "screenshots", name);
                            var result = Capture(path, route, theme, width, height, scale);
                            _renders.Add(result);
                            if (result.Errors.Count > 0)
                                viewportFailures.Add($"{name}: " + string.Join("; ", result.Errors.Take(8)));
                        }
                    if (viewportFailures.Count > 0) throw new InvalidOperationException(string.Join(" | ", viewportFailures));
                });
            }
        }
        await Check("render-matrix-physical-screenshot-completeness", () =>
        {
            var expected = Routes.Length * 2 * resolutions.Length * scales.Length;
            var matrixCount = _renders.Count(render => Routes.Contains(render.Route, StringComparer.Ordinal));
            Assert(matrixCount == expected, $"The actual rendering matrix is incomplete: {matrixCount}/{expected} captures.");
            Assert(_renders.All(render => File.Exists(Path.Combine(options.EvidenceDirectory, render.File.Replace('/', Path.DirectorySeparatorChar)))) , "A declared screenshot does not physically exist.");
            return Task.CompletedTask;
        });
    }

    private async Task Navigate(string route)
    {
        // Use the real accessible sidebar action so route/button selection stays covered.
        InvokeButton(FindButton(route));
        await WaitUntil(() => ProbeProperty<string>("CurrentRouteForTesting") == route, "The sidebar did not open its requested workspace.");
        await Flush();
        Assert(ProbeProperty<string>("CurrentRouteForTesting") == route, "The desktop did not select the requested real navigation route.");
        var page = _window.FindName("PageContent") as Panel;
        Assert(page is not null && page.Children.Count > 0, "The requested page rendered no content.");
    }

    private async Task SetViewport(int physicalWidth, int physicalHeight, double scale)
    {
        var width = physicalWidth / scale;
        var height = physicalHeight / scale;
        // The hosted runner's physical monitor can be only 1024x768. A normal
        // Window coerces SizeToContent to that work area and clips large bitmap
        // captures. Host the SAME production visual tree on a resizable WPF HWND
        // outside the monitor for the equivalent-DIP rendering matrix. This
        // preserves actual templates/controls/IsVisible and never duplicates UI.
        if (_renderSource is null)
        {
            _window.Content = null;
            _root.SetResourceReference(System.Windows.Documents.TextElement.ForegroundProperty, "TextBrush");
            _renderSource = new HwndSource(new HwndSourceParameters("SENTINEL rendering acceptance")
            {
                PositionX = -16000, PositionY = -16000,
                Width = (int)Math.Ceiling(width), Height = (int)Math.Ceiling(height),
                WindowStyle = unchecked((int)0x90000000) // visible popup; no work-area/chrome size coercion
            });
            _renderSource.RootVisual = _root;
        }
        var nativeScale = GetDpiForWindow(_renderSource.Handle) / 96.0;
        if (!SetWindowPos(_renderSource.Handle, IntPtr.Zero, -16000, -16000,
                (int)Math.Ceiling(width * nativeScale), (int)Math.Ceiling(height * nativeScale), 0x0014))
            throw new InvalidOperationException("The actual WPF rendering host could not resize to the requested viewport.");
        _root.Width = width;
        _root.Height = height;
        await Flush();
        _root.Measure(new Size(width, height));
        _root.Arrange(new Rect(0, 0, width, height));
        _root.UpdateLayout();
        await Flush();
        Assert(Math.Abs(_root.ActualWidth - width) < 1 && Math.Abs(_root.ActualHeight - height) < 1,
            "The production visual tree does not match the requested logical viewport.");
    }

    public void DisposeRenderingHost()
    {
        if (_renderSource is null) return;
        _renderSource.RootVisual = null;
        _renderSource.Dispose();
        _renderSource = null;
        _root.Width = _root.Height = double.NaN;
        if (_window.Content is null) _window.Content = _root;
    }

    private async Task CaptureInteraction(string name, string theme)
    {
        await Flush();
        var path = Path.Combine(options.EvidenceDirectory, "screenshots", name + ".png");
        var render = Capture(path, name, theme, (int)Math.Round(_root.ActualWidth), (int)Math.Round(_root.ActualHeight), 1);
        _renders.Add(render);
        Assert(render.Errors.Count == 0, "The actual interaction screenshot has layout/accessibility errors: " + string.Join("; ", render.Errors.Take(8)));
    }

    private RenderResult Capture(string path, string route, string theme, int physicalWidth, int physicalHeight, double scale)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var errors = new List<string>();
        var diagnostics = new List<ControlDiagnostic>();
        var bitmap = new RenderTargetBitmap(physicalWidth, physicalHeight, 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        bitmap.Render(_root);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using (var output = File.Create(path)) encoder.Save(output);
        var pixels = new byte[physicalWidth * physicalHeight * 4];
        bitmap.CopyPixels(pixels, physicalWidth * 4, 0);
        var colors = new HashSet<int>();
        var samples = 0;
        var transparentSamples = 0;
        for (var index = 0; index < pixels.Length; index += Math.Max(4, pixels.Length / 8192 / 4 * 4))
        {
            colors.Add(BitConverter.ToInt32(pixels, index));
            samples++;
            if (pixels[index + 3] < 255) transparentSamples++;
        }
        if (colors.Count < 8) errors.Add("The actual rendered screenshot is blank or lacks meaningful page content.");
        if (transparentSamples > samples / 1000)
            errors.Add($"The production visual tree did not paint the full viewport: {transparentSamples}/{samples} sampled pixels are transparent.");
        var viewport = new Rect(0, 0, physicalWidth / scale, physicalHeight / scale);
        foreach (var element in Descendants(_root).OfType<FrameworkElement>())
        {
            if (!element.IsVisible || element.ActualWidth <= 0 || element.ActualHeight <= 0) continue;
            if (element is not (TextBlock or TextBox or ComboBox or Button or DataGrid)) continue;
            Rect bounds;
            try { bounds = element.TransformToAncestor(_root).TransformBounds(new Rect(0, 0, element.ActualWidth, element.ActualHeight)); }
            catch (InvalidOperationException) { continue; }
            // Vertical scrolling is intentional. Measure only elements intersecting the current
            // viewport and account for a ScrollViewer's explicit internal clipping boundary.
            if (!bounds.IntersectsWith(viewport) || IsIntentionallyScrolledOrGraphClipped(element, bounds)) continue;
            var label = AccessibleText(element);
            var fontSize = element switch { TextBlock text => text.FontSize, Control fontControl => fontControl.FontSize, _ => 0 };
            if (element is TextBlock textBlock && !string.IsNullOrWhiteSpace(textBlock.Text) && fontSize < 12 - 0.01)
                errors.Add($"Text below the 12 DIP metadata minimum: '{Limit(textBlock.Text)}' ({fontSize:0.##} DIP).");
            if (bounds.Left < viewport.Left - 1.5 || bounds.Right > viewport.Right + 1.5)
                errors.Add($"Horizontal viewport clipping: {element.GetType().Name} '{Limit(label)}' [{bounds.Left:0.#},{bounds.Right:0.#}] vs {viewport.Width:0.#} DIP.");
            var control = element as Control;
            if (control is Button or TextBox or ComboBox && control.IsEnabled && string.IsNullOrWhiteSpace(label))
                errors.Add($"Interactive {control.GetType().Name} is missing an accessible label.");
            double? contrast = null;
            if (element is TextBlock contrastText && contrastText.IsEnabled && !string.IsNullOrWhiteSpace(contrastText.Text) &&
                contrastText.Foreground is SolidColorBrush foreground && foreground.Color.A == 255 && foreground.Opacity >= .999 &&
                NearestBackground(contrastText) is Color background)
            {
                var a = Luminance(foreground.Color);
                var b = Luminance(background);
                contrast = (Math.Max(a, b) + .05) / (Math.Min(a, b) + .05);
                var minimum = contrastText.FontSize >= 24 || (contrastText.FontSize >= 18.66 && contrastText.FontWeight.ToOpenTypeWeight() >= 600) ? 3 : 4.5;
                if (contrast < minimum - .02) errors.Add($"Rendered text contrast below {minimum:0.#}:1: '{Limit(contrastText.Text)}' ({contrast:0.##}:1).");
            }
            diagnostics.Add(new(element.GetType().Name, Limit(label), bounds.X, bounds.Y, bounds.Width, bounds.Height, fontSize,
                AutomationProperties.GetAutomationId(element), element.IsKeyboardFocused, contrast));
        }
        if (diagnostics.Count < 15)
            errors.Add("The rendering host exposes too few visible production controls for meaningful UI acceptance.");
        return new(route, theme, physicalWidth, physicalHeight, scale,
            "actual-production-WPF-visual-tree; simulated-effective-display-scaling; native window DPI recorded separately",
            physicalWidth / scale, physicalHeight / scale,
            Path.GetRelativePath(options.EvidenceDirectory, path).Replace('\\', '/'), new FileInfo(path).Length,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant(), diagnostics, errors.Distinct().ToArray());
    }

    private static bool IsIntentionallyScrolledOrGraphClipped(FrameworkElement element, Rect bounds)
    {
        DependencyObject? ancestor = VisualTreeHelper.GetParent(element);
        while (ancestor is not null)
        {
            if (ancestor.GetType().Name.Contains("Graph", StringComparison.Ordinal)) return true;
            if (ancestor is DataGrid && element is not DataGrid) return true;
            // Content inside an explicit horizontal scroll region may extend beyond its
            // viewport; that is accessible through the scrollbar and is not shell overlap.
            if (ancestor is ScrollViewer viewer && viewer.HorizontalScrollBarVisibility is ScrollBarVisibility.Auto or ScrollBarVisibility.Visible) return true;
            ancestor = VisualTreeHelper.GetParent(ancestor);
        }
        return false;
    }

    private DataGrid FirstGrid() => Descendants(PageRoot()).OfType<DataGrid>().FirstOrDefault()
        ?? throw new InvalidOperationException("The current workspace does not contain its actual data table.");

    private async Task SelectTab(string label)
    {
        var tab = Descendants(PageRoot()).OfType<TabItem>().FirstOrDefault(item => ItemText(item.Header ?? "").Equals(label, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The detail workspace is missing its real tab: " + label);
        tab.IsSelected = true;
        await Flush();
    }

    private TextBox FindTextBox(params string[] labels)
        => FindControl<TextBox>(labels) ?? throw new InvalidOperationException("Text input missing: " + string.Join(" / ", labels));

    private ComboBox FindCombo(params string[] labels)
        => FindControl<ComboBox>(labels) ?? throw new InvalidOperationException("Selection control missing: " + string.Join(" / ", labels));

    private T? FindControl<T>(IEnumerable<string> labels) where T : FrameworkElement
    {
        var controls = Descendants(PageRoot()).OfType<T>().ToList();
        foreach (var label in labels)
        {
            var control = controls.FirstOrDefault(item => AccessibleText(item).Contains(label, StringComparison.OrdinalIgnoreCase)
                || item.Name.Contains(label.Replace(" ", ""), StringComparison.OrdinalIgnoreCase));
            if (control is not null) return control;
        }
        return null;
    }

    private Button FindButton(params string[] labels)
    {
        var buttons = Descendants(_root).OfType<Button>().Where(button => button.IsVisible).ToList();
        foreach (var label in labels)
        {
            var exact = buttons.FirstOrDefault(button => AccessibleText(button).Equals(label, StringComparison.OrdinalIgnoreCase));
            if (exact is not null) return exact;
        }
        foreach (var label in labels)
        {
            var contains = buttons.FirstOrDefault(button => AccessibleText(button).Contains(label, StringComparison.OrdinalIgnoreCase));
            if (contains is not null) return contains;
        }
        throw new InvalidOperationException("Action control missing: " + string.Join(" / ", labels));
    }

    private static void InvokeButton(Button button)
    {
        Assert(button.IsEnabled, "The selected real application action is disabled: " + AccessibleText(button));
        button.Focus();
        var peer = UIElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button);
        if (peer.GetPattern(PatternInterface.Invoke) is IInvokeProvider invoke) invoke.Invoke();
        else button.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent, button));
    }

    private DependencyObject PageRoot() => _window.FindName("PageContent") as DependencyObject ?? _root;
    private string AllText() => string.Join("\n", Descendants(_root).OfType<TextBlock>().Where(text => text.IsVisible).Select(text => text.Text)
        .Concat(Descendants(_root).OfType<ContentControl>().Where(control => control.IsVisible && control.Content is string).Select(control => (string)control.Content)));

    private static string AccessibleText(FrameworkElement element)
    {
        var name = AutomationProperties.GetName(element);
        if (!string.IsNullOrWhiteSpace(name)) return name;
        if (AutomationProperties.GetLabeledBy(element) is FrameworkElement label && !ReferenceEquals(label, element))
        {
            var labelText = AccessibleText(label);
            if (!string.IsNullOrWhiteSpace(labelText)) return labelText;
        }
        if (element is TextBlock text) return text.Text;
        if (element is ContentControl content)
        {
            if (content.Content is string value) return value;
            if (content.Content is DependencyObject child) return string.Join(" ", Descendants(child).OfType<TextBlock>().Select(block => block.Text));
        }
        if (element.ToolTip is string tooltip) return tooltip;
        return element.Name;
    }

    private static string ItemText(object item) => item is ContentControl control ? control.Content?.ToString() ?? "" : item.ToString() ?? "";
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        yield return parent;
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
            foreach (var child in Descendants(VisualTreeHelper.GetChild(parent, index))) yield return child;
    }

    private object? Probe(string name, params object[] arguments)
    {
        var method = _window.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new MissingMethodException("The production desktop acceptance probe is unavailable: " + name);
        try { return method.Invoke(_window, arguments); }
        catch (TargetInvocationException exception) when (exception.InnerException is not null) { throw exception.InnerException; }
    }
    private async Task<object?> ProbeAsync(string name, params object[] arguments)
    {
        var task = Probe(name, arguments) as Task ?? throw new InvalidOperationException("The acceptance probe did not return a task: " + name);
        await task;
        return task.GetType().GetProperty("Result")?.GetValue(task);
    }
    private static object? Reflect(object target, string method, params object[] arguments)
    {
        var info = target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
        var parameters = info.GetParameters();
        if (arguments.Length < parameters.Length)
        {
            if (parameters.Skip(arguments.Length).Any(parameter => !parameter.HasDefaultValue))
                throw new ArgumentException("Required reflection test argument missing: " + method);
            arguments = arguments.Concat(parameters.Skip(arguments.Length).Select(parameter => parameter.DefaultValue!)).ToArray();
        }
        try { return info.Invoke(target, arguments); }
        catch (TargetInvocationException exception) when (exception.InnerException is not null) { throw exception.InnerException; }
    }
    private static async Task ReflectTask(object target, string method, params object[] arguments)
        => await (Task)Reflect(target, method, arguments)!;
    private static object? Get(object target, string property) => target.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.GetValue(target);
    private static void Set(object target, string property, object? value) => target.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.SetValue(target, value);
    private T ProbeProperty<T>(string name) => (T)(_window.GetType().GetProperty(name, BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(_window)
        ?? throw new MissingMemberException("The production desktop acceptance probe is unavailable: " + name));
    private JsonElement ParseProbe(string name)
    {
        using var document = JsonDocument.Parse(ProbeProperty<string>(name));
        return document.RootElement.Clone();
    }
    private static async Task Flush()
    {
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }
    private static Task WaitUntil(Func<bool> condition, string failure) => WaitUntil(() => Task.FromResult(condition()), failure);
    private static async Task WaitUntil(Func<Task<bool>> condition, string failure)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(20);
        while (!await condition())
        {
            if (DateTimeOffset.UtcNow >= deadline) throw new TimeoutException(failure);
            await Task.Delay(25);
        }
        await Flush();
    }

    private async Task Check(string name, Func<Task> operation)
    {
        var elapsed = Stopwatch.StartNew();
        try
        {
            await operation();
            _checks.Add(new(name, "passed", "", elapsed.ElapsedMilliseconds));
            Console.WriteLine("PASS " + name);
        }
        catch (Exception exception)
        {
            _checks.Add(new(name, "failed", exception.GetType().Name + ": " + exception.Message, elapsed.ElapsedMilliseconds));
            Console.Error.WriteLine("FAIL " + name + ": " + exception.Message);
        }
    }

    public void RecordDispatcherFailure(Exception exception)
    {
        _dispatcherFailures.Add(exception.GetType().Name + ": " + exception.Message);
        Console.Error.WriteLine("FAIL WPF dispatcher: " + exception.Message);
    }
    public void RecordFatalFailure(Exception exception)
        => _checks.Add(new("desktop-acceptance-fatal", "failed", exception.GetType().Name + ": " + exception.Message, _elapsed.ElapsedMilliseconds));

    public void WriteResults()
    {
        Directory.CreateDirectory(options.EvidenceDirectory);
        var result = new
        {
            product = "SENTINEL Enterprise V1.1",
            status = Failed ? "failed" : "passed",
            atUtc = DateTimeOffset.UtcNow,
            elapsedMilliseconds = _elapsed.ElapsedMilliseconds,
            desktopAssembly = Path.Combine(options.DesktopDirectory, "Sentinel.Desktop.dll"),
            desktopAssemblySha256 = _assemblyHash,
            isolatedOperatorProfile = _profileDirectory,
            nativeWindowDpi = _nativeDpi,
            scalingMethod = "Actual WPF production controls rendered at physical-pixel resolution from an effective DIP viewport; simulated 100/125/150% scaling, not an OS display-setting change.",
            quick = options.Quick,
            passed = _checks.Count(check => check.Status == "passed"),
            failed = _checks.Count(check => check.Status == "failed"),
            skipped = Array.Empty<string>(),
            checks = _checks,
            dispatcherFailures = _dispatcherFailures,
            renders = _renders,
            acceptanceLimitations = new[]
            {
                "Physical monitor DPI and Windows display-setting changes need separate manual acceptance.",
                "The report native SaveFileDialog is not automated; the actual installed coordinator exports are exercised.",
                "No live organizational network, credentials, or external AI provider is contacted by this offline harness."
            }
        };
        File.WriteAllText(Path.Combine(options.EvidenceDirectory, "verification-results.json"), JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        File.WriteAllText(Path.Combine(options.EvidenceDirectory, "README.txt"),
            "SENTINEL Enterprise V1.1 real installed-assembly WPF acceptance evidence.\n" +
            "Inspect the screenshots beside verification-results.json. Every image was rendered from production WPF controls using real offline Demo evidence.\n" +
            "The effective scaling matrix simulates logical viewport sizing and pixel density; nativeWindowDpi records the actual host window DPI separately.\n" +
            "A passed automated geometry check does not replace visual inspection of PNGs or physical-monitor acceptance.\n");
        Console.WriteLine($"SENTINEL desktop QA: {_checks.Count(check => check.Status == "passed")} passed, {_checks.Count(check => check.Status == "failed")} failed, {_renders.Count} real PNG captures.");
        Console.WriteLine("Evidence: " + options.EvidenceDirectory);
    }

    private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static string Slug(string value) => value.Replace(' ', '-').ToLowerInvariant();
    private static string Limit(string value) => value.Length > 90 ? value[..87] + "..." : value;
    private static double Luminance(Color color)
    {
        static double Channel(byte channel) { var value = channel / 255d; return value <= .04045 ? value / 12.92 : Math.Pow((value + .055) / 1.055, 2.4); }
        return .2126 * Channel(color.R) + .7152 * Channel(color.G) + .0722 * Channel(color.B);
    }
    private static Color? NearestBackground(DependencyObject element)
    {
        for (DependencyObject? ancestor = element; ancestor is not null; ancestor = VisualTreeHelper.GetParent(ancestor))
        {
            var brush = ancestor switch { Border border => border.Background, Panel panel => panel.Background, Control control => control.Background, _ => null };
            if (brush is SolidColorBrush solid && solid.Color.A == 255 && solid.Opacity >= .999) return solid.Color;
        }
        return Application.Current.Resources["BackgroundBrush"] is SolidColorBrush fallback ? fallback.Color : null;
    }
    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(IntPtr window, IntPtr insertAfter, int x, int y, int width, int height, uint flags);
}

internal sealed record CheckResult(string Name, string Status, string Details, long ElapsedMilliseconds);
internal sealed record ControlDiagnostic(string Type, string Label, double X, double Y, double Width, double Height, double FontSize, string AutomationId, bool KeyboardFocused, double? ContrastRatio);
internal sealed record RenderResult(string Route, string Theme, int PixelWidth, int PixelHeight, double EffectiveScale,
    string ScalingEvidence, double LogicalWidth, double LogicalHeight, string File, long Bytes, string Sha256,
    IReadOnlyList<ControlDiagnostic> Controls, IReadOnlyList<string> Errors);
