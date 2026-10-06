using System.Windows;
using System.Windows.Controls;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Desktop;

internal sealed class AuthorizedScopeDialog : Window
{
    public ScanScope? Scope { get; private set; }
    public string EngineId { get; private set; } = "";

    public AuthorizedScopeDialog(IReadOnlyList<EngineDescriptor> engines)
    {
        Title = "SENTINEL · Authorize assessment scope";
        Width = 800; Height = 840; MinHeight = 700; MinWidth = 650; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var available = engines.Where(e => e.IsAvailable).ToArray();
        var engine = new ComboBox { ItemsSource = available, DisplayMemberPath = "Name", SelectedIndex = available.Length == 0 ? -1 : 0, MinWidth = 300 };
        var description = Ui.Text(available.FirstOrDefault()?.Description ?? "No local engines are available.", 13, "MutedBrush");
        engine.SelectionChanged += (_, _) => description.Text = (engine.SelectedItem as EngineDescriptor)?.Description ?? "Select an available engine.";
        var hosts = Ui.Input(); hosts.AcceptsReturn = true; hosts.Height = 95; hosts.VerticalScrollBarVisibility = ScrollBarVisibility.Auto; hosts.ToolTip = "Exact authorized IP addresses, hostnames, or email domains. One per line. No CIDRs or wildcards.";
        var urls = Ui.Input(); urls.AcceptsReturn = true; urls.Height = 90; urls.VerticalScrollBarVisibility = ScrollBarVisibility.Auto; urls.ToolTip = "Exact authorized https:// URLs. One per line. Redirects do not expand authorized scope.";
        var ports = Ui.Input("22,80,443,3389", 270);
        ports.ToolTip = "Supported defensive posture ports: " + string.Join(", ", ScopeGuard.AllowedPorts.Order());
        var timeout = Ui.Input("5", 100);
        var local = new CheckBox { Content = "Include this computer for the local endpoint engine" };
        var operatorName = Ui.Input(Environment.UserName);
        var authorized = new CheckBox { Content = new TextBlock { Text = "I own these exact targets or have explicit authorization to assess them, and I authorize this non-destructive assessment.", TextWrapping = TextWrapping.Wrap, MaxWidth = 650 } };
        var error = Ui.Text("", 13, "CriticalBrush");
        var start = Ui.Button("Authorize and start assessment", () =>
        {
            try
            {
                if (engine.SelectedItem is not EngineDescriptor selected) throw new ArgumentException("Select an available assessment engine.");
                if (authorized.IsChecked != true) throw new ArgumentException("Confirm that you are authorized to assess every target in this scope.");
                if (string.IsNullOrWhiteSpace(operatorName.Text)) throw new ArgumentException("Record the authorizing operator name.");
                var hostList = SplitLines(hosts.Text);
                var urlList = SplitLines(urls.Text);
                if (hostList.Count > 128 || urlList.Count > 64) throw new ArgumentException("Limit one assessment to 128 exact hosts and 64 web properties.");
                if (hostList.Any(h => h.Contains('*') || h.Contains('/') || h.Contains(' ') || h.Length > 253)) throw new ArgumentException("Hosts must be exact hostnames or IP addresses. CIDRs, wildcards, URLs, and embedded spaces are not permitted.");
                foreach (var value in urlList) if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo)) throw new ArgumentException("Web properties must be exact HTTP or HTTPS URLs without embedded credentials.");
                var portList = ports.Text.Split([',', ' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(v => int.TryParse(v, out var port) ? port : -1).Distinct().ToList();
                if (portList.Count == 0 || portList.Count > 32 || portList.Any(p => p < 1 || p > 65535)) throw new ArgumentException("Specify 1–32 authorized TCP ports, each between 1 and 65535.");
                if (!int.TryParse(timeout.Text, out var seconds) || seconds < 1 || seconds > 30) throw new ArgumentException("Target timeout must be between 1 and 30 seconds.");
                if (hostList.Count == 0 && urlList.Count == 0 && local.IsChecked != true) throw new ArgumentException("Specify exact targets or include this computer for local endpoint assessment.");
                Scope = new ScanScope { Hosts = hostList, WebUrls = urlList, Ports = portList, TimeoutSeconds = seconds, MaxConcurrency = 8, IncludeLocalEndpoint = local.IsChecked == true, AuthorizationConfirmed = true, AuthorizedBy = operatorName.Text.Trim(), AuthorizedAt = DateTimeOffset.UtcNow };
                ScopeGuard.Validate(Scope);
                EngineId = selected.Id;
                DialogResult = true;
            }
            catch (ArgumentException ex) { error.Text = ex.Message; }
        }, true);
        var cancel = Ui.Button("Cancel", () => DialogResult = false);
        var panel = Ui.Stack(Ui.Text("Define the boundary. Record authorization.", 26, bold: true), Ui.Text("The assessment contacts only the exact targets below using the selected defensive engine. No autonomous discovery, credentials, exploitation, or remediation execution is enabled.", 14, "MutedBrush"), Ui.Text("Assessment engine", 14, bold: true), engine, description, Ui.Text("Exact hosts / IP addresses / email domains · one per line", 14, bold: true), hosts, Ui.Text("Authorized web URLs · one per line", 14, bold: true), urls, Ui.Row(Ui.Stack(Ui.Text("Authorized TCP ports", 12, "MutedBrush"), ports), Ui.Stack(Ui.Text("Timeout seconds", 12, "MutedBrush"), timeout)), local, Ui.Text("Authorizing operator", 14, bold: true), operatorName, authorized, Ui.Text("The saved audit entry records engine, exact scope, operator, time, and event ID. You can cancel safely at any time. Scope validation may reject malformed or unavailable targets before contact.", 12, "MutedBrush"), error, Ui.Row(start, cancel));
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(28) };
    }

    private static List<string> SplitLines(string text) => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
