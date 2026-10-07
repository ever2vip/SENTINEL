using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using Sentinel.Core;

namespace Sentinel.Desktop;

public partial class MainWindow
{
    private void BuildNavigation()
    {
        (string Group, string[] Pages)[] groups = [
            ("OBSERVE", ["Command Center", "Assets", "Network", "Endpoints"]),
            ("EXPOSURE", ["Vulnerabilities", "Identity", "Active Directory", "Cloud", "Web Security", "Attack Surface"]),
            ("ANALYZE", ["Attack Paths", "Evidence Graph", "Compliance"]),
            ("RESPOND", ["Monitoring", "Incidents", "Remediation"]),
            ("INTELLIGENCE", ["Reports", "AI Analyst"]),
            ("SYSTEM", ["Integrations", "Settings"])
        ];
        foreach (var (group, pages) in groups)
        {
            var label = Ui.Text(group, 12, "MutedBrush", true);
            label.Margin = new Thickness(4, 8, 0, 4);
            var routes = new StackPanel();
            var expander = new Expander { Header = label, Content = routes, IsExpanded = true, Margin = new Thickness(0, 0, 0, 8) };
            AutomationProperties.SetName(expander, group + " navigation group");
            _navigationGroups.Add((label, expander));
            foreach (var route in pages)
            {
                var button = Ui.Button(route, () => { if (_initialized && _coordinator.Current is not null && !_busy) Navigate(route); });
                var row = new StackPanel { Orientation = Orientation.Horizontal };
                var icon = Ui.Icon(route, 18, "MutedBrush");
                icon.Margin = new Thickness(0, 0, 12, 0);
                row.Children.Add(icon);
                row.Children.Add(new TextBlock { Text = route, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
                button.Content = row;
                button.ToolTip = route;
                button.HorizontalContentAlignment = HorizontalAlignment.Left;
                button.Margin = new Thickness(0, 2, 0, 2);
                button.Padding = new Thickness(12, 10, 8, 10);
                button.Tag = route;
                button.Style = (Style)Application.Current.FindResource("NavigationButton");
                AutomationProperties.SetName(button, route);
                _navigationButtons.Add(route, button);
                routes.Children.Add(button);
            }
            Navigation.Children.Add(expander);
        }
    }

    private void ToggleNavigation_Click(object sender, RoutedEventArgs e)
    {
        _manualCompact = !_compactNavigation;
        ApplyNavigationLayout();
    }

    private void ApplyNavigationLayout()
    {
        _compactNavigation = _manualCompact || ShellRoot.ActualWidth < 1160;
        SidebarColumn.Width = new GridLength(_compactNavigation ? 76 : 248);
        BrandLabel.Visibility = CompactNavigationLabel.Visibility = VersionLabel.Visibility = _compactNavigation ? Visibility.Collapsed : Visibility.Visible;
        foreach (var (label, group) in _navigationGroups)
        {
            label.Visibility = _compactNavigation ? Visibility.Collapsed : Visibility.Visible;
            if (_compactNavigation) group.IsExpanded = true;
        }
        foreach (var button in _navigationButtons.Values)
            if (button.Content is StackPanel row)
            {
                row.Children[1].Visibility = _compactNavigation ? Visibility.Collapsed : Visibility.Visible;
                ((FrameworkElement)row.Children[0]).Margin = _compactNavigation ? new Thickness(0) : new Thickness(0, 0, 12, 0);
            }
        AssessmentContext.Visibility = ShellRoot.ActualWidth < 1100 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void Notifications_Click(object sender, RoutedEventArgs e) => Navigate("Monitoring");
    private void Settings_Click(object sender, RoutedEventArgs e) => Navigate("Settings");

    private void OpenAsset(string id)
    {
        var asset = Snapshot.Assets.FirstOrDefault(a => a.Id == id);
        if (asset is null) { ShowNotice("Asset unavailable", "The referenced asset is not in the current environment."); return; }
        Navigate("Assets");
        PageContent.Children.Clear();
        PageTitle.Text = asset.Name;
        PageContent.Children.Add(Ui.Button("Back to assets", () => Navigate("Assets")));
        PageContent.Children.Add(AssetDetail(asset));
        PageScroll.ScrollToTop();
    }

    private void OpenFinding(string id)
    {
        var finding = Snapshot.Findings.FirstOrDefault(f => f.Id == id);
        if (finding is null) { ShowNotice("Finding unavailable", "The referenced finding is not in the current environment."); return; }
        Navigate("Vulnerabilities");
        PageContent.Children.Clear();
        PageTitle.Text = "Finding workspace";
        PageContent.Children.Add(Ui.Button("Back to findings", () => Navigate("Vulnerabilities")));
        PageContent.Children.Add(FindingDetail(finding));
        PageScroll.ScrollToTop();
    }

    private void OpenEvidence(string id)
    {
        Navigate("Evidence Graph");
        foreach (var graph in PageContent.Children.OfType<EvidenceGraphView>()) graph.FocusNode(id);
    }

    private void OpenPathGraph(AttackPath path)
    {
        Navigate("Evidence Graph");
        foreach (var graph in PageContent.Children.OfType<EvidenceGraphView>()) graph.HighlightPath(path);
    }

    private void ReviewPath(AttackPath path)
    {
        Navigate("Remediation");
        PageContent.Children.Clear();
        PageTitle.Text = "Break this path";
        PageSubtitle.Text = "A defensive plan supported by collected relationships.";
        PageContent.Children.Add(Ui.Button("Back to remediation", () => Navigate("Remediation")));
        var pathView = new AttackPathView(Snapshot, path, OpenAsset, OpenFinding, null, OpenPathGraph, false, _coordinator.Remediations, _coordinator.Risk);
        pathView.ShowBreakWorkspace();
        PageContent.Children.Add(Ui.Card(pathView));
        var related = _coordinator.Remediations.Where(a => a.FindingIds.Intersect(path.FindingIds).Any()).ToList();
        foreach (var action in related) PageContent.Children.Add(Ui.Card(ActionSummary(action)));
        PageContent.Children.Add(Ui.Button("Open full remediation workflow", () => Navigate("Remediation"), true));
    }
}
