using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.Core;

namespace Sentinel.Desktop;

/// <summary>Visualizes a known defensive evidence chain; it performs no assessment or path execution.</summary>
internal sealed class AttackPathView : StackPanel
{
    private readonly EnvironmentSnapshot _snapshot;
    private readonly AttackPath _path;
    private readonly Action<string>? _openAsset;
    private readonly Action<string>? _openFinding;
    private readonly Action<AttackPath>? _reviewRemediation;
    private readonly Action<AttackPath>? _openGraph;
    private readonly IReadOnlyList<RemediationAction> _remediations;
    private readonly RiskAssessment? _risk;
    private readonly Dictionary<string, EvidenceNode> _nodes;
    private readonly Dictionary<string, EvidenceEdge> _edges;
    private readonly StackPanel _flow = new();
    private readonly StackPanel _inspector = new();
    private readonly StackPanel _breakWorkspace = new() { Visibility = Visibility.Collapsed };
    private readonly Border _flowFrame;
    private readonly bool _compact;
    private bool _horizontal;

    public AttackPathView(EnvironmentSnapshot snapshot, AttackPath path,
        Action<string>? openAsset = null, Action<string>? openFinding = null,
        Action<AttackPath>? reviewRemediation = null, Action<AttackPath>? openGraph = null,
        bool compact = false, IReadOnlyList<RemediationAction>? remediations = null,
        RiskAssessment? risk = null)
    {
        _snapshot = snapshot;
        _path = path;
        _openAsset = openAsset;
        _openFinding = openFinding;
        _reviewRemediation = reviewRemediation;
        _openGraph = openGraph;
        _remediations = remediations ?? [];
        _risk = risk;
        _compact = compact;
        _horizontal = compact;
        _nodes = snapshot.Nodes.GroupBy(n => n.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        _edges = snapshot.Edges.GroupBy(e => e.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var target = snapshot.Assets.FirstOrDefault(a => a.Id == path.CriticalAssetId);
        var dependencies = snapshot.Findings.Where(f => path.FindingIds.Contains(f.Id, StringComparer.Ordinal)).ToList();
        var severity = dependencies.Count == 0 ? Severity.Informational : dependencies.Max(f => f.Severity);
        var title = Ui.Text(path.Title, compact ? 17 : 20, bold: true);
        title.Margin = new Thickness(0, 0, 0, 12);
        Children.Add(title);
        var metrics = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        metrics.Children.Add(Ui.Badge($"Path risk {path.Risk:0.0} / 100", "AccentBrush"));
        if (dependencies.Count > 0) metrics.Children.Add(Ui.Badge(severity + " finding dependency", EvidenceNodePresentation.SeverityColor(severity)));
        metrics.Children.Add(Ui.Badge($"Confidence {path.Confidence:P0}", "AccentBrush"));
        metrics.Children.Add(Ui.Badge($"{path.EdgeIds.Count} steps", "MutedBrush"));
        if (target is not null) metrics.Children.Add(Ui.Badge("Critical target · " + target.Name, "HighBrush"));
        Children.Add(metrics);
        UIElement flowContent = compact ? new ScrollViewer { Content = _flow, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled } : _flow;
        _flowFrame = new Border { Child = flowContent, CornerRadius = new CornerRadius(10), Padding = new Thickness(12), BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 0, 12) };
        _flowFrame.SetResourceReference(Border.BackgroundProperty, "BackgroundBrush");
        _flowFrame.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        Children.Add(_flowFrame);
        var source = path.NodeIds.Count > 0 && _nodes.TryGetValue(path.NodeIds[0], out var start) ? start.Label : "Exposure source unavailable";
        Children.Add(Ui.Text("Exposure source: " + source, 12, "MutedBrush"));
        var actions = new WrapPanel { Margin = new Thickness(0, 4, 0, 8) };
        var breakButton = Ui.Button("BREAK THIS PATH", () =>
        {
            _breakWorkspace.Visibility = Visibility.Visible;
            if (_reviewRemediation is not null) _reviewRemediation(path);
        }, true);
        AutomationProperties.SetAutomationId(breakButton, "AttackPathBreak:" + path.Id);
        AutomationProperties.SetName(breakButton, "BREAK THIS PATH");
        breakButton.ToolTip = "Review defensive remediation and its evidence. No attack path is executed.";
        actions.Children.Add(breakButton);
        if (_openGraph is not null)
        {
            var graphButton = Ui.Button("Highlight in Evidence Graph", () => _openGraph(path));
            AutomationProperties.SetAutomationId(graphButton, "AttackPathGraph:" + path.Id);
            actions.Children.Add(graphButton);
        }
        if (target is not null && _openAsset is not null) actions.Children.Add(Ui.Button("Open critical target", () => _openAsset(target.Id)));
        Children.Add(actions);
        Children.Add(_inspector);
        BuildBreakWorkspace();
        Children.Add(_breakWorkspace);
        if (!compact) Children.Add(Ui.Text("Defensive analysis only. These relationships are known evidence; the path is an interpretation of that evidence. It does not establish exploit success.", 12, "MutedBrush"));
        SizeChanged += (_, _) =>
        {
            var horizontal = _compact || ActualWidth >= Math.Max(850, path.NodeIds.Count * 208 + 24);
            if (_horizontal != horizontal) { _horizontal = horizontal; DrawFlow(); }
        };
        DrawFlow();
    }

    public void ShowBreakWorkspace() => _breakWorkspace.Visibility = Visibility.Visible;

    private void DrawFlow()
    {
        _flow.Children.Clear();
        _flow.Orientation = _horizontal ? Orientation.Horizontal : Orientation.Vertical;
        var count = _compact ? Math.Min(_path.NodeIds.Count, 8) : _path.NodeIds.Count;
        for (var i = 0; i < count; i++)
        {
            var id = _path.NodeIds[i];
            if (_nodes.TryGetValue(id, out var node))
            {
                var button = NodeButton(node, i == count - 1 && id == _path.NodeIds[^1]);
                _flow.Children.Add(button);
            }
            else _flow.Children.Add(Ui.Text("Evidence node unavailable: " + id, 14, "MutedBrush"));
            if (i < count - 1)
            {
                var edge = i < _path.EdgeIds.Count && _edges.TryGetValue(_path.EdgeIds[i], out var recorded) ? recorded : null;
                _flow.Children.Add(Connector(edge, _horizontal));
            }
        }
        if (count < _path.NodeIds.Count) _flow.Children.Add(Ui.Text($"{_path.NodeIds.Count - count} more recorded nodes · open full path to inspect", 12, "MutedBrush"));
    }

    private Button NodeButton(EvidenceNode node, bool criticalTarget)
    {
        var button = Ui.Button("", () => InspectNode(node));
        button.Padding = new Thickness(12);
        button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
        button.Margin = new Thickness(0);
        if (_horizontal) { button.Width = 176; button.MinHeight = 108; }
        else { button.MinHeight = _compact ? 64 : 76; button.HorizontalAlignment = HorizontalAlignment.Stretch; }
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(36) });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        var icon = Ui.Icon(EvidenceNodePresentation.Icon(node.Kind), 26, EvidenceNodePresentation.Color(node.Kind));
        icon.VerticalAlignment = VerticalAlignment.Center;
        grid.Children.Add(icon);
        var text = Ui.Stack(Ui.Text(EvidenceNodePresentation.Label(node.Kind), 12, EvidenceNodePresentation.Color(node.Kind)), Ui.Text(node.Label, 14, bold: true));
        if (criticalTarget) text.Children.Add(Ui.Text("Business critical target", 12, "HighBrush"));
        Grid.SetColumn(text, 1);
        grid.Children.Add(text);
        button.Content = grid;
        if (criticalTarget) button.SetResourceReference(Control.BorderBrushProperty, "HighBrush");
        button.ToolTip = $"{node.Label}\n{node.Source}\nConfidence {node.Confidence:P0}\nSelect to inspect evidence and related records.";
        AutomationProperties.SetAutomationId(button, "AttackPathNode:" + node.Id);
        AutomationProperties.SetName(button, EvidenceNodePresentation.Label(node.Kind) + ": " + node.Label);
        return button;
    }

    private FrameworkElement Connector(EvidenceEdge? edge, bool horizontal)
    {
        var panel = new StackPanel { Orientation = horizontal ? Orientation.Vertical : Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = horizontal ? HorizontalAlignment.Center : HorizontalAlignment.Left, Margin = horizontal ? new Thickness(4, 0, 4, 0) : new Thickness(14, 6, 0, 6) };
        var arrow = new System.Windows.Shapes.Path
        {
            Data = Geometry.Parse(horizontal ? "M0,10 L26,10 M19,3 L26,10 L19,17" : "M10,0 L10,24 M3,17 L10,24 L17,17"),
            Width = horizontal ? 24 : 18,
            Height = horizontal ? 18 : 24,
            Stretch = Stretch.Uniform,
            StrokeThickness = 1.8,
            Margin = horizontal ? new Thickness(0) : new Thickness(0, 0, 10, 0)
        };
        arrow.SetResourceReference(Shape.StrokeProperty, "HighBrush");
        panel.Children.Add(arrow);
        var description = Ui.Text(edge?.Relationship ?? "Relationship unavailable", 12, "MutedBrush");
        description.Margin = new Thickness(0);
        if (horizontal) { description.MaxWidth = 64; description.Visibility = Visibility.Collapsed; }
        panel.Children.Add(description);
        panel.ToolTip = edge is null ? "The referenced relationship is unavailable." : $"{edge.Relationship}\nConfidence {edge.Confidence:P0}\nRelationship ID: {edge.Id}";
        if (edge is not null) AutomationProperties.SetAutomationId(panel, "AttackPathEdge:" + edge.Id);
        return panel;
    }

    private void InspectNode(EvidenceNode node)
    {
        _inspector.Children.Clear();
        var content = Ui.Stack(Ui.Text(node.Label, 17, bold: true), Ui.Text($"{EvidenceNodePresentation.Label(node.Kind)} · confidence {node.Confidence:P0}\nSource: {node.Source}\nObserved: {node.ObservedAt.LocalDateTime:g}", 13, "MutedBrush"));
        var assetId = node.Properties.GetValueOrDefault("assetId", node.Id);
        var asset = _snapshot.Assets.FirstOrDefault(a => a.Id == assetId);
        if (asset is not null && _openAsset is not null) content.Children.Add(Ui.Button("Open asset · " + asset.Name, () => _openAsset(asset.Id)));
        var findingIds = _snapshot.Edges.Where(e => _path.EdgeIds.Contains(e.Id, StringComparer.Ordinal) && (e.SourceId == node.Id || e.TargetId == node.Id)).SelectMany(e => e.FindingIds).ToHashSet(StringComparer.Ordinal);
        foreach (var finding in _snapshot.Findings.Where(f => findingIds.Contains(f.Id)))
            content.Children.Add(_openFinding is null ? Ui.Text(finding.Title, 14) : Ui.Button(finding.Severity + " · " + finding.Title, () => _openFinding(finding.Id)));
        _inspector.Children.Add(Ui.Card(content, 16));
    }

    private void BuildBreakWorkspace()
    {
        _breakWorkspace.Children.Add(Ui.Text("Recommended defensive break point", 18, bold: true));
        _breakWorkspace.Children.Add(Ui.Text(_path.BreakPoint, 16, "AccentBrush", true));
        _breakWorkspace.Children.Add(Ui.Text(_path.RecommendedAction, 14));
        var routeEdges = _path.EdgeIds.Where(_edges.ContainsKey).Select(id => _edges[id]).ToList();
        // Use the same monotonic severity ordering and earliest-step tie break as
        // AttackPathEngine. Display labels need not be unique evidence identifiers.
        var selected = routeEdges.Where(e => !string.IsNullOrWhiteSpace(e.DefensiveBreak))
            .OrderByDescending(e => _snapshot.Findings.Where(f => e.FindingIds.Contains(f.Id, StringComparer.Ordinal)).Select(f => (int)f.Severity).DefaultIfEmpty(0).Max())
            .ThenBy(e => routeEdges.IndexOf(e)).FirstOrDefault() ?? routeEdges.FirstOrDefault();
        _breakWorkspace.Children.Add(Ui.Text("Why this point was selected", 16, bold: true));
        _breakWorkspace.Children.Add(Ui.Text(selected is not null && !string.IsNullOrWhiteSpace(selected.DefensiveBreak)
            ? "The current path engine prioritizes a recorded defensive break on the relationship with the highest severity supporting finding; earlier steps break ties. This is a modeled recommendation, not proof that other controls are unnecessary."
            : "The path engine uses the first enabling relationship when no recorded defensive break is available. Review its permissions and exposure, then collect fresh evidence.", 13, "MutedBrush"));
        if (selected is not null)
        {
            _breakWorkspace.Children.Add(Ui.Text("Affected evidence nodes", 16, bold: true));
            foreach (var id in new[] { selected.SourceId, selected.TargetId })
            {
                if (_nodes.TryGetValue(id, out var node)) _breakWorkspace.Children.Add(Ui.Button(EvidenceNodePresentation.Label(node.Kind) + " · " + node.Label, () => InspectNode(node)));
            }
            _breakWorkspace.Children.Add(Ui.Text($"Relationship confidence {selected.Confidence:P0} · path confidence {_path.Confidence:P0}", 12, "MutedBrush"));
        }
        _breakWorkspace.Children.Add(Ui.Text("Risk reduction estimate", 16, bold: true));
        var relatedActions = _remediations.Where(a => a.FindingIds.Any(id => _path.FindingIds.Contains(id, StringComparer.Ordinal))).OrderByDescending(a => a.ModeledRiskReduction).ToList();
        if (relatedActions.Count > 0)
        {
            var first = relatedActions[0];
            var estimate = _risk is { TotalRisk: > 0 } ? $"{first.ModeledRiskReduction / _risk.TotalRisk:P0} of currently modeled finding risk" : $"{first.ModeledRiskReduction:0.0} modeled risk units";
            _breakWorkspace.Children.Add(Ui.Text($"Related action: {first.Title}\nEstimated association: {estimate}\nAction confidence: {first.Confidence:P0}", 14));
            _breakWorkspace.Children.Add(Ui.Text("This is the related action's estimate across all its findings, not a measured path-specific reduction. Estimates can overlap. No risk is treated as removed until fresh evidence verifies remediation.", 12, "MutedBrush"));
        }
        else _breakWorkspace.Children.Add(Ui.Text("No independent risk reduction estimate is available for this break point. Path risk is not a percentage of organization-wide risk removed.", 13, "MutedBrush"));
        _breakWorkspace.Children.Add(Ui.Text("Actions and supporting findings", 16, bold: true));
        var findings = _snapshot.Findings.Where(f => _path.FindingIds.Contains(f.Id, StringComparer.Ordinal)).OrderByDescending(f => f.Severity).ToList();
        foreach (var finding in findings)
        {
            _breakWorkspace.Children.Add(Ui.Badge(finding.Severity.ToString(), EvidenceNodePresentation.SeverityColor(finding.Severity)));
            _breakWorkspace.Children.Add(_openFinding is null ? Ui.Text(finding.Title, 14, bold: true) : Ui.Button(finding.Title, () => _openFinding(finding.Id)));
            if (!string.IsNullOrWhiteSpace(finding.Remediation)) _breakWorkspace.Children.Add(Ui.Text(finding.Remediation, 14));
        }
        _breakWorkspace.Children.Add(Ui.Text("Verify remediation", 16, bold: true));
        foreach (var verification in findings.Select(f => f.Verification).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.Ordinal)) _breakWorkspace.Children.Add(Ui.Text(verification, 14));
        _breakWorkspace.Children.Add(Ui.Text("Collect the same evidence again. Confirm the enabling relationship is removed or its finding is verified fixed, then recalculate the path. Planning or accepting an action does not verify remediation.", 13, "MutedBrush"));
        _breakWorkspace.Children.Add(Ui.Text("Supporting relationship IDs: " + string.Join(", ", _path.EdgeIds), 12, "MutedBrush"));
        if (_reviewRemediation is not null) _breakWorkspace.Children.Add(Ui.Button("Open remediation workspace", () => _reviewRemediation(_path)));
    }
}
