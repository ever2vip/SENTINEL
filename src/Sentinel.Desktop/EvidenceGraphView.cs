using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Sentinel.Core;

namespace Sentinel.Desktop;

/// <summary>A bounded, read-only exploration of the collected evidence graph.</summary>
internal sealed class EvidenceGraphView : StackPanel
{
    private const int NodeLimit = 28;
    private const int EdgeLimit = 42;
    private const double NodeWidth = 204;
    private const double NodeHeight = 108;
    private const double ClusterWidth = 180;
    private const double ClusterHeight = 88;
    private readonly EnvironmentSnapshot _snapshot;
    private readonly IReadOnlyList<AttackPath> _paths;
    private readonly RiskAssessment? _risk;
    private readonly Action<string>? _openAsset;
    private readonly Action<string>? _openFinding;
    private readonly Action<AttackPath>? _openPath;
    private readonly Dictionary<string, EvidenceNode> _nodes;
    private readonly Dictionary<string, EvidenceEdge> _edges;
    private readonly HashSet<string> _pathNodeIds;
    private readonly HashSet<string> _criticalNodeIds;
    private readonly Canvas _canvas = new() { Background = Brushes.Transparent };
    private readonly Border _viewport = new() { ClipToBounds = true, Height = 560, CornerRadius = new CornerRadius(12), Focusable = true };
    private readonly StackPanel _detail = new();
    private readonly TextBlock _count = Ui.Text("", 12, "MutedBrush");
    private readonly TextBlock _zoom = Ui.Text("100%", 12, "MutedBrush");
    private readonly TextBox _search = Ui.Search("Search node", 280);
    private readonly ComboBox _kind;
    private readonly ComboBox _relationship;
    private readonly ComboBox _pathChoice;
    private readonly Button _focusButton;
    private readonly Grid _layout = new();
    private readonly Border _graphHost;
    private readonly Border _inspector;
    private readonly Canvas _minimap = new() { Width = 130, Height = 82, Background = Brushes.Transparent };
    private readonly Dictionary<string, Button> _buttons = [];
    private readonly Dictionary<string, System.Windows.Shapes.Path> _lines = [];
    private readonly DispatcherTimer _searchDelay = new() { Interval = TimeSpan.FromMilliseconds(180) };
    private readonly List<string> _displayedNodes = [];
    private readonly List<string> _displayedEdges = [];
    private readonly List<(Point Position, string Color)> _mapPoints = [];
    private Matrix _matrix = Matrix.Identity;
    private Point? _drag;
    private string? _focusId;
    private string? _selectedId;
    private string? _selectedEdgeId;
    private AttackPath? _highlightedPath;
    private bool _ready;
    private bool _ignoreFilters;
    private int _lastColumns;

    public EvidenceGraphView(EnvironmentSnapshot snapshot, IReadOnlyList<AttackPath>? paths = null,
        RiskAssessment? risk = null, Action<string>? openAsset = null,
        Action<string>? openFinding = null, Action<AttackPath>? openPath = null)
    {
        _snapshot = snapshot;
        _paths = paths ?? new AttackPathEngine().Analyze(snapshot);
        _risk = risk;
        _openAsset = openAsset;
        _openFinding = openFinding;
        _openPath = openPath;
        _nodes = snapshot.Nodes.Where(n => !string.IsNullOrWhiteSpace(n.Id)).GroupBy(n => n.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        _edges = snapshot.Edges.Where(e => _nodes.ContainsKey(e.SourceId) && _nodes.ContainsKey(e.TargetId)).GroupBy(e => e.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        _pathNodeIds = _paths.SelectMany(p => p.NodeIds).ToHashSet(StringComparer.Ordinal);
        _criticalNodeIds = snapshot.Findings.Where(f => f.Severity == Severity.Critical).SelectMany(f => f.EvidenceIds.Concat(f.AssetIds).Append(f.Id)).ToHashSet(StringComparer.Ordinal);
        _kind = Ui.Select(new[] { "All node types" }.Concat(Enum.GetValues<EvidenceKind>().Select(EvidenceNodePresentation.Label)), "All node types");
        _relationship = Ui.Select(new[] { "All relationships" }.Concat(_edges.Values.Select(e => e.Relationship).Distinct().Order(StringComparer.Ordinal)), "All relationships");
        _pathChoice = Ui.Select(new[] { "No highlighted path" }.Concat(_paths.Select(p => p.Title + " · " + p.Id[^Math.Min(6, p.Id.Length)..])), "No highlighted path");
        _kind.MaxWidth = 190;
        _relationship.MaxWidth = 220;
        _pathChoice.MaxWidth = 300;
        SetName(_search, "GraphSearch", "Search node");
        SetName(_kind, "GraphNodeType", "Filter evidence node type");
        SetName(_relationship, "GraphRelationship", "Filter evidence relationship");
        SetName(_pathChoice, "GraphAttackPath", "Highlight a defensive attack path");
        _search.ToolTip = "Search recorded node labels and IDs. Matches include their immediate evidence neighbors.";
        Children.Add(Ui.Text("Explore the evidence behind exposure", 20, bold: true));
        Children.Add(Ui.Text("Start with a type cluster, find a record, or highlight a modeled path. Every relationship shown comes from collected evidence.", 14, "MutedBrush"));
        Children.Add(Wrap(_search, _kind, _relationship, _pathChoice));
        _focusButton = Tool("Focus selected", "focus", FocusSelected, "GraphFocus");
        _focusButton.IsEnabled = false;
        Children.Add(Wrap(
            _focusButton,
            Tool("Fit graph", "fit", Fit, "GraphFit"),
            Tool("Reset view", "reset", Reset, "GraphReset"),
            Tool("Zoom in", "zoom-in", () => Zoom(1.15), "GraphZoomIn"),
            Tool("Zoom out", "zoom-out", () => Zoom(1 / 1.15), "GraphZoomOut"), _zoom));
        Children.Add(_count);
        _viewport.SetResourceReference(Border.BackgroundProperty, "BackgroundBrush");
        _viewport.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        _viewport.BorderThickness = new Thickness(1);
        var surface = new Grid();
        surface.Children.Add(_canvas);
        var mapFrame = new Border { Child = _minimap, Padding = new Thickness(8), CornerRadius = new CornerRadius(8), BorderThickness = new Thickness(1), Margin = new Thickness(12), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Bottom, ToolTip = "Evidence overview. Click to center the graph." };
        mapFrame.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
        mapFrame.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        surface.Children.Add(mapFrame);
        _viewport.Child = surface;
        _graphHost = new Border { Child = _viewport };
        var detailScroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, MaxHeight = 560, Padding = new Thickness(0, 0, 8, 0) };
        _inspector = Ui.Card(detailScroll, 16);
        _inspector.Margin = new Thickness(12, 0, 0, 0);
        _layout.Children.Add(_graphHost);
        _layout.Children.Add(_inspector);
        Children.Add(_layout);
        Children.Add(Legend());
        Children.Add(Ui.Text("Overview clusters summarize recorded nodes. Expanded views render up to 28 nodes and 42 relationships; omitted evidence stays available through the Inspector and structured reports. Automatic framing preserves readable labels. Use Fit graph for the entire layout, drag empty space to pan, or use the wheel to zoom.", 12, "MutedBrush"));

        _search.TextChanged += (_, _) => { _searchDelay.Stop(); _searchDelay.Start(); };
        _searchDelay.Tick += (_, _) => { _searchDelay.Stop(); if (_ready && !_ignoreFilters) { _focusId = null; _selectedId = null; _selectedEdgeId = null; _highlightedPath = null; ClearPathChoice(); Draw(); } };
        _kind.SelectionChanged += (_, _) => { if (_ready && !_ignoreFilters) { _focusId = null; _selectedId = null; _selectedEdgeId = null; _highlightedPath = null; ClearPathChoice(); Draw(); } };
        _relationship.SelectionChanged += (_, _) => { if (_ready && !_ignoreFilters) Draw(); };
        _pathChoice.SelectionChanged += (_, _) =>
        {
            if (!_ready || _ignoreFilters) return;
            var index = _pathChoice.SelectedIndex - 1;
            if (index >= 0 && index < _paths.Count) HighlightPath(_paths[index]);
            else { _highlightedPath = null; Draw(); }
        };
        _viewport.PreviewMouseWheel += (_, e) => { Zoom(e.Delta > 0 ? 1.12 : 1 / 1.12, e.GetPosition(_viewport)); e.Handled = true; };
        _canvas.MouseLeftButtonDown += (_, e) =>
        {
            if (e.OriginalSource != _canvas) return;
            _drag = e.GetPosition(_viewport);
            _canvas.CaptureMouse();
            _viewport.Cursor = Cursors.SizeAll;
            e.Handled = true;
        };
        _canvas.MouseMove += (_, e) =>
        {
            if (_drag is not Point previous) return;
            var current = e.GetPosition(_viewport);
            _matrix.Translate(current.X - previous.X, current.Y - previous.Y);
            _drag = current;
            ApplyTransform();
        };
        _canvas.MouseLeftButtonUp += (_, _) => EndPan();
        _canvas.LostMouseCapture += (_, _) => { _drag = null; _viewport.Cursor = Cursors.Arrow; };
        _viewport.KeyDown += (_, e) =>
        {
            var movement = e.Key switch { Key.Left => new Vector(40, 0), Key.Right => new Vector(-40, 0), Key.Up => new Vector(0, 40), Key.Down => new Vector(0, -40), _ => new Vector() };
            if (movement.Length > 0) { _matrix.Translate(movement.X, movement.Y); ApplyTransform(); e.Handled = true; }
            else if (e.Key == Key.Home) { Fit(); e.Handled = true; }
            else if (e.Key is Key.Add or Key.OemPlus) { Zoom(1.15); e.Handled = true; }
            else if (e.Key is Key.Subtract or Key.OemMinus) { Zoom(1 / 1.15); e.Handled = true; }
        };
        _minimap.MouseLeftButtonDown += (_, e) =>
        {
            if (_canvas.Width <= 0 || _canvas.Height <= 0) return;
            var p = e.GetPosition(_minimap);
            _matrix.OffsetX = _viewport.ActualWidth / 2 - p.X / _minimap.Width * _canvas.Width * _matrix.M11;
            _matrix.OffsetY = _viewport.ActualHeight / 2 - p.Y / _minimap.Height * _canvas.Height * _matrix.M22;
            ApplyTransform();
            e.Handled = true;
        };
        SizeChanged += (_, _) => AdaptLayout();
        _viewport.SizeChanged += (_, _) =>
        {
            var columns = Columns();
            if (_ready && columns != _lastColumns) { Draw(); FrameReadable(); }
            else UpdateMinimap();
        };
        Loaded += (_, _) => { AdaptLayout(); Draw(); FrameReadable(); };
        Unloaded += (_, _) => _searchDelay.Stop();
        _ready = true;
        Draw();
    }

    internal IReadOnlyList<string> DisplayedNodeIds => _displayedNodes;
    internal IReadOnlyList<string> DisplayedRelationshipIds => _displayedEdges;
    internal bool IsClusterOverview { get; private set; }
    internal string? SelectedNodeId => _selectedId;

    public void FocusNode(string id)
    {
        if (!_nodes.TryGetValue(id, out var node)) return;
        _focusId = id;
        _selectedEdgeId = null;
        _highlightedPath = null;
        _ignoreFilters = true;
        _search.Text = "";
        _kind.SelectedIndex = 0;
        _relationship.SelectedIndex = 0;
        _pathChoice.SelectedIndex = 0;
        _ignoreFilters = false;
        _searchDelay.Stop();
        Draw();
        SelectNode(node);
        FrameReadable();
    }

    public void HighlightPath(AttackPath path)
    {
        _highlightedPath = path;
        _focusId = null;
        _selectedId = null;
        _selectedEdgeId = null;
        _ignoreFilters = true;
        _search.Text = "";
        _kind.SelectedIndex = 0;
        _relationship.SelectedIndex = 0;
        var index = _paths.ToList().FindIndex(p => p.Id == path.Id);
        _pathChoice.SelectedIndex = index < 0 ? 0 : index + 1;
        _ignoreFilters = false;
        _searchDelay.Stop();
        Draw();
        ShowPathInspector(path);
        FrameReadable();
    }

    private void ShowPathInspector(AttackPath path)
    {
        _focusButton.IsEnabled = false;
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Text("Highlighted defensive path", 18, bold: true));
        _detail.Children.Add(Ui.Text(path.Title, 15, bold: true));
        _detail.Children.Add(Ui.Badge($"Confidence {path.Confidence:P0}", "HighBrush"));
        _detail.Children.Add(Ui.Text($"Path risk {path.Risk:0.0} · {path.EdgeIds.Count} recorded steps", 14));
        _detail.Children.Add(Ui.Text(path.RecommendedAction, 14));
        if (_openPath is not null) _detail.Children.Add(Ui.Button("Review this path", () => _openPath(path), true));
        _detail.Children.Add(Ui.Text("A modeled chain is an inference from evidence. It does not establish exploit success, and SENTINEL does not execute it.", 12, "MutedBrush"));
    }

    private void Draw()
    {
        _canvas.Children.Clear();
        _buttons.Clear();
        _lines.Clear();
        _mapPoints.Clear();
        _displayedNodes.Clear();
        _displayedEdges.Clear();
        var term = _search.Text.Trim();
        var allKinds = _kind.SelectedIndex <= 0;
        var allRelationships = _relationship.SelectedIndex <= 0;
        IsClusterOverview = string.IsNullOrWhiteSpace(term) && allKinds && allRelationships && _focusId is null && _highlightedPath is null;
        if (IsClusterOverview) DrawClusters();
        else DrawRecords(term, allKinds, allRelationships);
        if (_selectedId is not null && _nodes.TryGetValue(_selectedId, out var selected)) SelectNode(selected);
        else if (_selectedEdgeId is not null && _edges.TryGetValue(_selectedEdgeId, out var selectedEdge)) SelectEdge(selectedEdge);
        else if (_highlightedPath is not null) ShowPathInspector(_highlightedPath);
        else ShowInspectorHelp();
        ApplyTransform();
    }

    private void DrawClusters()
    {
        var groups = _nodes.Values.GroupBy(n => n.Kind).OrderBy(g => EvidenceNodePresentation.Order(g.Key)).ToList();
        var positions = Positions(groups.Count, clusters: true);
        var kindPositions = groups.Select((g, i) => (g.Key, Position: positions[i])).ToDictionary(x => x.Key, x => x.Position);
        var aggregate = _edges.Values.GroupBy(e => (_nodes[e.SourceId].Kind, _nodes[e.TargetId].Kind)).Where(g => g.Key.Item1 != g.Key.Item2)
            .OrderByDescending(g => g.Any(e => e.EnablesPath)).ThenByDescending(g => g.Count()).Take(26).ToList();
        foreach (var group in aggregate)
        {
            var realEdges = group.ToList();
            var line = RelationshipLine(kindPositions[group.Key.Item1], kindPositions[group.Key.Item2], realEdges.Any(e => e.EnablesPath), ClusterWidth, ClusterHeight);
            line.ToolTip = $"{EvidenceNodePresentation.Label(group.Key.Item1)} → {EvidenceNodePresentation.Label(group.Key.Item2)}\n{realEdges.Count} recorded relationships";
            line.MouseLeftButtonDown += (_, e) => { InspectClusterRelationship(group.Key.Item1, group.Key.Item2, realEdges); e.Handled = true; };
            AutomationProperties.SetName(line, EvidenceNodePresentation.Label(group.Key.Item1) + " to " + EvidenceNodePresentation.Label(group.Key.Item2) + " relationship group");
            line.KeyDown += (_, e) => { if (e.Key is Key.Enter or Key.Space) { InspectClusterRelationship(group.Key.Item1, group.Key.Item2, realEdges); e.Handled = true; } };
            _canvas.Children.Add(line);
        }
        for (var i = 0; i < groups.Count; i++)
        {
            var group = groups[i];
            var button = Ui.Button("", () => InspectCluster(group.Key));
            button.Width = ClusterWidth;
            button.Height = ClusterHeight;
            button.Padding = new Thickness(12);
            button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
            button.Content = NodeContent(group.Key, EvidenceNodePresentation.Label(group.Key), $"{group.Count():N0} recorded nodes", null);
            button.ToolTip = "Select this type cluster to inspect and expand its recorded evidence.";
            SetName(button, "GraphCluster:" + group.Key, EvidenceNodePresentation.Label(group.Key) + " evidence cluster, " + group.Count() + " nodes");
            AddAt(button, positions[i]);
            _mapPoints.Add((positions[i], EvidenceNodePresentation.Color(group.Key)));
        }
        _count.Text = $"{groups.Count} type clusters · {_nodes.Count:N0} recorded nodes · {_edges.Count:N0} recorded relationships · {aggregate.Count} visible relationship groups";
        if (_nodes.Count == 0)
        {
            var empty = Ui.Stack(Ui.Icon("graph", 32), Ui.Text("No graph evidence yet", 18, bold: true), Ui.Text("Open Demo Organization or collect evidence in an authorized Live Environment.", 14, "MutedBrush"));
            _canvas.Children.Add(empty);
            Canvas.SetLeft(empty, 24);
            Canvas.SetTop(empty, 32);
        }
    }

    private void DrawRecords(string term, bool allKinds, bool allRelationships)
    {
        var relationship = _relationship.SelectedItem?.ToString();
        var allowedEdges = _edges.Values.Where(e => allRelationships || e.Relationship == relationship).ToList();
        var relationshipNodeIds = allowedEdges.SelectMany(e => new[] { e.SourceId, e.TargetId }).ToHashSet(StringComparer.Ordinal);
        var matches = _nodes.Values.Where(n => (allKinds || EvidenceNodePresentation.Label(n.Kind) == _kind.SelectedItem?.ToString()) && (allRelationships || relationshipNodeIds.Contains(n.Id)) && $"{n.Label} {n.Id}".Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();
        var candidates = new List<EvidenceNode>();
        if (_highlightedPath is not null)
        {
            candidates.AddRange(_highlightedPath.NodeIds.Where(_nodes.ContainsKey).Select(id => _nodes[id]));
            allowedEdges = allowedEdges.Where(e => _highlightedPath.EdgeIds.Contains(e.Id, StringComparer.Ordinal)).ToList();
        }
        else if (_focusId is not null && _nodes.TryGetValue(_focusId, out var focus))
        {
            candidates.Add(focus);
            var neighborIds = allowedEdges.Where(e => e.SourceId == _focusId || e.TargetId == _focusId).SelectMany(e => new[] { e.SourceId, e.TargetId }).Distinct();
            candidates.AddRange(neighborIds.Where(_nodes.ContainsKey).Select(id => _nodes[id]).OrderByDescending(n => PathNode(n.Id)).ThenBy(n => n.Label, StringComparer.Ordinal));
        }
        else
        {
            var seeds = matches.OrderByDescending(n => PathNode(n.Id)).ThenByDescending(n => _criticalNodeIds.Contains(n.Id)).ThenBy(n => n.Label, StringComparer.Ordinal).Take(16).ToList();
            candidates.AddRange(seeds);
            var seedIds = seeds.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
            var neighborIds = allowedEdges.Where(e => seedIds.Contains(e.SourceId) || seedIds.Contains(e.TargetId)).SelectMany(e => new[] { e.SourceId, e.TargetId }).Distinct();
            candidates.AddRange(neighborIds.Where(_nodes.ContainsKey).Select(id => _nodes[id]).OrderByDescending(n => PathNode(n.Id)).ThenBy(n => n.Label, StringComparer.Ordinal));
        }
        var nodes = candidates.DistinctBy(n => n.Id).Take(NodeLimit).ToList();
        var ids = nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        var visibleEdges = allowedEdges.Where(e => ids.Contains(e.SourceId) && ids.Contains(e.TargetId)).OrderByDescending(e => _highlightedPath?.EdgeIds.Contains(e.Id, StringComparer.Ordinal) == true).ThenByDescending(e => e.EnablesPath).ThenBy(e => e.Id, StringComparer.Ordinal).Take(EdgeLimit).ToList();
        var points = Positions(nodes.Count);
        var positions = nodes.Select((n, i) => (n.Id, Point: points[i])).ToDictionary(x => x.Id, x => x.Point, StringComparer.Ordinal);
        foreach (var edge in visibleEdges)
        {
            var line = RelationshipLine(positions[edge.SourceId], positions[edge.TargetId], edge.EnablesPath);
            SetName(line, "GraphEdge:" + edge.Id, edge.Relationship + " relationship from " + _nodes[edge.SourceId].Label + " to " + _nodes[edge.TargetId].Label);
            line.ToolTip = $"{edge.Relationship}\n{_nodes[edge.SourceId].Label} → {_nodes[edge.TargetId].Label}\nConfidence {edge.Confidence:P0}";
            line.MouseLeftButtonDown += (_, e) => { SelectEdge(edge); e.Handled = true; };
            line.KeyDown += (_, e) => { if (e.Key is Key.Enter or Key.Space) { SelectEdge(edge); e.Handled = true; } };
            _canvas.Children.Add(line);
            _lines[edge.Id] = line;
            _displayedEdges.Add(edge.Id);
        }
        foreach (var node in nodes)
        {
            var button = Ui.Button("", () => SelectNode(node));
            button.Width = NodeWidth;
            button.Height = NodeHeight;
            button.Padding = new Thickness(12);
            button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
            var degree = _edges.Values.Count(e => e.SourceId == node.Id || e.TargetId == node.Id);
            button.Content = NodeContent(node.Kind, node.Label, $"{degree} relationships · {node.Confidence:P0}", node);
            button.ToolTip = $"{node.Label}\n{node.Source}\nConfidence {node.Confidence:P0}\nDouble-click to focus this neighborhood.";
            SetName(button, "GraphNode:" + node.Id, EvidenceNodePresentation.Label(node.Kind) + ": " + node.Label);
            button.MouseDoubleClick += (_, e) => { FocusNode(node.Id); e.Handled = true; };
            AddAt(button, positions[node.Id]);
            _buttons[node.Id] = button;
            _displayedNodes.Add(node.Id);
            _mapPoints.Add((positions[node.Id], EvidenceNodePresentation.Color(node.Kind)));
        }
        var mode = _highlightedPath is not null ? "highlighted path" : _focusId is not null ? "focused neighborhood" : $"{matches.Count:N0} direct matches, with immediate neighbors";
        _count.Text = $"{nodes.Count} displayed / {_nodes.Count:N0} recorded nodes · {visibleEdges.Count} displayed / {_edges.Count:N0} recorded relationships · {mode}";
        if (nodes.Count == 0)
        {
            var empty = Ui.Stack(Ui.Icon("search", 28), Ui.Text("No matching evidence", 18, bold: true), Ui.Text("Try a different label, node type, or relationship filter.", 14, "MutedBrush"), Ui.Button("Clear filters", Reset));
            AddAt(empty, new Point(24, 32));
        }
    }

    private static Grid NodeContent(EvidenceKind kind, string label, string meta, EvidenceNode? node)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(30) });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        var icon = Ui.Icon(EvidenceNodePresentation.Icon(kind), 24, EvidenceNodePresentation.Color(kind));
        icon.VerticalAlignment = VerticalAlignment.Top;
        icon.Margin = new Thickness(0, 3, 6, 0);
        grid.Children.Add(icon);
        var title = Ui.Text(label, 14, bold: true);
        title.MaxHeight = node is null ? 32 : 40;
        title.TextTrimming = TextTrimming.CharacterEllipsis;
        title.Margin = new Thickness(0, 0, 0, 2);
        var metadata = Ui.Text(meta, 13.5, "MutedBrush");
        metadata.Margin = new Thickness(0);
        metadata.TextWrapping = TextWrapping.NoWrap;
        metadata.TextTrimming = TextTrimming.CharacterEllipsis;
        metadata.ToolTip = meta;
        var text = Ui.Stack(title, metadata);
        if (node is not null)
        {
            var type = Ui.Text(EvidenceNodePresentation.Label(kind), 13.5, EvidenceNodePresentation.Color(kind));
            type.Margin = new Thickness(0, 0, 0, 1);
            text.Children.Insert(0, type);
        }
        Grid.SetColumn(text, 1);
        grid.Children.Add(text);
        return grid;
    }

    private void InspectCluster(EvidenceKind kind)
    {
        _selectedId = null;
        _selectedEdgeId = null;
        _focusButton.IsEnabled = false;
        _detail.Children.Clear();
        var records = _nodes.Values.Where(n => n.Kind == kind).OrderBy(n => n.Label, StringComparer.Ordinal).ToList();
        _detail.Children.Add(Ui.Icon(EvidenceNodePresentation.Icon(kind), 28, EvidenceNodePresentation.Color(kind)));
        _detail.Children.Add(Ui.Text(EvidenceNodePresentation.Label(kind) + " cluster", 18, bold: true));
        _detail.Children.Add(Ui.Text($"{records.Count:N0} recorded evidence nodes. This cluster summarizes real records; it has no independent source or confidence.", 14, "MutedBrush"));
        _detail.Children.Add(Ui.Button("Expand this type", () =>
        {
            _ignoreFilters = true;
            _search.Text = "";
            _kind.SelectedItem = EvidenceNodePresentation.Label(kind);
            _ignoreFilters = false;
            _searchDelay.Stop();
            Draw();
            FrameReadable();
        }, true));
        _detail.Children.Add(Ui.Text("Recorded nodes", 16, bold: true));
        foreach (var node in records.Take(20)) _detail.Children.Add(Ui.Button(node.Label, () => FocusNode(node.Id)));
        if (records.Count > 20) _detail.Children.Add(Ui.Text($"Showing the first 20 of {records.Count:N0}. Search by label to reach another record.", 12, "MutedBrush"));
    }

    private void InspectClusterRelationship(EvidenceKind source, EvidenceKind target, IReadOnlyList<EvidenceEdge> edges)
    {
        _selectedId = null;
        _selectedEdgeId = null;
        _focusButton.IsEnabled = false;
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Text("Relationship group", 18, bold: true));
        _detail.Children.Add(Ui.Text($"{EvidenceNodePresentation.Label(source)} → {EvidenceNodePresentation.Label(target)}", 15, bold: true));
        _detail.Children.Add(Ui.Text($"{edges.Count} actual relationships are summarized. Select a relationship to inspect its own confidence and dependencies.", 14, "MutedBrush"));
        foreach (var group in edges.GroupBy(e => e.Relationship)) _detail.Children.Add(Ui.Badge($"{group.Key} · {group.Count()}", "AccentBrush"));
        foreach (var edge in edges.Take(20)) _detail.Children.Add(Ui.Button(_nodes[edge.SourceId].Label + " → " + _nodes[edge.TargetId].Label, () => SelectEdge(edge)));
        if (edges.Count > 20) _detail.Children.Add(Ui.Text("More relationships are available by focusing a node or filtering the relationship type.", 12, "MutedBrush"));
    }

    private void SelectNode(EvidenceNode node)
    {
        _selectedId = node.Id;
        _selectedEdgeId = null;
        _focusButton.IsEnabled = true;
        foreach (var pair in _buttons) pair.Value.SetResourceReference(Control.BorderBrushProperty, pair.Key == node.Id ? "AccentBrush" : "BorderBrush");
        foreach (var pair in _lines)
        {
            var edge = _edges[pair.Key];
            var adjacent = edge.SourceId == node.Id || edge.TargetId == node.Id;
            pair.Value.Opacity = adjacent ? 1 : 0.18;
            pair.Value.StrokeThickness = adjacent ? 3 : 1.5;
        }
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Icon(EvidenceNodePresentation.Icon(node.Kind), 28, EvidenceNodePresentation.Color(node.Kind)));
        _detail.Children.Add(Ui.Text(node.Label, 19, bold: true));
        _detail.Children.Add(Ui.Badge(EvidenceNodePresentation.Label(node.Kind), EvidenceNodePresentation.Color(node.Kind)));
        var findings = RelatedFindings(node).ToList();
        var assetIds = RelatedAssetIds(node).ToList();
        var scored = _risk?.RankedFindings.Where(s => findings.Any(f => f.Id == s.Finding.Id)).ToList();
        _detail.Children.Add(Ui.Text(scored is { Count: > 0 } ? $"Highest associated finding risk: {scored.Max(s => s.Risk):0.0} / 100" : "Associated contextual risk: not assessed", 14, scored is { Count: > 0 } ? "HighBrush" : "MutedBrush"));
        AddSection("Provenance", Ui.Text(string.IsNullOrWhiteSpace(node.Source) ? "Source not recorded" : node.Source, 14), Ui.Text($"Confidence {node.Confidence:P0}\nObserved {node.ObservedAt.LocalDateTime:g}", 12, "MutedBrush"));
        _detail.Children.Add(Ui.Button("Focus this neighborhood", () => FocusNode(node.Id)));
        if (node.Properties.Count > 0)
        {
            AddSection("Recorded properties");
            foreach (var pair in node.Properties.OrderBy(p => p.Key, StringComparer.Ordinal)) _detail.Children.Add(Ui.Text($"{pair.Key}: {pair.Value}", 13));
        }
        AddSection("Related assets");
        if (assetIds.Count == 0) _detail.Children.Add(Ui.Text("No asset link is stored for this node.", 12, "MutedBrush"));
        foreach (var id in assetIds.Take(8))
        {
            var asset = _snapshot.Assets.First(a => a.Id == id);
            _detail.Children.Add(_openAsset is null ? Ui.Text(asset.Name, 14) : Ui.Button("Open asset · " + asset.Name, () => _openAsset(id)));
        }
        AddSection("Related findings");
        if (findings.Count == 0) _detail.Children.Add(Ui.Text("No linked finding is recorded.", 12, "MutedBrush"));
        foreach (var finding in findings.OrderByDescending(f => f.Severity).Take(10)) AddFinding(finding);
        var paths = _paths.Where(p => p.NodeIds.Contains(node.Id, StringComparer.Ordinal) || p.FindingIds.Any(id => findings.Any(f => f.Id == id))).ToList();
        AddSection($"Defensive paths · {paths.Count}");
        foreach (var path in paths.Take(8)) _detail.Children.Add(Ui.Button(path.Title, () => { if (_openPath is not null) _openPath(path); else HighlightPath(path); }));
        if (paths.Count == 0) _detail.Children.Add(Ui.Text("No currently modeled path references this evidence.", 12, "MutedBrush"));
        AddSection("Related evidence");
        var connectedEdges = _edges.Values.Where(e => e.SourceId == node.Id || e.TargetId == node.Id).ToList();
        foreach (var edge in connectedEdges.Take(14))
        {
            var other = _nodes[edge.SourceId == node.Id ? edge.TargetId : edge.SourceId];
            _detail.Children.Add(Ui.Button($"{edge.Relationship} · {other.Label}", () => SelectEdge(edge)));
        }
        if (connectedEdges.Count > 14) _detail.Children.Add(Ui.Text($"{connectedEdges.Count - 14} further relationships exist. Use relationship filters to narrow the view.", 12, "MutedBrush"));
        AddSection("History");
        var changes = _snapshot.Changes.Where(c => c.EntityId == node.Id || assetIds.Contains(c.EntityId, StringComparer.Ordinal) || findings.Any(f => f.Id == c.EntityId)).OrderByDescending(c => c.At).Take(5).ToList();
        foreach (var change in changes) _detail.Children.Add(Ui.Text($"{change.At.LocalDateTime:g} · {change.Kind}\n{change.Summary}\nSource: {change.Source}", 12, "MutedBrush"));
        if (changes.Count == 0) _detail.Children.Add(Ui.Text("No historical change record is linked to this node. The observation time above describes the stored evidence.", 12, "MutedBrush"));
        _detail.Children.Add(Ui.Text("Evidence ID: " + node.Id, 12, "MutedBrush"));
    }

    private void SelectEdge(EvidenceEdge edge)
    {
        _selectedId = null;
        _selectedEdgeId = edge.Id;
        _focusButton.IsEnabled = false;
        foreach (var button in _buttons.Values) button.SetResourceReference(Control.BorderBrushProperty, "BorderBrush");
        foreach (var pair in _lines) { pair.Value.Opacity = pair.Key == edge.Id ? 1 : 0.2; pair.Value.StrokeThickness = pair.Key == edge.Id ? 4 : 1.5; }
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Text(edge.Relationship, 19, bold: true));
        _detail.Children.Add(Ui.Badge(edge.EnablesPath ? "Path enabling evidence" : "Observed relationship", edge.EnablesPath ? "HighBrush" : "AccentBrush"));
        foreach (var id in new[] { edge.SourceId, edge.TargetId })
        {
            var node = _nodes[id];
            _detail.Children.Add(Ui.Button(EvidenceNodePresentation.Label(node.Kind) + " · " + node.Label, () => FocusNode(node.Id)));
        }
        _detail.Children.Add(Ui.Text($"Direction: source → target\nRelationship confidence: {edge.Confidence:P0}", 13));
        AddSection("Provenance");
        _detail.Children.Add(Ui.Text("The relationship model does not separately record a source or timestamp. Endpoint observations and supporting findings provide the recorded provenance below.", 12, "MutedBrush"));
        foreach (var node in new[] { _nodes[edge.SourceId], _nodes[edge.TargetId] }) _detail.Children.Add(Ui.Text($"{node.Label}\n{node.Source} · {node.ObservedAt.LocalDateTime:g}\nNode confidence {node.Confidence:P0}", 12, "MutedBrush"));
        if (!string.IsNullOrWhiteSpace(edge.DefensiveBreak)) AddSection("Recommended defensive break", Ui.Text(edge.DefensiveBreak, 14));
        AddSection("Supporting findings");
        foreach (var id in edge.FindingIds)
        {
            var finding = _snapshot.Findings.FirstOrDefault(f => f.Id == id);
            if (finding is not null) AddFinding(finding);
            else _detail.Children.Add(Ui.Text("Referenced finding unavailable: " + id, 12, "MutedBrush"));
        }
        if (edge.FindingIds.Count == 0) _detail.Children.Add(Ui.Text("No finding dependency is recorded on this relationship.", 12, "MutedBrush"));
        var paths = _paths.Where(p => p.EdgeIds.Contains(edge.Id, StringComparer.Ordinal)).ToList();
        AddSection($"Defensive paths · {paths.Count}");
        foreach (var path in paths.Take(8)) _detail.Children.Add(Ui.Button(path.Title, () => { if (_openPath is not null) _openPath(path); else HighlightPath(path); }));
        _detail.Children.Add(Ui.Text("Relationship ID: " + edge.Id, 12, "MutedBrush"));
    }

    private IEnumerable<Finding> RelatedFindings(EvidenceNode node)
    {
        var edgeFindingIds = _edges.Values.Where(e => e.SourceId == node.Id || e.TargetId == node.Id).SelectMany(e => e.FindingIds).ToHashSet(StringComparer.Ordinal);
        var linkedFindingNodeIds = _edges.Values.Where(e => e.SourceId == node.Id || e.TargetId == node.Id).SelectMany(e => new[] { e.SourceId, e.TargetId }).ToHashSet(StringComparer.Ordinal);
        var assetId = node.Properties.GetValueOrDefault("assetId", node.Kind is EvidenceKind.Asset or EvidenceKind.CloudResource ? node.Id : "");
        return _snapshot.Findings.Where(f => f.Id == node.Id || f.EvidenceIds.Contains(node.Id, StringComparer.Ordinal) || edgeFindingIds.Contains(f.Id) || linkedFindingNodeIds.Contains(f.Id) || (!string.IsNullOrEmpty(assetId) && f.AssetIds.Contains(assetId, StringComparer.Ordinal)));
    }

    private IEnumerable<string> RelatedAssetIds(EvidenceNode node)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal) { node.Id, node.Properties.GetValueOrDefault("assetId", "") };
        foreach (var edge in _edges.Values.Where(e => e.SourceId == node.Id || e.TargetId == node.Id))
        {
            var other = _nodes[edge.SourceId == node.Id ? edge.TargetId : edge.SourceId];
            ids.Add(other.Id);
            ids.Add(other.Properties.GetValueOrDefault("assetId", ""));
        }
        foreach (var finding in RelatedFindings(node)) ids.UnionWith(finding.AssetIds);
        return _snapshot.Assets.Where(a => ids.Contains(a.Id)).Select(a => a.Id);
    }

    private void AddFinding(Finding finding)
    {
        _detail.Children.Add(Ui.Badge(finding.Severity + " · " + finding.Status, EvidenceNodePresentation.SeverityColor(finding.Severity)));
        _detail.Children.Add(_openFinding is null ? Ui.Text(finding.Title, 14) : Ui.Button(finding.Title, () => _openFinding(finding.Id)));
        _detail.Children.Add(Ui.Text($"Source: {finding.Source}\nConfidence {finding.Confidence:P0} · last seen {finding.LastSeen.LocalDateTime:g}", 12, "MutedBrush"));
    }

    private void AddSection(string title, params UIElement[] content)
    {
        var heading = Ui.Text(title, 16, bold: true);
        heading.Margin = new Thickness(0, 16, 0, 8);
        _detail.Children.Add(heading);
        foreach (var child in content) _detail.Children.Add(child);
    }

    private void ShowInspectorHelp()
    {
        _focusButton.IsEnabled = false;
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Icon("graph", 28, "AccentBrush"));
        _detail.Children.Add(Ui.Text("Evidence Inspector", 19, bold: true));
        _detail.Children.Add(Ui.Text(_nodes.Count == 0 ? "Collect evidence or open Demo Organization to explore relationships." : IsClusterOverview ? "Select a type cluster to inspect its recorded nodes. Expand a cluster or search to reveal a focused graph." : "Select a node for its source, confidence, findings, related assets and history. Select a connector to inspect the relationship.", 14, "MutedBrush"));
        _detail.Children.Add(Ui.Text("Evidence and inference", 16, bold: true));
        _detail.Children.Add(Ui.Text("Nodes and relationships are stored evidence. Defensive attack paths are calculated interpretations of explicitly enabling relationships. Neither establishes exploit success.", 13, "MutedBrush"));
    }

    private List<Point> Positions(int count, bool clusters = false)
    {
        var width = clusters ? ClusterWidth : NodeWidth;
        var height = clusters ? ClusterHeight : NodeHeight;
        var gapX = clusters ? 24.0 : 46.0;
        var gapY = clusters ? 24.0 : 44.0;
        var columns = Columns();
        _lastColumns = columns;
        _canvas.Width = Math.Max(_viewport.ActualWidth, columns * (width + gapX) + 24);
        _canvas.Height = Math.Max(560, Math.Ceiling(Math.Max(1, count) / (double)columns) * (height + gapY) + 40);
        return Enumerable.Range(0, count).Select(i => new Point(24 + i % columns * (width + gapX), 24 + i / columns * (height + gapY))).ToList();
    }

    private int Columns() => Math.Clamp((int)Math.Floor((Math.Max(600, _viewport.ActualWidth) - 24) / (IsClusterOverview ? ClusterWidth + 24 : NodeWidth + 46)), 2, 5);
    private bool PathNode(string id) => _pathNodeIds.Contains(id);
    private void AddAt(UIElement child, Point point) { Canvas.SetLeft(child, point.X); Canvas.SetTop(child, point.Y); _canvas.Children.Add(child); }

    private static System.Windows.Shapes.Path RelationshipLine(Point source, Point target, bool path, double width = NodeWidth, double height = NodeHeight)
    {
        Point from;
        Point to;
        if (Math.Abs(source.X - target.X) > width / 2)
        {
            var right = target.X > source.X;
            from = new Point(source.X + (right ? width : 0), source.Y + height / 2);
            to = new Point(target.X + (right ? 0 : width), target.Y + height / 2);
        }
        else
        {
            var down = target.Y > source.Y;
            from = new Point(source.X + width / 2, source.Y + (down ? height : 0));
            to = new Point(target.X + width / 2, target.Y + (down ? 0 : height));
        }
        var delta = to - from;
        var direction = delta.Length > 0 ? delta / delta.Length : new Vector(1, 0);
        var bend = Math.Abs(delta.X) > Math.Abs(delta.Y) ? new Vector(delta.X * 0.45, 0) : new Vector(0, delta.Y * 0.45);
        var geometry = new PathGeometry();
        var curve = new PathFigure { StartPoint = from, IsClosed = false };
        curve.Segments.Add(new BezierSegment(from + bend, to - bend, to, true));
        geometry.Figures.Add(curve);
        var arrow = new PathFigure { StartPoint = to - direction * 9 + new Vector(-direction.Y, direction.X) * 4, IsClosed = false };
        arrow.Segments.Add(new LineSegment(to, true));
        arrow.Segments.Add(new LineSegment(to - direction * 9 - new Vector(-direction.Y, direction.X) * 4, true));
        geometry.Figures.Add(arrow);
        var result = new System.Windows.Shapes.Path { Data = geometry, StrokeThickness = path ? 2.5 : 1.5, Opacity = path ? 0.85 : 0.45, Cursor = Cursors.Hand, Focusable = true };
        result.SetResourceReference(Shape.StrokeProperty, path ? "HighBrush" : "MutedBrush");
        return result;
    }

    private WrapPanel Legend()
    {
        var legend = new WrapPanel { Margin = new Thickness(0, 16, 0, 12) };
        foreach (var kind in Enum.GetValues<EvidenceKind>())
        {
            var item = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 16, 8) };
            var icon = Ui.Icon(EvidenceNodePresentation.Icon(kind), 16, EvidenceNodePresentation.Color(kind));
            icon.Margin = new Thickness(0, 0, 6, 0);
            item.Children.Add(icon);
            item.Children.Add(Ui.Text(EvidenceNodePresentation.Label(kind), 12, "MutedBrush"));
            legend.Children.Add(item);
        }
        legend.Children.Add(Ui.Badge("Path enabling relationship", "HighBrush"));
        legend.Children.Add(Ui.Badge("Recorded relationship", "MutedBrush"));
        return legend;
    }

    private void AdaptLayout()
    {
        var wide = ActualWidth >= 1250;
        _layout.ColumnDefinitions.Clear();
        _layout.RowDefinitions.Clear();
        if (wide)
        {
            _layout.ColumnDefinitions.Add(new ColumnDefinition());
            _layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });
            Grid.SetRow(_graphHost, 0);
            Grid.SetColumn(_graphHost, 0);
            Grid.SetRow(_inspector, 0);
            Grid.SetColumn(_inspector, 1);
            _inspector.Margin = new Thickness(12, 0, 0, 0);
        }
        else
        {
            _layout.ColumnDefinitions.Add(new ColumnDefinition());
            _layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            _layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(_graphHost, 0);
            Grid.SetColumn(_graphHost, 0);
            Grid.SetRow(_inspector, 1);
            Grid.SetColumn(_inspector, 0);
            _inspector.Margin = new Thickness(0, 12, 0, 0);
        }
    }

    private void Zoom(double factor, Point? center = null)
    {
        var scale = Math.Clamp(_matrix.M11 * factor, 0.1, 2.5);
        factor = scale / _matrix.M11;
        var p = center ?? new Point(_viewport.ActualWidth / 2, _viewport.ActualHeight / 2);
        _matrix.ScaleAt(factor, factor, p.X, p.Y);
        ApplyTransform();
    }

    private void Fit() => Fit(0.1);
    private void FrameReadable() => Fit(0.9);

    private void Fit(double minimumScale)
    {
        var width = Math.Max(600, _viewport.ActualWidth);
        var scale = Math.Clamp(Math.Min((width - 24) / Math.Max(1, _canvas.Width), (_viewport.Height - 24) / Math.Max(1, _canvas.Height)), minimumScale, 1.1);
        _matrix = new Matrix(scale, 0, 0, scale, 12, 12);
        ApplyTransform();
    }

    private void Reset()
    {
        _searchDelay.Stop();
        _focusId = null;
        _selectedId = null;
        _selectedEdgeId = null;
        _highlightedPath = null;
        _ignoreFilters = true;
        _search.Text = "";
        _kind.SelectedIndex = 0;
        _relationship.SelectedIndex = 0;
        _pathChoice.SelectedIndex = 0;
        _ignoreFilters = false;
        _searchDelay.Stop();
        Draw();
        FrameReadable();
    }

    private void FocusSelected() { if (_selectedId is not null) FocusNode(_selectedId); }
    private void ClearPathChoice() { _ignoreFilters = true; _pathChoice.SelectedIndex = 0; _ignoreFilters = false; }
    private void EndPan() { _drag = null; _canvas.ReleaseMouseCapture(); _viewport.Cursor = Cursors.Arrow; }
    private void ApplyTransform() { _canvas.RenderTransform = new MatrixTransform(_matrix); _zoom.Text = $"{_matrix.M11:P0}"; UpdateMinimap(); }

    private void UpdateMinimap()
    {
        _minimap.Children.Clear();
        if (_canvas.Width <= 0 || _canvas.Height <= 0) return;
        var xScale = _minimap.Width / _canvas.Width;
        var yScale = _minimap.Height / _canvas.Height;
        foreach (var point in _mapPoints)
        {
            var dot = new Rectangle { Width = Math.Max(4, (IsClusterOverview ? ClusterWidth : NodeWidth) * xScale), Height = Math.Max(3, (IsClusterOverview ? ClusterHeight : NodeHeight) * yScale), RadiusX = 2, RadiusY = 2, IsHitTestVisible = false };
            dot.SetResourceReference(Shape.FillProperty, point.Color);
            Canvas.SetLeft(dot, point.Position.X * xScale);
            Canvas.SetTop(dot, point.Position.Y * yScale);
            _minimap.Children.Add(dot);
        }
        var frame = new Rectangle { Width = Math.Min(_minimap.Width, _viewport.ActualWidth / _matrix.M11 * xScale), Height = Math.Min(_minimap.Height, _viewport.Height / _matrix.M22 * yScale), StrokeThickness = 1.4, IsHitTestVisible = false };
        frame.SetResourceReference(Shape.StrokeProperty, "TextBrush");
        Canvas.SetLeft(frame, Math.Clamp(-_matrix.OffsetX / _matrix.M11 * xScale, 0, Math.Max(0, _minimap.Width - frame.Width)));
        Canvas.SetTop(frame, Math.Clamp(-_matrix.OffsetY / _matrix.M22 * yScale, 0, Math.Max(0, _minimap.Height - frame.Height)));
        _minimap.Children.Add(frame);
    }

    private static Button Tool(string label, string icon, Action action, string id)
    {
        var button = Ui.Button(label, action);
        var row = new StackPanel { Orientation = Orientation.Horizontal };
        var vector = Ui.Icon(icon, 16);
        vector.Margin = new Thickness(0, 0, 7, 0);
        row.Children.Add(vector);
        var text = Ui.Text(label, 13);
        text.Margin = new Thickness(0);
        row.Children.Add(text);
        button.Content = row;
        SetName(button, id, label);
        return button;
    }

    private static WrapPanel Wrap(params UIElement[] children) => Ui.Toolbar(children);

    private static void SetName(DependencyObject element, string id, string name)
    {
        AutomationProperties.SetAutomationId(element, id);
        AutomationProperties.SetName(element, name);
    }
}

internal static class EvidenceNodePresentation
{
    public static string Label(EvidenceKind kind) => kind switch { EvidenceKind.IP => "IP address", EvidenceKind.CloudResource => "Cloud resource", _ => kind.ToString() };
    public static string Icon(EvidenceKind kind) => kind switch { EvidenceKind.IP => "ip", EvidenceKind.CloudResource => "cloud-resource", _ => kind.ToString().ToLowerInvariant() };
    public static string Color(EvidenceKind kind) => kind switch
    {
        EvidenceKind.Asset => "AccentBrush", EvidenceKind.Identity => "MediumBrush", EvidenceKind.IP or EvidenceKind.Service => "TealBrush",
        EvidenceKind.Domain or EvidenceKind.CloudResource => "InfoBrush", EvidenceKind.Vulnerability => "CriticalBrush",
        EvidenceKind.Permission or EvidenceKind.Finding => "HighBrush", EvidenceKind.Control => "SuccessBrush",
        EvidenceKind.Certificate => "LowBrush", _ => "MutedBrush"
    };
    public static int Order(EvidenceKind kind) => kind switch { EvidenceKind.Internet => 0, EvidenceKind.Domain => 1, EvidenceKind.IP => 2, EvidenceKind.Service => 3, EvidenceKind.Asset => 4, EvidenceKind.CloudResource => 5, EvidenceKind.Identity => 6, EvidenceKind.Permission => 7, EvidenceKind.Software => 8, EvidenceKind.Vulnerability => 9, EvidenceKind.Finding => 10, EvidenceKind.Certificate => 11, _ => 12 };
    public static string SeverityColor(Severity severity) => severity switch { Severity.Critical => "CriticalBrush", Severity.High => "HighBrush", Severity.Medium => "MediumBrush", Severity.Low => "LowBrush", _ => "InfoBrush" };
}
