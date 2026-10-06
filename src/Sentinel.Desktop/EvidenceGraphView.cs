using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.Core;

namespace Sentinel.Desktop;

internal sealed class EvidenceGraphView : StackPanel
{
    private readonly EnvironmentSnapshot _snapshot;
    private readonly Canvas _canvas = new() { Width = 2100, Height = 1800, Background = Brushes.Transparent };
    private readonly Border _viewport = new() { ClipToBounds = true, Height = 580, CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 0, 14, 0) };
    private readonly StackPanel _detail = new();
    private readonly TextBlock _count = Ui.Text("", 12, "MutedBrush");
    private readonly TextBox _search = Ui.Input(width: 320);
    private readonly ComboBox _kind = Ui.Select(new[] { "All relationships" }.Concat(Enum.GetNames<EvidenceKind>()), "All relationships");
    private readonly Dictionary<string, Button> _buttons = [];
    private readonly Dictionary<string, Line> _lines = [];
    private Matrix _matrix = new(0.58, 0, 0, 0.58, 14, 15);
    private Point? _drag;

    public EvidenceGraphView(EnvironmentSnapshot snapshot)
    {
        _snapshot = snapshot;
        Children.Add(Ui.Text("Interactive evidence relationships", 22, bold: true));
        Children.Add(Ui.Text("Select nodes or edges to inspect provenance. Drag the background to pan; use the wheel or zoom controls. Amber edges participate in defensive paths. The graph never executes a relationship.", 13, "MutedBrush"));
        _search.ToolTip = "Filter graph label or ID; matching nodes include their immediate neighbors";
        Children.Add(Ui.Row(_search, _kind, Ui.Button("＋", () => Zoom(1.15)), Ui.Button("−", () => Zoom(1 / 1.15)), Ui.Button("Reset view", Reset)));
        Children.Add(_count);
        _viewport.SetResourceReference(Border.BackgroundProperty, "BackgroundBrush");
        _viewport.Child = _canvas;
        var layout = new Grid(); layout.ColumnDefinitions.Add(new ColumnDefinition()); layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
        layout.Children.Add(_viewport);
        var detailScroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 580 };
        Grid.SetColumn(detailScroll, 1); layout.Children.Add(detailScroll);
        Children.Add(Ui.Card(layout, 16));
        Children.Add(Ui.Text("For readability, each view displays up to 80 evidence nodes. Filter by label or type to inspect a focused neighborhood. Full evidence remains in the repository and structured reports.", 12, "MutedBrush"));
        _search.TextChanged += (_, _) => Draw(); _kind.SelectionChanged += (_, _) => Draw();
        _viewport.PreviewMouseWheel += (_, e) => { Zoom(e.Delta > 0 ? 1.12 : 1 / 1.12, e.GetPosition(_viewport)); e.Handled = true; };
        _canvas.MouseLeftButtonDown += (_, e) =>
        {
            if (e.OriginalSource != _canvas) return;
            _drag = e.GetPosition(_viewport); _canvas.CaptureMouse(); _viewport.Cursor = Cursors.SizeAll; e.Handled = true;
        };
        _canvas.MouseMove += (_, e) =>
        {
            if (_drag is not Point old) return;
            var current = e.GetPosition(_viewport); _matrix.Translate(current.X - old.X, current.Y - old.Y); _drag = current; ApplyTransform();
        };
        _canvas.MouseLeftButtonUp += (_, _) => { _drag = null; _canvas.ReleaseMouseCapture(); _viewport.Cursor = Cursors.Arrow; };
        _canvas.LostMouseCapture += (_, _) => _drag = null;
        Draw();
    }

    private void Draw()
    {
        _canvas.Children.Clear(); _buttons.Clear(); _lines.Clear(); _detail.Children.Clear();
        var term = _search.Text.Trim(); var kind = _kind.SelectedItem?.ToString();
        var matches = _snapshot.Nodes.Where(n => (kind == "All relationships" || n.Kind.ToString() == kind) && $"{n.Label} {n.Id}".Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();
        var focus = matches.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        var edges = _snapshot.Edges.Where(e => focus.Contains(e.SourceId) || focus.Contains(e.TargetId)).ToList();
        var neighborIds = edges.SelectMany(e => new[] { e.SourceId, e.TargetId }).ToHashSet(StringComparer.Ordinal);
        var nodes = matches.Concat(_snapshot.Nodes.Where(n => neighborIds.Contains(n.Id) && !focus.Contains(n.Id))).OrderByDescending(n => n.Kind == EvidenceKind.Internet).ThenByDescending(n => edges.Any(e => e.EnablesPath && (e.SourceId == n.Id || e.TargetId == n.Id))).Take(80).ToList();
        var ids = nodes.Select(n => n.Id).ToHashSet(); edges = edges.Where(e => ids.Contains(e.SourceId) && ids.Contains(e.TargetId)).ToList();
        _count.Text = $"{nodes.Count} displayed of {_snapshot.Nodes.Count} evidence nodes · {edges.Count} relationships · {matches.Count} direct matches";
        var positions = new Dictionary<string, Point>();
        var groups = nodes.GroupBy(n => Group(n.Kind)).OrderBy(g => g.Key).ToList();
        foreach (var group in groups)
        {
            var label = Ui.Text(GroupLabel(group.Key), 13, "MutedBrush", true); Canvas.SetLeft(label, 30 + group.Key * 335); Canvas.SetTop(label, 5); _canvas.Children.Add(label);
            var index = 0;
            foreach (var node in group)
            {
                positions[node.Id] = new Point(30 + group.Key * 335 + (index / 18) * 170, 45 + (index % 18) * 90); index++;
            }
        }
        foreach (var edge in edges)
        {
            var source = positions[edge.SourceId]; var target = positions[edge.TargetId];
            var line = new Line { X1 = source.X + 77, Y1 = source.Y + 35, X2 = target.X + 77, Y2 = target.Y + 35, StrokeThickness = edge.EnablesPath ? 2.5 : 1.4, Opacity = 0.7, ToolTip = $"{edge.Relationship} · confidence {edge.Confidence:P0}" };
            line.SetResourceReference(Shape.StrokeProperty, edge.EnablesPath ? "HighBrush" : "BorderBrush");
            line.MouseLeftButtonDown += (_, e) => { SelectEdge(edge); e.Handled = true; };
            _canvas.Children.Add(line); _lines[edge.Id] = line;
            var arrow = new Polygon { Points = Arrow(source, target), Fill = Ui.Brush(edge.EnablesPath ? "HighBrush" : "MutedBrush"), Opacity = 0.7, IsHitTestVisible = false };
            _canvas.Children.Add(arrow);
        }
        foreach (var node in nodes)
        {
            var position = positions[node.Id];
            var button = Ui.Button("", () => SelectNode(node)); button.Width = 154; button.Height = 70; button.Padding = new Thickness(10, 7, 10, 7); button.HorizontalContentAlignment = HorizontalAlignment.Left;
            button.Content = Ui.Stack(Ui.Text(node.Kind.ToString().ToUpperInvariant(), 11, node.Kind is EvidenceKind.Finding or EvidenceKind.Vulnerability ? "HighBrush" : "AccentBrush", true), Ui.Text(node.Label.Length > 40 ? node.Label[..37] + "…" : node.Label, 12, bold: true));
            button.ToolTip = $"{node.Label}\n{node.Source}\nConfidence {node.Confidence:P0}";
            Canvas.SetLeft(button, position.X); Canvas.SetTop(button, position.Y); _canvas.Children.Add(button); _buttons[node.Id] = button;
        }
        _detail.Children.Add(Ui.Text("Inspect evidence", 19, bold: true));
        _detail.Children.Add(Ui.Text(nodes.Count == 0 ? "No evidence nodes match. Collect evidence or adjust the filter." : "Select a node or relationship to see source, confidence, observation time, and related records.", brush: "MutedBrush"));
        ApplyTransform();
    }

    private void SelectNode(EvidenceNode node)
    {
        foreach (var button in _buttons.Values) button.SetResourceReference(Control.BorderBrushProperty, "BorderBrush");
        if (_buttons.TryGetValue(node.Id, out var selected)) selected.SetResourceReference(Control.BorderBrushProperty, "AccentBrush");
        foreach (var edge in _snapshot.Edges)
            if (_lines.TryGetValue(edge.Id, out var line)) { line.Opacity = edge.SourceId == node.Id || edge.TargetId == node.Id ? 1 : 0.22; line.StrokeThickness = edge.SourceId == node.Id || edge.TargetId == node.Id ? 3 : 1.4; }
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Text(node.Label, 20, bold: true)); _detail.Children.Add(Ui.Text(node.Kind.ToString(), 12, "AccentBrush", true));
        _detail.Children.Add(Ui.Text($"Source: {node.Source}\nConfidence: {node.Confidence:P0}\nObserved: {node.ObservedAt.LocalDateTime:g}", 12, "MutedBrush"));
        foreach (var pair in node.Properties) _detail.Children.Add(Ui.Text($"{pair.Key}: {pair.Value}", 13));
        _detail.Children.Add(Ui.Text("Relationships", 16, bold: true));
        foreach (var edge in _snapshot.Edges.Where(e => e.SourceId == node.Id || e.TargetId == node.Id).Take(30))
        {
            var otherId = edge.SourceId == node.Id ? edge.TargetId : edge.SourceId;
            var other = _snapshot.Nodes.FirstOrDefault(n => n.Id == otherId);
            _detail.Children.Add(Ui.Button($"{edge.Relationship}\n{other?.Label ?? otherId}", () => SelectEdge(edge)));
        }
        _detail.Children.Add(Ui.Text("Evidence ID: " + node.Id, 10, "MutedBrush"));
    }

    private void SelectEdge(EvidenceEdge edge)
    {
        foreach (var line in _lines.Values) line.Opacity = 0.3;
        if (_lines.TryGetValue(edge.Id, out var selected)) { selected.Opacity = 1; selected.StrokeThickness = 4; }
        _detail.Children.Clear();
        _detail.Children.Add(Ui.Text(edge.Relationship, 20, bold: true));
        foreach (var id in new[] { edge.SourceId, edge.TargetId }) { var node = _snapshot.Nodes.FirstOrDefault(n => n.Id == id); if (node is not null) _detail.Children.Add(Ui.Button(node.Label, () => SelectNode(node))); }
        _detail.Children.Add(Ui.Text($"Confidence: {edge.Confidence:P0}\nPath enabling evidence: {(edge.EnablesPath ? "Yes" : "No")}", 12, "MutedBrush"));
        if (!string.IsNullOrWhiteSpace(edge.DefensiveBreak)) { _detail.Children.Add(Ui.Text("Defensive break", 16, "AccentBrush", true)); _detail.Children.Add(Ui.Text(edge.DefensiveBreak)); }
        _detail.Children.Add(Ui.Text("Supporting findings", 16, bold: true));
        foreach (var id in edge.FindingIds) _detail.Children.Add(Ui.Text(_snapshot.Findings.FirstOrDefault(f => f.Id == id)?.Title ?? id, 13));
        _detail.Children.Add(Ui.Text("Relationship ID: " + edge.Id, 10, "MutedBrush"));
    }

    private void Zoom(double factor, Point? center = null)
    {
        var next = _matrix.M11 * factor;
        if (next < 0.3 || next > 2.5) return;
        var point = center ?? new Point(_viewport.ActualWidth / 2, _viewport.ActualHeight / 2);
        _matrix.ScaleAt(factor, factor, point.X, point.Y); ApplyTransform();
    }
    private void Reset() { _matrix = new Matrix(0.58, 0, 0, 0.58, 14, 15); ApplyTransform(); }
    private void ApplyTransform() => _canvas.RenderTransform = new MatrixTransform(_matrix);
    private static int Group(EvidenceKind kind) => kind switch { EvidenceKind.Internet or EvidenceKind.Domain or EvidenceKind.IP => 0, EvidenceKind.Service or EvidenceKind.Certificate => 1, EvidenceKind.Asset or EvidenceKind.CloudResource or EvidenceKind.Software => 2, EvidenceKind.Finding or EvidenceKind.Vulnerability => 3, EvidenceKind.Identity or EvidenceKind.Permission => 4, _ => 5 };
    private static string GroupLabel(int group) => group switch { 0 => "EXPOSURE", 1 => "SERVICES & TRUST", 2 => "ASSETS & SOFTWARE", 3 => "FINDINGS", 4 => "IDENTITY & ACCESS", _ => "CONTROLS" };
    private static PointCollection Arrow(Point source, Point target)
    {
        var from = new Point(source.X + 77, source.Y + 35); var to = new Point(target.X + 77, target.Y + 35);
        var dx = to.X - from.X; var dy = to.Y - from.Y; var length = Math.Sqrt(dx * dx + dy * dy);
        if (length < 1) return [];
        var ux = dx / length; var uy = dy / length; var tip = new Point(to.X - ux * 50, to.Y - uy * 50);
        return [tip, new Point(tip.X - ux * 9 + uy * 4, tip.Y - uy * 9 - ux * 4), new Point(tip.X - ux * 9 - uy * 4, tip.Y - uy * 9 + ux * 4)];
    }
}
