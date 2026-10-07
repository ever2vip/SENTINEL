using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.Core;

namespace Sentinel.Desktop;

internal sealed class ScoreTrendView : Canvas
{
    private readonly IReadOnlyList<ScoreHistory> _history;
    public ScoreTrendView(IReadOnlyList<ScoreHistory> history)
    {
        _history = history; Height = 216; ClipToBounds = true;
        SizeChanged += (_, _) => Draw(); Loaded += (_, _) => Draw();
    }
    private void Draw()
    {
        Children.Clear(); if (ActualWidth < 80 || _history.Count == 0) return;
        const double left = 40, top = 12, plotHeight = 152;
        var width = Math.Max(20, ActualWidth - left - 20);
        foreach (var tick in new[] { 0, 25, 50, 75, 100 })
        {
            var y = top + plotHeight * (1 - tick / 100.0);
            var line = new Line { X1 = left, X2 = left + width, Y1 = y, Y2 = y, StrokeThickness = 1 };
            line.SetResourceReference(Shape.StrokeProperty, "BorderBrush"); Children.Add(line);
            var label = Ui.Text(tick.ToString(CultureInfo.InvariantCulture), 12, "MutedBrush");
            SetLeft(label, 0); SetTop(label, y - 8); Children.Add(label);
        }
        var points = new PointCollection();
        var first = _history[0].At; var total = Math.Max(1, (_history[^1].At - first).TotalSeconds);
        foreach (var entry in _history)
        {
            var point = new Point(left + (_history.Count == 1 ? width / 2 : (entry.At - first).TotalSeconds / total * width), top + (1 - Math.Clamp(entry.Score, 0, 100) / 100) * plotHeight);
            points.Add(point);
            var dot = new Ellipse { Width = 10, Height = 10, ToolTip = $"{entry.At.LocalDateTime:g}\nScore {entry.Score:0.0}/100\nSource: {entry.Source}" };
            dot.SetResourceReference(Shape.FillProperty, "AccentBrush"); SetLeft(dot, point.X - 5); SetTop(dot, point.Y - 5); Children.Add(dot);
        }
        var trend = new Polyline { Points = points, StrokeThickness = 2.5, StrokeLineJoin = PenLineJoin.Round, IsHitTestVisible = false };
        trend.SetResourceReference(Shape.StrokeProperty, "AccentBrush"); Children.Insert(0, trend);
        var start = Ui.Text(first.LocalDateTime.ToString("dd MMM"), 12, "MutedBrush"); SetLeft(start, left); SetTop(start, 176); Children.Add(start);
        var end = Ui.Text(_history[^1].At.LocalDateTime.ToString("dd MMM"), 12, "MutedBrush"); SetLeft(end, Math.Max(left + 64, left + width - 50)); SetTop(end, 176); Children.Add(end);
        var source = Ui.Text(_history.All(s => s.Source.Contains("Synthetic", StringComparison.OrdinalIgnoreCase)) ? "Synthetic scenario history" : $"{_history.Count} recorded scores", 12, "MutedBrush"); SetLeft(source, left); SetTop(source, 198); Children.Add(source);
    }
}
