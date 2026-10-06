using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace Sentinel.Desktop;

internal static class Ui
{
    public static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
    public static TextBlock Text(string value, double size = 14, string? brush = null, bool bold = false)
    {
        var text = new TextBlock { Text = value, FontSize = size, TextWrapping = TextWrapping.Wrap, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, Margin = new Thickness(0, 0, 0, 8) };
        text.SetResourceReference(TextBlock.ForegroundProperty, brush ?? "TextBrush");
        return text;
    }
    public static StackPanel Stack(params UIElement[] children)
    {
        var stack = new StackPanel();
        foreach (var child in children) stack.Children.Add(child);
        return stack;
    }
    public static Border Card(UIElement content, double padding = 20)
    {
        var card = new Border { Child = content, Padding = new Thickness(padding), CornerRadius = new CornerRadius(10), BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 0, 16) };
        card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
        card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        return card;
    }
    public static Button Button(string label, Action click, bool primary = false)
    {
        var button = new Button { Content = label };
        if (primary) button.Style = (Style)Application.Current.FindResource("PrimaryButton");
        button.Click += (_, _) => click();
        return button;
    }
    public static StackPanel Row(params UIElement[] children)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
        foreach (var child in children) row.Children.Add(child);
        return row;
    }
    public static TextBox Input(string value = "", double width = double.NaN)
        => new() { Text = value, Width = width, Margin = new Thickness(0, 0, 8, 10), MinHeight = 36 };
    public static ComboBox Select<T>(IEnumerable<T> values, T selected)
    {
        var combo = new ComboBox { ItemsSource = values.ToArray(), SelectedItem = selected };
        return combo;
    }
    public static DataGrid Table(IEnumerable source, params (string Heading, string Path, double Width)[] columns)
    {
        var grid = new DataGrid { ItemsSource = source, MinHeight = 90, MaxHeight = 500, Margin = new Thickness(0, 8, 0, 12) };
        foreach (var column in columns)
        {
            grid.Columns.Add(new DataGridTextColumn { Header = column.Heading, Binding = new Binding(column.Path), Width = column.Width == 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(column.Width), MinWidth = 90 });
        }
        return grid;
    }
    public static Border Metric(string title, string value, string note, string color = "TextBrush")
        => Card(Stack(Text(title, 12, "MutedBrush"), Text(value, 36, color, true), Text(note, 12, "MutedBrush")));
    public static Grid Columns(params UIElement[] children)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 2) };
        for (var i = 0; i < children.Length; i++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            var wrapper = new Border { Child = children[i], Margin = new Thickness(i == 0 ? 0 : 8, 0, i == children.Length - 1 ? 0 : 8, 0) };
            Grid.SetColumn(wrapper, i);
            grid.Children.Add(wrapper);
        }
        return grid;
    }
}
