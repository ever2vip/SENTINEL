using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Media;

namespace Sentinel.Desktop;

internal static class Ui
{
    public static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
    public static TextBlock Text(string value, double size = 14, string? brush = null, bool bold = false)
    {
        size = Math.Max(DesignTokens.Meta, size);
        var text = new TextBlock { Text = value, FontSize = size, TextWrapping = TextWrapping.Wrap, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, LineHeight = size * 1.4, Margin = new Thickness(0, 0, 0, DesignTokens.SpaceSm) };
        text.SetResourceReference(TextBlock.ForegroundProperty, brush ?? "TextBrush");
        return text;
    }
    public static StackPanel Stack(params UIElement[] children)
    {
        var stack = new StackPanel();
        foreach (var child in children) stack.Children.Add(child);
        return stack;
    }
    public static Border Card(UIElement content, double padding = 24)
    {
        var card = new Border { Child = content, Padding = new Thickness(padding), CornerRadius = new CornerRadius(DesignTokens.CardRadius), BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 0, DesignTokens.SpaceLg) };
        card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
        card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        return card;
    }
    public static Button Button(string label, Action click, bool primary = false)
    {
        var button = new Button { Content = label };
        AutomationProperties.SetName(button, label);
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
    {
        var input = new TextBox { Text = value, Width = width, Margin = new Thickness(0, 0, DesignTokens.SpaceSm, DesignTokens.SpaceSm), MinHeight = DesignTokens.ControlHeight };
        input.Loaded += (_, _) =>
        {
            if (!string.IsNullOrWhiteSpace(AutomationProperties.GetName(input))) return;
            if (input.ToolTip is string purpose && !string.IsNullOrWhiteSpace(purpose)) AutomationProperties.SetName(input, purpose);
            else if (input.Parent is Panel panel && panel.Children.IndexOf(input) is var index && index > 0 && panel.Children[index - 1] is TextBlock label)
                AutomationProperties.SetLabeledBy(input, label);
        };
        return input;
    }
    public static TextBox Input(string value, double width, string accessibleName)
    {
        var input = Input(value, width);
        AutomationProperties.SetName(input, accessibleName);
        return input;
    }
    public static TextBox Search(string placeholder, double width = 300)
    {
        var input = Input(width: width);
        input.Tag = placeholder;
        input.ToolTip = placeholder;
        input.Style = (Style)Application.Current.FindResource("SearchTextBoxStyle");
        AutomationProperties.SetName(input, placeholder);
        input.KeyDown += (_, args) => { if (args.Key == Key.Escape && input.Text.Length > 0) { input.Clear(); args.Handled = true; } };
        return input;
    }
    public static FrameworkElement Icon(string name, double size = 20, string key = "MutedBrush") => Icons.Create(name, size, key);
    public static Button IconButton(string label, string icon, Action click)
    {
        var button = Button(label, click);
        button.Content = Icon(icon);
        button.ToolTip = label;
        button.Width = DesignTokens.ControlHeight;
        button.Height = DesignTokens.ControlHeight;
        button.Padding = new Thickness(8);
        return button;
    }
    public static Border Badge(string label, string color = "MutedBrush")
    {
        var text = Text(label, DesignTokens.Meta, color, true);
        text.Margin = new Thickness(0);
        text.TextWrapping = TextWrapping.NoWrap;
        var background = color switch
        {
            "CriticalBrush" => "CriticalSubtleBrush", "HighBrush" => "HighSubtleBrush", "MediumBrush" => "MediumSubtleBrush",
            "LowBrush" => "LowSubtleBrush", "InfoBrush" => "InfoSubtleBrush", "SuccessBrush" => "SuccessSubtleBrush",
            "AccentBrush" => "AccentSubtleBrush", "TealBrush" => "TealSubtleBrush", _ => "NeutralSubtleBrush"
        };
        var badge = new Border { Child = text, Padding = new Thickness(8, 3, 8, 3), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 8, 4), VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left, ToolTip = label };
        badge.SetResourceReference(Border.BackgroundProperty, background);
        AutomationProperties.SetName(badge, label);
        return badge;
    }
    public static WrapPanel Toolbar(params UIElement[] children)
    {
        var panel = new WrapPanel { Margin = new Thickness(0, 0, 0, DesignTokens.SpaceSm), VerticalAlignment = VerticalAlignment.Center };
        foreach (var child in children)
        {
            if (child is FrameworkElement element)
            {
                element.Margin = new Thickness(element.Margin.Left, element.Margin.Top, Math.Max(DesignTokens.SpaceSm, element.Margin.Right), Math.Max(DesignTokens.SpaceSm, element.Margin.Bottom));
                element.VerticalAlignment = VerticalAlignment.Center;
                if (element is TextBlock) element.Margin = new Thickness(0, 0, 12, 8);
            }
            panel.Children.Add(child);
        }
        return panel;
    }
    public static StackPanel Section(string title, string? subtitle = null)
    {
        var panel = Stack(Text(title, DesignTokens.SectionTitle, bold: true));
        if (!string.IsNullOrWhiteSpace(subtitle)) panel.Children.Add(Text(subtitle, brush: "MutedBrush"));
        return panel;
    }
    public static Border Empty(string title, string message, string icon = "search")
    {
        var content = Stack(Icon(icon, 32), Text(title, 18, bold: true), Text(message, brush: "MutedBrush"));
        content.Margin = new Thickness(0, 8, 0, 8);
        return Card(content);
    }
    public static ComboBox Select<T>(IEnumerable<T> values, T selected)
    {
        var combo = new ComboBox { ItemsSource = values.ToArray(), SelectedItem = selected };
        AutomationProperties.SetName(combo, selected?.ToString() ?? typeof(T).Name);
        return combo;
    }
    public static DataGrid Table(IEnumerable source, params (string Heading, string Path, double Width)[] columns)
    {
        var grid = new DataGrid { ItemsSource = source, MinHeight = 90, MaxHeight = 500, Margin = new Thickness(0, 8, 0, 12), FontSize = 14 };
        AutomationProperties.SetName(grid, "Evidence records");
        ScrollViewer.SetCanContentScroll(grid, true);
        VirtualizingPanel.SetVirtualizationMode(grid, VirtualizationMode.Recycling);
        foreach (var column in columns)
        {
            grid.Columns.Add(new DataGridTextColumn { Header = column.Heading, Binding = new Binding(column.Path), Width = column.Width == 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(column.Width), MinWidth = 90 });
        }
        return grid;
    }
    public static Border Metric(string title, string value, string note, string color = "TextBrush")
        => Card(Stack(Text(title, 12, "MutedBrush", true), Text(value, 34, color, true), Text(note, 12, "MutedBrush")));
    public static Grid Columns(params UIElement[] children)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 2) };
        var wrappers = new List<Border>();
        for (var i = 0; i < children.Length; i++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            var wrapper = new Border { Child = children[i], Margin = new Thickness(i == 0 ? 0 : 8, 0, i == children.Length - 1 ? 0 : 8, 0) };
            Grid.SetColumn(wrapper, i);
            grid.Children.Add(wrapper);
            wrappers.Add(wrapper);
        }
        var previousColumns = children.Length;
        grid.SizeChanged += (_, args) =>
        {
            if (children.Length < 2 || args.NewSize.Width < 1) return;
            var columns = Math.Clamp((int)(args.NewSize.Width / 280), 1, children.Length);
            if (columns == previousColumns) return;
            previousColumns = columns;
            grid.ColumnDefinitions.Clear();
            grid.RowDefinitions.Clear();
            for (var column = 0; column < columns; column++) grid.ColumnDefinitions.Add(new ColumnDefinition());
            for (var row = 0; row < (children.Length + columns - 1) / columns; row++) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            for (var i = 0; i < wrappers.Count; i++)
            {
                Grid.SetColumn(wrappers[i], i % columns);
                Grid.SetRow(wrappers[i], i / columns);
                wrappers[i].Margin = new Thickness(i % columns == 0 ? 0 : 8, 0, i % columns == columns - 1 ? 0 : 8, 0);
            }
        };
        return grid;
    }
}
