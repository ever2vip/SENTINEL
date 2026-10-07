using System.Windows;
using System.Windows.Media;

namespace Sentinel.Desktop;

internal static class ThemeManager
{
    public static string ResolvedTheme { get; private set; } = "Dark";

    public static void Apply(string theme)
    {
        var light = string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase) || (string.Equals(theme, "System", StringComparison.OrdinalIgnoreCase) && IsSystemLight());
        ResolvedTheme = light ? "Light" : "Dark";
        var colors = light ? new Dictionary<string, string>
        {
            ["BackgroundBrush"] = "#F3F5F9", ["SidebarBrush"] = "#EBEFF5", ["SurfaceBrush"] = "#FFFFFF",
            ["ElevatedBrush"] = "#F0F3F8", ["BorderBrush"] = "#D7DFEA", ["ControlBorderBrush"] = "#8392A7",
            ["TextBrush"] = "#18263B", ["MutedBrush"] = "#52627B", ["AccentBrush"] = "#225FA8",
            ["AccentTextBrush"] = "#FFFFFF", ["AccentHoverBrush"] = "#1B5091", ["TealBrush"] = "#146E65",
            ["HoverBrush"] = "#E6EDF7", ["PressedBrush"] = "#DCE6F3", ["SelectionBrush"] = "#DFEBFB",
            ["FocusBrush"] = "#225FA8", ["CriticalBrush"] = "#B52E43", ["HighBrush"] = "#A75A15",
            ["MediumBrush"] = "#80640A", ["LowBrush"] = "#346BAD", ["InfoBrush"] = "#346BAD", ["SuccessBrush"] = "#14744D",
            ["CriticalSubtleBrush"] = "#FCECEF", ["HighSubtleBrush"] = "#FFF0E2", ["MediumSubtleBrush"] = "#FBF4D9",
            ["LowSubtleBrush"] = "#EAF0FA", ["InfoSubtleBrush"] = "#EAF0FA", ["SuccessSubtleBrush"] = "#E5F4EC",
            ["AccentSubtleBrush"] = "#E8EFFA", ["TealSubtleBrush"] = "#E3F2EF", ["NeutralSubtleBrush"] = "#EEF2F7"
        } : new Dictionary<string, string>
        {
            ["BackgroundBrush"] = "#0E1624", ["SidebarBrush"] = "#101A2A", ["SurfaceBrush"] = "#152133",
            ["ElevatedBrush"] = "#1B2A3F", ["BorderBrush"] = "#2B3C53", ["ControlBorderBrush"] = "#687B97",
            ["TextBrush"] = "#EBF0F8", ["MutedBrush"] = "#A8B6CC", ["AccentBrush"] = "#8CB7FC",
            ["AccentTextBrush"] = "#10223C", ["AccentHoverBrush"] = "#A8C9FF", ["TealBrush"] = "#80D6C7",
            ["HoverBrush"] = "#23354E", ["PressedBrush"] = "#2A405C", ["SelectionBrush"] = "#223D61",
            ["FocusBrush"] = "#96BCFF", ["CriticalBrush"] = "#FFA0AB", ["HighBrush"] = "#F6B782",
            ["MediumBrush"] = "#EDD28C", ["LowBrush"] = "#9CBEF7", ["InfoBrush"] = "#9CBEF7", ["SuccessBrush"] = "#8AD7AD",
            ["CriticalSubtleBrush"] = "#3B2635", ["HighSubtleBrush"] = "#3C302C", ["MediumSubtleBrush"] = "#363426",
            ["LowSubtleBrush"] = "#243A58", ["InfoSubtleBrush"] = "#243A58", ["SuccessSubtleBrush"] = "#203B35",
            ["AccentSubtleBrush"] = "#253C5E", ["TealSubtleBrush"] = "#203D40", ["NeutralSubtleBrush"] = "#223147"
        };
        foreach (var pair in colors)
        {
            var color = (Color)ColorConverter.ConvertFromString(pair.Value);
            // Preserve brush identity for graph/canvas consumers as well as DynamicResource controls.
            if (Application.Current.Resources[pair.Key] is SolidColorBrush existing && !existing.IsFrozen) existing.Color = color;
            else Application.Current.Resources[pair.Key] = new SolidColorBrush(color);
        }
    }

    private static bool IsSystemLight()
    {
        try
        {
            return Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 0) is int value && value != 0;
        }
        catch { return false; }
    }
}
