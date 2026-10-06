using System.Windows;
using System.Windows.Media;

namespace Sentinel.Desktop;

internal static class ThemeManager
{
    public static void Apply(string theme)
    {
        var light = theme == "Light" || (theme == "System" && IsSystemLight());
        var colors = light ? new Dictionary<string, string>
        {
            ["BackgroundBrush"] = "#F0F4F8", ["SidebarBrush"] = "#E7EDF4", ["SurfaceBrush"] = "#FFFFFF",
            ["ElevatedBrush"] = "#E8F0F7", ["BorderBrush"] = "#CCD8E6", ["TextBrush"] = "#17283C",
            ["MutedBrush"] = "#53667F", ["AccentBrush"] = "#167C6B", ["AccentTextBrush"] = "#FFFFFF",
            ["CriticalBrush"] = "#B52E43", ["HighBrush"] = "#A85B16", ["MediumBrush"] = "#886B06"
        } : new Dictionary<string, string>
        {
            ["BackgroundBrush"] = "#0D131D", ["SidebarBrush"] = "#111A28", ["SurfaceBrush"] = "#172232",
            ["ElevatedBrush"] = "#1D2B3D", ["BorderBrush"] = "#2A3A50", ["TextBrush"] = "#EAF0F7",
            ["MutedBrush"] = "#A5B5C9", ["AccentBrush"] = "#78D8C5", ["AccentTextBrush"] = "#102923",
            ["CriticalBrush"] = "#FF8E96", ["HighBrush"] = "#F8B375", ["MediumBrush"] = "#EDD285"
        };
        foreach (var pair in colors) Application.Current.Resources[pair.Key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(pair.Value));
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
