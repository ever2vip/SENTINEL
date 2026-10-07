using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Sentinel.Desktop;

/// <summary>Resolution-independent, original outline icons; no font or network dependency.</summary>
internal static class Icons
{
    public static FrameworkElement Create(string name, double size = 20, string key = "MutedBrush")
    {
        var normalized = new string(name.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        string[] data = normalized switch
        {
            "commandcenter" or "dashboard" => ["M3,3 H10 V10 H3 Z M14,3 H21 V7 H14 Z M14,11 H21 V21 H14 Z M3,14 H10 V21 H3 Z"],
            "asset" or "assets" => ["M3,4 H21 V16 H3 Z M8,21 H16 M12,16 V21", "M7,8 H11 M7,11 H16"],
            "endpoint" or "endpoints" or "device" => ["M5,3 H19 V18 H5 Z M8,21 H16 M10,18 V21 M14,18 V21", "M9,7 H15 M9,11 H15 M9,15 H11"],
            "network" or "topology" => ["M9,2 H15 V8 H9 Z M2,16 H8 V22 H2 Z M16,16 H22 V22 H16 Z M12,8 V12 M5,16 V12 H19 V16"],
            "vulnerability" or "vulnerabilities" => ["M12,3 L22,20 H2 Z M12,8 V13", "M12,16 V16.4"],
            "finding" or "findings" or "incident" or "incidents" or "alert" => ["M12,2 L21,7 V17 L12,22 L3,17 V7 Z M12,7 V13", "M12,17 V17.4"],
            "identity" or "user" or "profile" => ["M8,6 A4,4 0 1 0 16,6 A4,4 0 1 0 8,6 M4,22 V19 C4,15 8,13 12,13 C16,13 20,15 20,19 V22"],
            "activedirectory" or "users" => ["M9,5 A3,3 0 1 0 15,5 A3,3 0 1 0 9,5 M6,17 C6,10 18,10 18,17 M3,5 H5 M19,5 H21 M3,9 V20 H21 V9 M12,17 V20"],
            "cloud" or "cloudresource" => ["M6,19 C0,19 0,10 6,10 C6,2 18,1 19,10 C25,11 24,19 18,19 Z"],
            "web" or "websecurity" or "internet" or "domain" => ["M2,12 A10,10 0 1 0 22,12 A10,10 0 1 0 2,12 M2,12 H22 M4,6 H20 M4,18 H20 M12,2 C5,9 5,15 12,22 C19,15 19,9 12,2"],
            "attacksurface" or "target" => ["M3,12 A9,9 0 1 0 21,12 A9,9 0 1 0 3,12 M8,12 A4,4 0 1 0 16,12 A4,4 0 1 0 8,12 M12,1 V5 M12,19 V23 M1,12 H5 M19,12 H23"],
            "attackpath" or "attackpaths" or "path" => ["M2,3 H8 V9 H2 Z M16,15 H22 V21 H16 Z M8,6 H16 V12 H19 V15 M13,9 L16,12 L19,9"],
            "evidencegraph" or "graph" => ["M2,12 A3,3 0 1 0 8,12 A3,3 0 1 0 2,12 M15,5 A3,3 0 1 0 21,5 A3,3 0 1 0 15,5 M15,19 A3,3 0 1 0 21,19 A3,3 0 1 0 15,19 M8,10 L15,6 M8,14 L15,18 M18,8 V16"],
            "compliance" or "control" or "shield" or "security" => ["M12,2 L21,6 V12 C21,17 17,21 12,23 C7,21 3,17 3,12 V6 Z M7,12 L11,16 L17,9"],
            "monitoring" or "pulse" => ["M2,12 H6 L9,5 L13,19 L16,10 L18,12 H22"],
            "remediation" or "wrench" => ["M14,3 C19,0 24,5 21,10 L17,8 L14,11 L16,15 L7,22 L2,17 L11,10 L9,6 Z"],
            "reports" or "report" or "document" => ["M5,2 H14 L20,8 V22 H5 Z M14,2 V8 H20 M9,12 H16 M9,16 H16 M9,19 H13"],
            "aianalyst" or "analyst" or "conversation" => ["M3,3 H21 V17 H10 L5,22 V17 H3 Z M7,8 H17 M7,12 H14"],
            "integrations" or "plug" => ["M8,2 V7 M16,2 V7 M5,7 H19 V10 C19,14 16,17 12,17 C8,17 5,14 5,10 Z M12,17 V22"],
            "settings" or "configure" => ["M3,6 H21 M3,12 H21 M3,18 H21", "M7,3 V9 M16,9 V15 M10,15 V21"],
            "permission" or "key" => ["M3,8 A5,5 0 1 0 13,8 A5,5 0 1 0 3,8 M12,11 L22,21 M18,17 L21,14 M16,15 L19,12"],
            "service" or "server" => ["M3,3 H21 V10 H3 Z M3,14 H21 V21 H3 Z M7,6.5 H8 M7,17.5 H8 M12,6.5 H17 M12,17.5 H17"],
            "software" or "package" => ["M12,2 L22,7 V17 L12,22 L2,17 V7 Z M2,7 L12,12 L22,7 M12,12 V22 M7,4.5 L17,9.5"],
            "ip" or "ipaddress" => ["M3,4 H21 V20 H3 Z M7,9 H8 M11,9 H12 M15,9 H16 M7,15 H8 M11,15 H12 M15,15 H16"],
            "certificate" => ["M5,2 H19 V16 H5 Z M9,6 H15 M9,9 H15", "M9,15 A3,3 0 1 0 15,15 A3,3 0 1 0 9,15 M10,18 L9,23 L12,21 L15,23 L14,18"],
            "search" => ["M3,10 A7,7 0 1 0 17,10 A7,7 0 1 0 3,10 M15,15 L22,22"],
            "filter" => ["M3,4 H21 L14,12 V20 L10,22 V12 Z"],
            "menu" => ["M3,6 H21 M3,12 H21 M3,18 H21"],
            "chevrondown" or "expand" => ["M6,9 L12,15 L18,9"],
            "chevronright" => ["M9,6 L15,12 L9,18"],
            "chevronleft" or "back" => ["M15,6 L9,12 L15,18"],
            "close" => ["M5,5 L19,19 M19,5 L5,19"],
            "check" or "verified" => ["M4,12 L9,17 L20,6"],
            "plus" => ["M12,4 V20 M4,12 H20"],
            "minus" => ["M4,12 H20"],
            "download" or "export" => ["M12,2 V16 M6,10 L12,16 L18,10 M3,16 V22 H21 V16"],
            "refresh" or "reset" => ["M20,8 C18,2 8,1 4,7 M4,7 V2 M4,7 H9 M4,16 C6,22 16,23 20,17 M20,17 V22 M20,17 H15"],
            "focus" or "fit" or "fitgraph" => ["M3,9 V3 H9 M15,3 H21 V9 M21,15 V21 H15 M9,21 H3 V15 M9,12 H15 M12,9 V15"],
            "zoomin" => ["M3,10 A7,7 0 1 0 17,10 A7,7 0 1 0 3,10 M15,15 L22,22 M6,10 H14 M10,6 V14"],
            "zoomout" => ["M3,10 A7,7 0 1 0 17,10 A7,7 0 1 0 3,10 M15,15 L22,22 M6,10 H14"],
            "notifications" or "bell" => ["M5,16 H19 L17,12 V8 C17,1 7,1 7,8 V12 Z M9,20 C10,23 14,23 15,20"],
            "clock" or "history" => ["M2,12 A10,10 0 1 0 22,12 A10,10 0 1 0 2,12 M12,6 V12 L16,15"],
            "calendar" => ["M3,5 H21 V22 H3 Z M3,10 H21 M7,2 V8 M17,2 V8 M7,14 H10 M14,14 H17 M7,18 H10"],
            "sun" or "light" => ["M7,12 A5,5 0 1 0 17,12 A5,5 0 1 0 7,12 M12,1 V4 M12,20 V23 M1,12 H4 M20,12 H23 M4,4 L6,6 M18,18 L20,20 M4,20 L6,18 M18,6 L20,4"],
            "moon" or "dark" => ["M20,16 C11,18 5,10 9,3 C-1,6 1,21 12,22 C16,22 19,19 20,16 Z"],
            "external" or "open" => ["M14,2 H22 V10 M22,2 L11,13 M10,4 H3 V21 H20 V14"],
            "up" or "trendup" => ["M3,18 L10,11 L14,15 L21,6 M15,6 H21 V12"],
            "down" or "trenddown" => ["M3,6 L10,13 L14,9 L21,18 M15,18 H21 V12"],
            "info" or "help" => ["M2,12 A10,10 0 1 0 22,12 A10,10 0 1 0 2,12 M12,10 V17", "M12,6.5 V7"],
            "live" or "lock" => ["M5,10 H19 V22 H5 Z M8,10 V6 A4,4 0 1 1 16,6 V10 M12,14 V18"],
            "demo" or "lab" => ["M8,2 H16 M9,2 V10 L3,20 C2,22 4,22 6,22 H18 C20,22 22,22 21,20 L15,10 V2 M6,16 H18"],
            _ => ["M12,2 L21,6 V12 C21,17 17,21 12,23 C7,21 3,17 3,12 V6 Z M7,12 L11,16 L17,9"]
        };
        var drawing = new Canvas { Width = 24, Height = 24, IsHitTestVisible = false };
        foreach (var item in data)
        {
            var path = new System.Windows.Shapes.Path { Data = Geometry.Parse(item), StrokeThickness = 1.65, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round, IsHitTestVisible = false };
            path.SetResourceReference(Shape.StrokeProperty, key);
            drawing.Children.Add(path);
        }
        return new Viewbox { Width = size, Height = size, Child = drawing, Stretch = Stretch.Uniform, IsHitTestVisible = false, Focusable = false, VerticalAlignment = VerticalAlignment.Center };
    }
}
