using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Desktop;

// Internal, read-only observability and deterministic UI operations for the Windows
// acceptance executable. No network, credentials, or operator profile is exposed.
public partial class MainWindow
{
    internal async Task WaitForTestingReadyAsync()
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (!_initialized)
        {
            if (DateTimeOffset.UtcNow >= deadline)
                throw new TimeoutException("The SENTINEL desktop did not initialize its isolated local evidence workspace within 30 seconds.");
            await Task.Delay(25);
        }
    }

    internal bool HasEnvironmentForTesting => _coordinator.Current is not null;
    internal string CurrentRouteForTesting => _route;
    internal string SnapshotJsonForTesting => JsonSerializer.Serialize(Snapshot);
    internal string AnalyticsJsonForTesting => JsonSerializer.Serialize(new
    {
        _coordinator.Risk, _coordinator.AttackPaths, _coordinator.Remediations, _coordinator.Compliance
    });

    internal Task OpenEnvironmentForTestingAsync(string mode)
        => OpenEnvironmentAsync(Enum.Parse<EnvironmentMode>(mode, ignoreCase: false));

    internal void NavigateForTesting(string route)
    {
        if (!Routes.Contains(route, StringComparer.Ordinal))
            throw new ArgumentException("The desktop acceptance harness requested an unknown navigation route.", nameof(route));
        Navigate(route);
    }

    internal void ApplyThemeForTesting(string theme)
    {
        if (theme is not ("Dark" or "Light" or "System"))
            throw new ArgumentException("Choose a supported SENTINEL theme.", nameof(theme));
        ThemeManager.Apply(theme);
        RenderPage();
    }

    internal async Task<string> SettingsJsonForTestingAsync()
        => JsonSerializer.Serialize(await _coordinator.GetSettingsAsync());

    internal async Task ExportReportForTestingAsync(string kind, string format, string path)
        => await _coordinator.ExportReportAsync(Enum.Parse<ReportKind>(kind), Enum.Parse<ReportFormat>(format), path);

    internal void DisposeRepositoryForTesting() => _repository.Dispose();
}
