using System.Text.Json;

namespace Sentinel.Service;

/// <summary>Owns service files only. Never reads operator databases or connector credentials.</summary>
public sealed class MaintenanceStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _root;
    private readonly string _stateDirectory;
    private readonly string _logsDirectory;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly string _instanceId = Guid.NewGuid().ToString("N");

    public MaintenanceStore(string root)
    {
        _root = Path.GetFullPath(root);
        _stateDirectory = Path.Combine(_root, "ServiceState");
        _logsDirectory = Path.Combine(_root, "ServiceLogs");
        Directory.CreateDirectory(_stateDirectory);
        Directory.CreateDirectory(_logsDirectory);
    }

    public async Task WriteHealthAsync(string status, string message, CancellationToken cancellationToken)
    {
        var document = new
        {
            schemaVersion = 1,
            serviceName = "SentinelMaintenance",
            productVersion = typeof(MaintenanceStore).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            status,
            message,
            instanceId = _instanceId,
            startedAtUtc = _startedAt,
            heartbeatAtUtc = DateTimeOffset.UtcNow,
            capabilities = new[] { "service-health", "opt-in-service-log-retention" },
            assessmentsEnabled = false
        };
        var destination = Path.Combine(_stateDirectory, "health.json");
        var temporary = Path.Combine(_stateDirectory, "health.tmp");
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(document, JsonOptions), cancellationToken);
        File.Move(temporary, destination, overwrite: true);
    }

    public Task AppendAuditAsync(string eventId, string message, CancellationToken cancellationToken)
    {
        var record = JsonSerializer.Serialize(new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            eventId,
            correlationId = Guid.NewGuid().ToString("N"),
            instanceId = _instanceId,
            message
        });
        return File.AppendAllTextAsync(Path.Combine(_logsDirectory, $"maintenance-{DateTime.UtcNow:yyyy-MM-dd}.jsonl"), record + Environment.NewLine, cancellationToken);
    }

    public async Task<int> PruneOptInLogsAsync(CancellationToken cancellationToken)
    {
        var settingsPath = Path.Combine(_root, "maintenance-settings.json");
        if (!File.Exists(settingsPath)) return 0;
        var json = await File.ReadAllTextAsync(settingsPath, cancellationToken);
        var settings = JsonSerializer.Deserialize<MaintenanceSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (settings is null || !settings.EnableServiceLogRetention) return 0;
        if (settings.ServiceLogRetentionDays is < 7 or > 365)
            throw new InvalidDataException("Service log retention must be between 7 and 365 days.");

        var threshold = DateTimeOffset.UtcNow.AddDays(-settings.ServiceLogRetentionDays);
        var removed = 0;
        foreach (var file in Directory.EnumerateFiles(_logsDirectory, "maintenance-*.jsonl", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(file);
            // Never follow a link or delete outside this service's own log directory.
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
            if (info.LastWriteTimeUtc >= threshold.UtcDateTime) continue;
            info.Delete();
            removed++;
        }
        return removed;
    }
}

public sealed record MaintenanceSettings(bool EnableServiceLogRetention = false, int ServiceLogRetentionDays = 30);
