using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Service;

public sealed class MaintenanceWorker(MaintenanceStore store, ILogger<MaintenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await store.AppendAuditAsync("maintenance.started", "SENTINEL maintenance service started. No assessments are scheduled or executed by this service.", stoppingToken);
        var nextRetention = DateTimeOffset.MinValue;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        try
        {
            do
            {
                try
                {
                    if (DateTimeOffset.UtcNow >= nextRetention)
                    {
                        var removed = await store.PruneOptInLogsAsync(stoppingToken);
                        if (removed > 0) await store.AppendAuditAsync("maintenance.retention", $"Removed {removed} expired service log files under configured retention.", stoppingToken);
                        nextRetention = DateTimeOffset.UtcNow.AddHours(6);
                    }
                    await store.WriteHealthAsync("healthy", "Service maintenance is available. Assessments run only from an authorized desktop session.", stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
                {
                    var correlationId = Guid.NewGuid().ToString("N");
                    logger.LogWarning("Service maintenance could not complete. Event {EventId}, correlation {CorrelationId}, failure type {FailureType}.", "maintenance.failed", correlationId, exception.GetType().Name);
                    await store.WriteHealthAsync("degraded", $"Service maintenance could not complete. Review service directory permissions and maintenance settings. Correlation ID: {correlationId}", stoppingToken);
                    await store.AppendAuditAsync("maintenance.failed", $"Maintenance failed ({exception.GetType().Name}); correlation ID: {correlationId}.", stoppingToken);
                    nextRetention = DateTimeOffset.UtcNow.AddMinutes(5);
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            // SCM cancellation receives a bounded local-file shutdown and never leaves a scan running.
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await store.WriteHealthAsync("stopped", "SENTINEL maintenance service stopped.", shutdown.Token);
                await store.AppendAuditAsync("maintenance.stopped", "Service stopped cleanly.", shutdown.Token);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException)
            {
                logger.LogWarning("Service shutdown status could not be written. Failure type {FailureType}.", exception.GetType().Name);
            }
        }
    }
}
