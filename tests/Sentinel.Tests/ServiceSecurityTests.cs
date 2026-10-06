using System.Text;
using System.Text.Json;
using Sentinel.Infrastructure;
using Sentinel.Service;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class ServiceSecurityTests
{
    public static async Task Run(TestRunner test)
    {
        if (!OperatingSystem.IsWindows())
            await test.Check("Secret storage fails closed on unsupported platforms without plaintext fallback", async () =>
            {
                using var temp = new TemporaryDirectory(); var directory = temp.File("secrets"); var store = new DpapiSecretStore(directory);
                await Throws<PlatformNotSupportedException>(() => store.SetAsync("qa-key", "SENTINEL_QA_SECRET"));
                await Throws<PlatformNotSupportedException>(() => store.GetAsync("qa-key"));
                await Throws<PlatformNotSupportedException>(() => store.DeleteAsync("qa-key"));
                Assert(!Directory.Exists(directory), "Unsupported platform created a plaintext secret store.");
            });
        else
            await test.Check("Windows DPAPI secrets round trip as ciphertext and support deletion", async () =>
            {
                using var temp = new TemporaryDirectory(); var store = new DpapiSecretStore(temp.File("secrets"));
                await store.SetAsync("qa-key", "SENTINEL_QA_SECRET"); Equal("SENTINEL_QA_SECRET", (await store.GetAsync("qa-key"))!, "DPAPI round trip");
                Assert(Directory.GetFiles(temp.File("secrets")).All(path => !Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains("SENTINEL_QA_SECRET")), "Secret persisted in plaintext.");
                await store.DeleteAsync("qa-key"); Assert(await store.GetAsync("qa-key") is null, "Deleted secret remained readable.");
            });
        await test.Check("Service health is atomic and advertises maintenance rather than assessments", async () =>
        {
            using var temp = new TemporaryDirectory(); var store = new MaintenanceStore(temp.Path);
            await store.WriteHealthAsync("healthy", "QA health", default); await store.WriteHealthAsync("stopped", "QA stopped", default);
            using var health = JsonDocument.Parse(await File.ReadAllTextAsync(temp.File("ServiceState/health.json")));
            Equal("stopped", health.RootElement.GetProperty("status").GetString()!, "Service lifecycle state");
            Assert(!health.RootElement.GetProperty("assessmentsEnabled").GetBoolean(), "Maintenance service advertises autonomous assessments.");
            Assert(!File.Exists(temp.File("ServiceState/health.tmp")), "Atomic health write left temporary output.");
        });
        await test.Check("Service audit is structured and includes distinct correlation identifiers", async () =>
        {
            using var temp = new TemporaryDirectory(); var store = new MaintenanceStore(temp.Path);
            await store.AppendAuditAsync("qa-start", "Authorized QA maintenance", default); await store.AppendAuditAsync("qa-stop", "Authorized QA shutdown", default);
            var lines = File.ReadAllLines(Directory.GetFiles(temp.File("ServiceLogs")).Single()); Equal(2, lines.Length, "Service audit count");
            using var first = JsonDocument.Parse(lines[0]); using var second = JsonDocument.Parse(lines[1]);
            Assert(first.RootElement.GetProperty("correlationId").GetString() != second.RootElement.GetProperty("correlationId").GetString(), "Service audit reuses correlation ID.");
        });
        await test.Check("Service log retention requires opt-in and stays within its own log directory", async () =>
        {
            using var temp = new TemporaryDirectory(); var store = new MaintenanceStore(temp.Path);
            var expired = temp.File("ServiceLogs/maintenance-2000-01-01.jsonl"); var other = temp.File("ServiceLogs/operator-data.json"); var external = temp.File("outside-service.jsonl");
            await File.WriteAllTextAsync(expired, "old service log"); await File.WriteAllTextAsync(other, "operator-owned data"); await File.WriteAllTextAsync(external, "outside log directory");
            File.SetLastWriteTimeUtc(expired, DateTime.UtcNow.AddDays(-100)); File.SetLastWriteTimeUtc(other, DateTime.UtcNow.AddDays(-100)); File.SetLastWriteTimeUtc(external, DateTime.UtcNow.AddDays(-100));
            Equal(0, await store.PruneOptInLogsAsync(default), "Retention ran without opt-in");
            await File.WriteAllTextAsync(temp.File("maintenance-settings.json"), JsonSerializer.Serialize(new MaintenanceSettings(true, 30)));
            Equal(1, await store.PruneOptInLogsAsync(default), "Expired service log removal");
            Assert(!File.Exists(expired) && File.Exists(other) && File.Exists(external), "Service retention crossed ownership boundary.");
        });
        await test.Check("Invalid service retention policies cannot delete service logs", async () =>
        {
            using var temp = new TemporaryDirectory(); var store = new MaintenanceStore(temp.Path);
            var log = temp.File("ServiceLogs/maintenance-old.jsonl"); await File.WriteAllTextAsync(log, "old fixture"); File.SetLastWriteTimeUtc(log, DateTime.UtcNow.AddDays(-100));
            await File.WriteAllTextAsync(temp.File("maintenance-settings.json"), JsonSerializer.Serialize(new MaintenanceSettings(true, 1)));
            await Throws<InvalidDataException>(() => store.PruneOptInLogsAsync(default)); Assert(File.Exists(log), "Invalid retention deleted a log.");
        });
    }
}
