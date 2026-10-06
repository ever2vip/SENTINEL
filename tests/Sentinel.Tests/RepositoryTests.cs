using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Infrastructure;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class RepositoryTests
{
    public static async Task Run(TestRunner test)
    {
        await test.Check("First database creation exposes defaults without inventing an environment", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            await repository.InitializeAsync(); await repository.InitializeAsync();
            Assert(await repository.LoadAsync(EnvironmentMode.Live) is null && await repository.LoadAsync(EnvironmentMode.Demo) is null, "Fresh database contains a fabricated workspace.");
            var settings = await repository.GetSettingsAsync();
            Equal("System", settings.Theme, "First launch theme"); Assert(settings.LastEnvironment is null && !settings.AiEnabled, "First launch enables AI or assumes an environment.");
            Equal(2L, await Scalar(temp.File("sentinel.db"), "PRAGMA user_version;"), "Current migration version");
        });
        await test.Check("Demo and Live persist separately and preserve immutable asset history", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var demo = new DemoLab().Create(CoreTests.FixtureTime);
            await repository.SaveAsync(demo);
            var before = demo.Assets[0].OperatingSystem;
            demo.Assets[0].OperatingSystem = "Changed synthetic OS"; await repository.SaveAsync(demo);
            var live = new EnvironmentSnapshot { Id = "live-test", Name = "Authorized QA", Mode = EnvironmentMode.Live };
            await repository.SaveAsync(live);
            Equal("live-test", (await repository.LoadAsync(EnvironmentMode.Live))!.Id, "Live workspace contaminated by demo");
            Equal("Changed synthetic OS", (await repository.LoadAsync(EnvironmentMode.Demo))!.Assets[0].OperatingSystem, "Current asset state");
            var history = await repository.ReadHistoryAsync(EnvironmentMode.Demo);
            Equal(2, history.Count, "Historical snapshot count");
            Equal(before, history[1].Assets[0].OperatingSystem, "Earlier snapshot mutated");
            Assert(history[0].Nodes.Count > 900, "Graph lost during storage round trip.");
        });
        await test.Check("Dark Light and System settings survive database reopening", async () =>
        {
            using var temp = new TemporaryDirectory(); var path = temp.File("sentinel.db");
            foreach (var theme in new[] { "Dark", "Light", "System" })
            {
                using (var repository = new SQLiteEnvironmentRepository(path))
                    await repository.SaveSettingsAsync(new AppSettings { Theme = theme, RetentionDays = 180, LastEnvironment = EnvironmentMode.Demo, AiEnabled = false });
                using var reopened = new SQLiteEnvironmentRepository(path);
                var settings = await reopened.GetSettingsAsync(); Equal(theme, settings.Theme, "Theme persistence"); Equal(180, settings.RetentionDays, "Retention persistence");
                Equal(EnvironmentMode.Demo, settings.LastEnvironment!.Value, "Last environment persistence");
            }
        });
        await test.Check("Invalid settings and credential-bearing AI endpoints are rejected", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            await Throws<ArgumentException>(() => repository.SaveSettingsAsync(new AppSettings { Theme = "Invisible" }));
            await Throws<ArgumentException>(() => repository.SaveSettingsAsync(new AppSettings { RetentionDays = 0 }));
            foreach (var endpoint in new[] { "http://example.invalid", "https://user:secret@example.invalid", "https://example.invalid/?api_key=secret" })
                await Throws<ArgumentException>(() => repository.SaveSettingsAsync(new AppSettings { AiEndpoint = endpoint }));
            Equal("System", (await repository.GetSettingsAsync()).Theme, "Invalid setting contaminated stored defaults");
        });
        await test.Check("Database version-one upgrade preserves data and backfills the evidence graph", async () =>
        {
            using var temp = new TemporaryDirectory(); var path = temp.File("version1.db");
            var demo = new DemoLab().Create(CoreTests.FixtureTime);
            await using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                await connection.OpenAsync(); await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE environment_snapshots(mode INTEGER PRIMARY KEY, environment_id TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL);
                    CREATE TABLE snapshot_history(id INTEGER PRIMARY KEY AUTOINCREMENT, mode INTEGER NOT NULL, environment_id TEXT NOT NULL, saved_at TEXT NOT NULL, payload TEXT NOT NULL);
                    CREATE TABLE settings(id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
                    CREATE TABLE audit_entries(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL, entity_id TEXT NOT NULL, detail TEXT NOT NULL, event_id TEXT NOT NULL);
                    INSERT INTO environment_snapshots(mode,environment_id,updated_at,payload) VALUES(0,$id,$at,$payload);
                    PRAGMA user_version=1;
                    """;
                command.Parameters.AddWithValue("$id", demo.Id); command.Parameters.AddWithValue("$at", demo.UpdatedAt.ToString("O")); command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(demo));
                await command.ExecuteNonQueryAsync();
            }
            using var repository = new SQLiteEnvironmentRepository(path); await repository.InitializeAsync();
            Equal(demo.Assets.Count, (await repository.LoadAsync(EnvironmentMode.Demo))!.Assets.Count, "Upgrade lost asset inventory");
            Equal(2L, await Scalar(path, "PRAGMA user_version;"), "Upgrade schema");
            Equal((long)demo.Nodes.Count, await Scalar(path, "SELECT COUNT(*) FROM evidence_nodes;"), "Graph node backfill");
            Equal((long)demo.Edges.Count, await Scalar(path, "SELECT COUNT(*) FROM evidence_edges;"), "Graph edge backfill");
        });
        await test.Check("Forward database schemas and malformed saved payloads fail closed", async () =>
        {
            using var temp = new TemporaryDirectory(); var path = temp.File("sentinel.db");
            using (var repository = new SQLiteEnvironmentRepository(path)) await repository.SaveAsync(new EnvironmentSnapshot { Id = "live", Mode = EnvironmentMode.Live });
            await Execute(path, "UPDATE environment_snapshots SET payload='{ malformed';");
            using (var repository = new SQLiteEnvironmentRepository(path)) await Throws<InvalidDataException>(() => repository.LoadAsync(EnvironmentMode.Live));
            await Execute(path, "PRAGMA user_version=999;");
            using var future = new SQLiteEnvironmentRepository(path); await Throws<InvalidDataException>(() => future.InitializeAsync());
        });
        await test.Check("Rejected snapshots and cancellation preserve the previous committed workspace", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var snapshot = new EnvironmentSnapshot { Id = "good", Mode = EnvironmentMode.Live }; await repository.SaveAsync(snapshot);
            var malformed = new EnvironmentSnapshot { Id = "bad", Mode = EnvironmentMode.Live, Assets = [new Asset { Id = "duplicate" }, new Asset { Id = "duplicate" }] };
            await Throws<InvalidDataException>(() => repository.SaveAsync(malformed));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Throws<OperationCanceledException>(() => repository.SaveAsync(new EnvironmentSnapshot { Id = "cancelled", Mode = EnvironmentMode.Live }, cancelled.Token));
            Equal("good", (await repository.LoadAsync(EnvironmentMode.Live))!.Id, "Failed save replaced committed workspace");
            Equal(1, (await repository.ReadHistoryAsync(EnvironmentMode.Live)).Count, "Failed save entered history");
        });
        await test.Check("Retention prunes old history while retaining current assets and unresolved risks", async () =>
        {
            using var temp = new TemporaryDirectory(); var path = temp.File("sentinel.db"); using var repository = new SQLiteEnvironmentRepository(path);
            var old = DateTimeOffset.UtcNow.AddDays(-100); var now = DateTimeOffset.UtcNow;
            var snapshot = new EnvironmentSnapshot
            {
                Id = "retention-test", Mode = EnvironmentMode.Live, Assets = [new Asset { Id = "asset", LastSeen = old }],
                Findings = [new Finding { Id = "open", Status = FindingStatus.Open, LastSeen = old }, new Finding { Id = "accepted", Status = FindingStatus.AcceptedRisk, LastSeen = old }, new Finding { Id = "fixed-old", Status = FindingStatus.Fixed, FixedAt = old }, new Finding { Id = "fixed-new", Status = FindingStatus.Fixed, FixedAt = now }],
                Observations = [new Observation { Id = "old", ObservedAt = old }, new Observation { Id = "new", ObservedAt = now }],
                Changes = [new ChangeEvent { Id = "old", At = old }, new ChangeEvent { Id = "new", At = now }],
                Scans = [new ScanRun { Id = "complete-old", Status = ScanStatus.Completed, StartedAt = old, FinishedAt = old }, new ScanRun { Id = "running-old", Status = ScanStatus.Running, StartedAt = old }, new ScanRun { Id = "complete-new", Status = ScanStatus.Completed, StartedAt = now, FinishedAt = now }],
                ScoreHistory = [new ScoreHistory { At = old, Score = 40 }, new ScoreHistory { At = now, Score = 55 }]
            };
            await repository.SaveAsync(snapshot); await repository.SaveAsync(snapshot);
            await Execute(path, $"UPDATE snapshot_history SET saved_at='{old:O}' WHERE id=(SELECT MIN(id) FROM snapshot_history);");
            await repository.AuditAsync(new AuditEntry(old, "expired-audit", "asset", "Old fixture", "old-event"));
            await repository.ApplyRetentionAsync(30);
            var current = (await repository.LoadAsync(EnvironmentMode.Live))!;
            Equal(1, current.Assets.Count, "Stale current inventory was deleted");
            Assert(current.Findings.Any(x => x.Id == "open") && current.Findings.Any(x => x.Id == "accepted") && current.Findings.All(x => x.Id != "fixed-old"), "Risk retention is incorrect.");
            Assert(current.Scans.Any(x => x.Id == "running-old") && current.Scans.All(x => x.Id != "complete-old"), "Scan retention is incorrect.");
            Equal(1, current.Observations.Count, "Observation retention"); Equal(1, current.Changes.Count, "Change retention"); Equal(1, current.ScoreHistory.Count, "Score retention");
            Equal(1, (await repository.ReadHistoryAsync(EnvironmentMode.Live)).Count, "Snapshot retention");
            Assert((await repository.ReadAuditAsync()).All(x => x.Action != "expired-audit"), "Expired audit retained.");
        });
        await test.Check("Audit round trips retain correlation and operator context", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            await repository.AuditAsync(new AuditEntry(DateTimeOffset.UtcNow, "authorized", "scope", "QA exact loopback scope", "qa-correlation"));
            var audit = (await repository.ReadAuditAsync()).Single(); Equal("qa-correlation", audit.EventId, "Correlation identifier"); Equal("QA exact loopback scope", audit.Detail, "Audit detail");
            await Throws<ArgumentOutOfRangeException>(() => repository.ReadAuditAsync(0));
        });
    }

    private static async Task<long> Scalar(string path, string sql)
    {
        await using var connection = new SqliteConnection($"Data Source={path}"); await connection.OpenAsync();
        await using var command = connection.CreateCommand(); command.CommandText = sql; return Convert.ToInt64(await command.ExecuteScalarAsync());
    }
    private static async Task Execute(string path, string sql)
    {
        await using var connection = new SqliteConnection($"Data Source={path}"); await connection.OpenAsync();
        await using var command = connection.CreateCommand(); command.CommandText = sql; await command.ExecuteNonQueryAsync();
    }
}
