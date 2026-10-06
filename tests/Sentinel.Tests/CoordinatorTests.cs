using Sentinel.Core;
using Sentinel.Infrastructure;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class CoordinatorTests
{
    public static async Task Run(TestRunner test)
    {
        await test.Check("First-launch Demo and Live workspaces initialize actual analytics independently", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var application = new ApplicationCoordinator(repository); await application.InitializeAsync();
            var demo = await application.OpenAsync(EnvironmentMode.Demo);
            Assert(demo.Assets.Count > 250 && application.AttackPaths.Count >= 5 && application.Remediations.Count > 0 && application.Risk.CategoryScores.Count == 8, "Demo bypasses actual product engines.");
            var live = await application.OpenAsync(EnvironmentMode.Live); Equal(0, live.Assets.Count, "Live starts with demo assets"); Equal(0, application.Risk.CategoryScores.Count, "Empty Live is shown as assessed");
            Equal(EnvironmentMode.Live, (await application.GetSettingsAsync()).LastEnvironment!.Value, "First launch mode preference");
            Equal(demo.Assets.Count, (await application.OpenAsync(EnvironmentMode.Demo)).Assets.Count, "Switching environments lost offline lab");
        });
        await test.Check("Coordinator forbids live scans in Demo and rejects unauthorized or unavailable engines", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var engine = new FixtureEngine(_ => Task.FromResult(EmptyResult()));
            var unavailable = new FixtureEngine(_ => Task.FromResult(EmptyResult()), "unavailable", false);
            var app = new ApplicationCoordinator(repository, [engine, unavailable]); await app.OpenAsync(EnvironmentMode.Demo);
            await Throws<InvalidOperationException>(() => app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope()));
            await app.OpenAsync(EnvironmentMode.Live);
            await Throws<ArgumentException>(() => app.RunScanAsync(engine.Descriptor.Id, new ScanScope()));
            await Throws<InvalidOperationException>(() => app.RunScanAsync("unavailable", AuthorizedScope()));
            await Throws<ArgumentException>(() => app.RunScanAsync("missing", AuthorizedScope()));
            Equal(0, engine.Calls, "Collection ran outside approved workflow"); Equal(0, app.Current!.Scans.Count, "Rejected collection became scan history");
        });
        await test.Check("Coordinator cancellation persists a cancelled run without partial evidence", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var engine = new FixtureEngine(async token => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return Result("partial"); });
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live);
            using var cancellation = new CancellationTokenSource(); var scan = app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope(), cancellationToken: cancellation.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancellation.Cancel();
            await Throws<OperationCanceledException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
            Equal(0, app.Current!.Assets.Count, "Partial scan asset committed"); Equal(ScanStatus.Cancelled, app.Current.Scans.Single().Status, "Cancellation disposition");
            Equal(0, (await repository.LoadAsync(EnvironmentMode.Live))!.Assets.Count, "Partial asset persisted to disk");
            Assert((await repository.ReadAuditAsync()).Any(x => x.Action == "scan.cancelled"), "Cancellation audit missing.");
        });
        await test.Check("Cancellation after engine return still prevents evidence commit", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db")); using var cancellation = new CancellationTokenSource();
            var engine = new FixtureEngine(_ => { cancellation.Cancel(); return Task.FromResult(Result("returned-partial")); });
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live);
            await Throws<OperationCanceledException>(() => app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope(), cancellationToken: cancellation.Token));
            Equal(0, app.Current!.Assets.Count, "Post-return cancellation committed output"); Equal(ScanStatus.Cancelled, app.Current.Scans.Single().Status, "Post-return cancellation state");
        });
        await test.Check("Failed collection preserves previous findings and reports a human-readable event", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var engine = new FixtureEngine(_ => throw new IOException("Sensitive internal path should not appear as a user stack trace"));
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("existing"), "qa-engine");
            await Throws<IOException>(() => app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope()));
            Equal(1, app.Current!.Assets.Count, "Failed scan removed previous assets"); Equal(FindingStatus.Open, app.Current.Findings.Single().Status, "Failed scan cleared previous finding");
            var run = app.Current.Scans.Single(); Equal(ScanStatus.Failed, run.Status, "Failure disposition");
            Assert(run.Message.Contains(run.EventId) && !run.Message.Contains("Sensitive internal path"), "Normal scan history exposed internal exception details.");
        });
        await test.Check("Unavailable target output does not imply a previously observed finding was fixed", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var engine = new FixtureEngine(_ => Task.FromResult(EmptyResult("Target unavailable; posture unknown")));
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("existing"), "qa-engine");
            await app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope());
            Equal(FindingStatus.Open, app.Current!.Findings.Single().Status, "Unavailability silently resolved risk");
            Equal(1, app.Current.Assets.Count, "Unavailability deleted inventory");
        });
        await test.Check("Only a completed assessment of all affected assets resolves a prior engine finding", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var engine = new FixtureEngine(_ => Task.FromResult(new EngineResult([new Asset { Id = "existing", Name = "Existing endpoint" }], [], [new EvidenceNode { Id = "existing", Kind = EvidenceKind.Asset }], [],
                [new Observation { Id = "complete", AssetId = "existing", EngineId = "qa-engine", Property = "AssessmentComplete", Value = "true" }], [], ["Assessment completed"])));
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("existing"), "qa-engine");
            await app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope());
            var finding = app.Current!.Findings.Single(); Equal(FindingStatus.Fixed, finding.Status, "Fresh verified no-gap posture did not resolve finding"); Assert(finding.FixedAt is not null, "Resolution lacks timestamp.");
            Assert(app.Current.Changes.Any(x => x.Kind == "Resolved finding") && app.Current.ScoreHistory.Count >= 2, "Resolution lacks timeline/score evidence.");
        });
        await test.Check("Operator acceptance persists across repeat collection while risk remains modeled", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var engine = new FixtureEngine(_ => Task.FromResult(Result("existing")));
            var app = new ApplicationCoordinator(repository, [engine]); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("existing"), "qa-engine");
            var findingId = app.Current!.Findings.Single().Id; var total = app.Risk.TotalRisk;
            await Throws<ArgumentException>(() => app.UpdateFindingAsync(findingId, FindingStatus.AcceptedRisk, "", DateTimeOffset.UtcNow.AddDays(7)));
            await Throws<ArgumentException>(() => app.UpdateFindingAsync(findingId, FindingStatus.AcceptedRisk, "QA exception", DateTimeOffset.UtcNow.AddDays(-1)));
            await app.UpdateFindingAsync(findingId, FindingStatus.AcceptedRisk, "QA owner accepted pending scheduled fix", DateTimeOffset.UtcNow.AddDays(7));
            Equal(total, app.Risk.TotalRisk, "Acceptance erased exposure");
            await app.RunScanAsync(engine.Descriptor.Id, AuthorizedScope());
            Equal(FindingStatus.AcceptedRisk, app.Current.Findings.Single().Status, "Repeated scan lost operator disposition");
            Assert(app.Current.Findings.Single().DispositionReason.Contains("QA owner"), "Disposition reason lost.");
        });
        await test.Check("Interrupted running scans recover as failed without imported partial output", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            await repository.SaveAsync(new EnvironmentSnapshot { Id = "live", Mode = EnvironmentMode.Live, Scans = [new ScanRun { Id = "interrupted", Status = ScanStatus.Running }] });
            var app = new ApplicationCoordinator(repository); var current = await app.OpenAsync(EnvironmentMode.Live);
            Equal(ScanStatus.Failed, current.Scans.Single().Status, "Interrupted scan still appears running");
            Assert(current.Scans[0].Message.Contains("interrupted") && current.Assets.Count == 0, "Recovery invented output.");
        });
        await test.Check("Settings validate themes and retention before saving operator changes", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db")); var app = new ApplicationCoordinator(repository);
            await app.SaveSettingsAsync(new AppSettings { Theme = "Dark", RetentionDays = 90 }); Equal("Dark", (await app.GetSettingsAsync()).Theme, "Coordinator theme persistence");
            await Throws<ArgumentException>(() => app.SaveSettingsAsync(new AppSettings { Theme = "Invisible" }));
            await Throws<ArgumentException>(() => app.SaveSettingsAsync(new AppSettings { RetentionDays = 1 }));
            Equal("Dark", (await app.GetSettingsAsync()).Theme, "Rejected settings replaced preference");
        });
        await test.Check("Asset business importance recalculates risk while retirement preserves unresolved evidence", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var app = new ApplicationCoordinator(repository); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("business-asset"), "qa-engine");
            await app.UpdateAssetAsync("business-asset", "QA asset owner", 1, "Owner confirmed low-impact test workload");
            var lowerImportanceRisk = app.Risk.TotalRisk;
            await app.UpdateAssetAsync("business-asset", "Finance operations", 5, "Owner identified a critical finance dependency");
            Assert(app.Risk.TotalRisk > lowerImportanceRisk, "Business importance did not update contextual risk.");
            var criticalRisk = app.Risk.TotalRisk;
            await Throws<ArgumentException>(() => app.UpdateAssetAsync("business-asset", "Finance operations", 0, "Invalid importance"));
            await Throws<ArgumentException>(() => app.UpdateAssetAsync("business-asset", "", 5, "Missing owner"));
            await app.UpdateAssetAsync("business-asset", "Finance operations", 5, "Operator attests planned retirement; exposure still requires verification", retired: true);
            Equal(criticalRisk, app.Risk.TotalRisk, "Retirement declaration erased unresolved risk");
            Equal(FindingStatus.Open, app.Current!.Findings.Single().Status, "Retirement closed a finding without verification");
            var persisted = (await repository.LoadAsync(EnvironmentMode.Live))!;
            Equal(1, persisted.Assets.Count, "Retirement deleted historical inventory");
            Equal("Operator retired", persisted.Assets.Single().Properties["lifecycle"], "Retirement state persistence");
            Equal("Finance operations", persisted.Assets.Single().Owner, "Business owner persistence");
            Assert(persisted.Changes.Any(x => x.Kind == "Removed asset (operator attested)"), "Operator retirement lacks an attested timeline event.");
        });
        await test.Check("Incident lifecycle persists owner status notes and evidence while malformed cases are rejected", async () =>
        {
            using var temp = new TemporaryDirectory(); using var repository = new SQLiteEnvironmentRepository(temp.File("sentinel.db"));
            var app = new ApplicationCoordinator(repository); await app.OpenAsync(EnvironmentMode.Live); await app.ImportAsync(Result("case-asset"), "qa-engine");
            var findingId = app.Current!.Findings.Single().Id;
            await Throws<ArgumentException>(() => app.CreateIncidentAsync("", "QA investigator", [findingId]));
            await Throws<ArgumentException>(() => app.CreateIncidentAsync("Unsupported case", "QA investigator", ["unknown-finding"]));
            await Throws<ArgumentException>(() => app.CreateIncidentAsync("Empty case", "QA investigator", []));
            Equal(0, app.Current.Incidents.Count, "Malformed incident was persisted");
            await app.CreateIncidentAsync("Review observed configuration risk", "QA investigator", [findingId, findingId]);
            var id = app.Current.Incidents.Single().Id;
            await app.UpdateIncidentAsync(id, "Investigating", "Security operations", "Owner is reviewing the collected finding evidence.");
            await app.UpdateIncidentAsync(id, "Contained", "Security operations", "Approved access restriction recorded; remediation verification remains pending.");
            await Throws<ArgumentException>(() => app.UpdateIncidentAsync(id, "Unrecognized", "Security operations", "Invalid lifecycle status"));
            await Throws<ArgumentException>(() => app.UpdateIncidentAsync(id, "Resolved", "Security operations", ""));
            var reopened = await new ApplicationCoordinator(repository).OpenAsync(EnvironmentMode.Live);
            var incident = reopened.Incidents.Single(); Equal(id, incident.Id, "Incident identity persistence"); Equal("Contained", incident.Status, "Incident lifecycle persistence");
            Equal("Security operations", incident.Owner, "Incident owner persistence"); Equal(1, incident.FindingIds.Count, "Duplicate evidence references"); Equal(findingId, incident.FindingIds.Single(), "Incident evidence link");
            Equal(3, incident.Notes.Count, "Incident notes persistence");
            Assert(incident.Notes[0].Summary.Contains("does not confirm a security breach") && incident.Notes[^1].Summary.Contains("verification remains pending"), "Case interpretation or operator notes lost.");
            Equal(FindingStatus.Open, reopened.Findings.Single().Status, "Incident containment silently fixed its supporting finding");
            var audit = await repository.ReadAuditAsync(); Assert(audit.Any(x => x.Action == "incident.created") && audit.Any(x => x.Action == "incident.updated"), "Incident lifecycle audit missing.");
        });
        await test.Check("Normal errors contain a correlation identifier and no raw stack trace", () =>
        {
            var error = ErrorTranslator.FromException(new InvalidDataException("Raw untrusted input"));
            Assert(!string.IsNullOrWhiteSpace(error.EventId) && error.TechnicalDetails.Contains(error.EventId) && !error.Message.Contains("Raw untrusted input") && !error.Message.Contains(" at "), "Error translation leaks raw details or lacks correlation.");
            Assert(!ErrorTranslator.FromException(new OperationCanceledException()).CanRetry, "Cancellation implies an automatic retry.");
        });
    }

    private static EngineResult EmptyResult(string message = "QA empty result") => new([], [], [], [], [], [], [message]);
    private static EngineResult Result(string id) => new(
        [new Asset { Id = id, Name = "Authorized QA endpoint", Kind = AssetKind.Endpoint, BusinessCriticality = 4 }],
        [new Finding { Id = $"finding-{id}", Title = "QA configuration gap", Category = SecurityCategory.Endpoint, Severity = Severity.High, Source = "qa-engine", RootCauseKey = "qa-configuration", AssetIds = [id], EvidenceIds = [id] }],
        [new EvidenceNode { Id = id, Label = "Authorized QA asset", Kind = EvidenceKind.Asset, Source = "qa-engine" }], [], [], [], ["Authorized QA fixture"]);

    private sealed class FixtureEngine(Func<CancellationToken, Task<EngineResult>> collect, string id = "qa-engine", bool available = true) : IAssessmentEngine
    {
        public EngineDescriptor Descriptor { get; } = new(id, "Authorized QA engine", "In-process behavioral fixture", available, available ? "Available" : "QA unavailable platform");
        public int Calls { get; private set; }
        public Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken) { Calls++; return collect(cancellationToken); }
    }
}
