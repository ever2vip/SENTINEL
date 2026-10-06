using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Engines;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class EngineContractTests
{
    private static readonly JsonSerializerOptions ImportJson = new() { Converters = { new JsonStringEnumConverter() } };
    public static async Task Run(TestRunner test)
    {
        await test.Check("Collection requires a named unexpired exact-scope authorization", () =>
        {
            Throws<ArgumentException>(() => ScopeGuard.Validate(new ScanScope()));
            var expired = AuthorizedScope(); expired.AuthorizedAt = DateTimeOffset.UtcNow.AddDays(-2); Throws<ArgumentException>(() => ScopeGuard.Validate(expired));
            var future = AuthorizedScope(); future.AuthorizedAt = DateTimeOffset.UtcNow.AddHours(1); Throws<ArgumentException>(() => ScopeGuard.Validate(future));
            var unnamed = AuthorizedScope(); unnamed.AuthorizedBy = ""; Throws<ArgumentException>(() => ScopeGuard.Validate(unnamed));
        });
        await test.Check("Malformed hosts ranges and credential URLs cannot expand scope", () =>
        {
            foreach (var host in new[] { "10.0.0.0/8", "*.example.invalid", "server:443", "256.256.256.256", "host..example.invalid", " user.example.invalid", "user@example.invalid", "127.0.0.1/path" })
            { var scope = AuthorizedScope(); scope.Hosts.Add(host); Throws<ArgumentException>(() => ScopeGuard.Validate(scope)); }
            foreach (var url in new[] { "https://user:secret@example.invalid/", "https://example.invalid/?token=secret", "ftp://example.invalid/", "https://example.invalid/#secret", "https://*.example.invalid/" })
            { var scope = AuthorizedScope(); scope.WebUrls.Add(url); Throws<ArgumentException>(() => ScopeGuard.Validate(scope)); }
            Equal("example.invalid", ScopeGuard.NormalizeHost("EXAMPLE.INVALID"), "Host normalization");
        });
        await test.Check("Collection workload concurrency timeout and ports are bounded", () =>
        {
            var scope = AuthorizedScope(); scope.MaxConcurrency = 17; Throws<ArgumentException>(() => ScopeGuard.Validate(scope));
            scope = AuthorizedScope(); scope.TimeoutSeconds = 31; Throws<ArgumentException>(() => ScopeGuard.Validate(scope));
            scope = AuthorizedScope(); scope.Ports.Add(65535); Throws<ArgumentException>(() => ScopeGuard.Validate(scope));
            scope = AuthorizedScope(); scope.Hosts = Enumerable.Range(1, 129).Select(i => $"host{i}.example.invalid").ToList(); Throws<ArgumentException>(() => ScopeGuard.Validate(scope));
        });
        await test.Check("All assessment engines stop for precancelled collection", async () =>
        {
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            foreach (var engine in new IAssessmentEngine[] { new NetworkPostureEngine(), new WebPostureEngine(), new LocalEndpointEngine(), new EmailPostureEngine(new FixtureDns("Success", [])) })
                await Throws<OperationCanceledException>(() => engine.AssessAsync(new ScanContext(AuthorizedScope()), cancelled.Token));
        });
        await test.Check("Network collection never equates reachability with public exposure", async () =>
        {
            var scope = AuthorizedScope(); scope.Hosts = ["127.0.0.1"]; scope.Ports = [8080];
            var result = await new NetworkPostureEngine().AssessAsync(new ScanContext(scope), default);
            Assert(result.Assets.Count == 1 && result.Assets[0].Exposure == 0, "TCP collection invented Internet exposure.");
            Assert(result.Observations.Any(x => x.Property == "Public exposure" && x.Value.StartsWith("Unknown")), "Exposure uncertainty absent.");
            Assert(result.Findings.All(x => x.Severity is Severity.Low or Severity.Informational), "Unverified TCP reachability reported as verified high-risk service.");
        });
        if (!OperatingSystem.IsWindows())
            await test.Check("Windows-only endpoint collection honestly reports unavailable on Linux", async () =>
            {
                var engine = new LocalEndpointEngine(); var scope = AuthorizedScope(); scope.IncludeLocalEndpoint = true;
                var result = await engine.AssessAsync(new ScanContext(scope), default);
                Assert(!engine.Descriptor.IsAvailable && result.Assets.Count == 0 && result.Findings.Count == 0, "Unavailable Windows assessment fabricated evidence.");
            });
        else test.Skip("Windows local endpoint posture", "Actual local posture is machine-dependent; authorized desktop validation is documented separately.");
        await test.Check("DNS resolver failures remain unknown rather than missing-policy findings", async () =>
        {
            var resolver = new FixtureDns("TimedOut", []); var scope = AuthorizedScope(); scope.Hosts = ["northstar.example.invalid"];
            var result = await new EmailPostureEngine(resolver).AssessAsync(new ScanContext(scope), default);
            Equal(0, result.Findings.Count, "DNS timeout generated false policy failures");
            Assert(resolver.Names.SequenceEqual(new[] { "northstar.example.invalid", "_dmarc.northstar.example.invalid" }), "Email assessment guessed selectors or expanded domain scope.");
            Assert(result.Observations.Any(x => x.Property == "DKIM" && x.Value.StartsWith("Unknown")), "DKIM absence was guessed.");
        });
        await test.Check("SPF and DMARC findings follow actual resolver evidence", async () =>
        {
            var scope = AuthorizedScope(); scope.Hosts = ["northstar.example.invalid"];
            var result = await new EmailPostureEngine(new FixtureDns("Success", ["v=spf1 +all", "v=DMARC1; p=none"])).AssessAsync(new ScanContext(scope), default);
            Assert(result.Findings.Any(x => x.RootCauseKey == "spf-permissive") && result.Findings.Any(x => x.RootCauseKey == "dmarc-monitor-only"), "Collected permissive policy did not create findings.");
            Assert(result.Findings.All(x => x.Source == "email"), "Engine finding provenance absent.");
        });
        await test.Check("Web HEAD collection does not follow even a reachable redirect", async () =>
        {
            await using var sink = new LoopbackHttpServer("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await using var server = new LoopbackHttpServer($"HTTP/1.1 302 Found\r\nLocation: {sink.Url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            var scope = AuthorizedScope(); scope.WebUrls = [server.Url];
            var result = await new WebPostureEngine().AssessAsync(new ScanContext(scope), default);
            Equal(1, server.Requests, "HEAD request count"); Equal("HEAD", server.Method!, "Request method"); Equal(0, sink.Requests, "Redirect crossed exact URL boundary");
            Assert(result.Observations.Any(x => x.Property == "Redirect" && x.Value.Contains("Not followed")), "Redirect behavior absent from evidence.");
            Assert(result.Findings.All(x => x.RootCauseKey == "https-required"), "Application headers assessed on a redirect.");
        });
        await test.Check("Web cookie posture retains attributes but excludes secret cookie values", async () =>
        {
            await using var server = new LoopbackHttpServer("HTTP/1.1 200 OK\r\nSet-Cookie: session=SENTINEL_QA_COOKIE_SECRET; Path=/\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            var scope = AuthorizedScope(); scope.WebUrls = [server.Url];
            var result = await new WebPostureEngine().AssessAsync(new ScanContext(scope), default);
            Assert(result.Findings.Any(x => x.RootCauseKey == "cookie-httponly"), "Missing cookie protection not reported.");
            Assert(!JsonSerializer.Serialize(result).Contains("SENTINEL_QA_COOKIE_SECRET"), "Cookie value entered evidence storage.");
        });
        await test.Check("In-flight web cancellation interrupts a stalled authorized HEAD", async () =>
        {
            await using var server = new LoopbackHttpServer(null); var scope = AuthorizedScope(); scope.TimeoutSeconds = 30; scope.WebUrls = [server.Url];
            using var cancellation = new CancellationTokenSource();
            var collection = new WebPostureEngine().AssessAsync(new ScanContext(scope), cancellation.Token);
            await server.RequestReceived.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancellation.Cancel();
            await Throws<OperationCanceledException>(() => collection.WaitAsync(TimeSpan.FromSeconds(5)));
        });
        await test.Check("Unavailable web targets do not fabricate headers certificates or completed posture", async () =>
        {
            string unavailableUrl; await using (var server = new LoopbackHttpServer(null)) unavailableUrl = server.Url;
            var scope = AuthorizedScope(); scope.WebUrls = [unavailableUrl];
            var result = await new WebPostureEngine().AssessAsync(new ScanContext(scope), default);
            Equal(0, result.Findings.Count, "Unavailable URL created configuration findings"); Equal(0, result.Certificates.Count, "Unavailable URL created certificates");
            Assert(result.Observations.Any(x => x.Value.StartsWith("Unknown")) && !result.Observations.Any(x => x.Property == "AssessmentComplete" && x.Value == "true"), "Unavailable target treated as completed posture.");
        });
        await test.Check("Authorized exports preserve stable namespace provenance unknown MFA and graph integrity", async () =>
        {
            var envelope = Envelope(); using var a = Stream(envelope); using var b = Stream(envelope);
            var importer = new ExportedEvidenceImporter(); var first = await importer.ImportAsync(a, Authorization()); var second = await importer.ImportAsync(b, Authorization());
            Equal(first.Result.Assets[0].Id, second.Result.Assets[0].Id, "Repeated import changed identifiers"); Equal(first.Sha256, second.Sha256, "Repeated import changed file hash");
            Assert(first.Result.Findings.All(x => x.Source == "import:azure" && x.Confidence <= .95), "Operator-supplied evidence presented as verified live data.");
            Assert(first.Identities[0].MfaEnabled is null, "Unknown MFA became true or false.");
            var nodes = first.Result.Nodes.Select(x => x.Id).ToHashSet();
            Assert(first.Result.Edges.All(x => nodes.Contains(x.SourceId) && nodes.Contains(x.TargetId)), "Importer produced dangling graph references.");
            Assert(first.Result.Messages.Any(x => x.Contains("No live API connection")), "Importer advertises a live connector.");
        });
        await test.Check("Evidence imports require exact source organization and current authorization", async () =>
        {
            var importer = new ExportedEvidenceImporter(); var auth = Authorization(); auth.AuthorizationConfirmed = false;
            using (var input = Stream(Envelope())) await Throws<ArgumentException>(() => importer.ImportAsync(input, auth));
            var envelope = Envelope(); envelope.OrganizationId = "unapproved-tenant";
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => importer.ImportAsync(input, Authorization()));
            envelope = Envelope(); envelope.SourceId = "aws";
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => importer.ImportAsync(input, Authorization()));
        });
        await test.Check("Imports reject dangling duplicate and conflicting graph identities", async () =>
        {
            var envelope = Envelope(); envelope.Findings[0].AssetIds = ["unknown"];
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
            envelope = Envelope(); envelope.Identities.Add(envelope.Identities[0]);
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
            envelope = Envelope(); envelope.Nodes = [new EvidenceNode { Id = "resource-1", Label = "Wrong kind", Kind = EvidenceKind.Identity }];
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
        });
        await test.Check("Imports reject secret properties malformed schemas and invalid CVE metadata", async () =>
        {
            var envelope = Envelope(); envelope.Assets[0].Properties["access_token"] = "SENTINEL_QA_SECRET";
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
            envelope = Envelope(); envelope.Findings[0].Cve = "NOT-A-CVE";
            using (var input = Stream(envelope)) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
            using (var input = new MemoryStream(Encoding.UTF8.GetBytes("{ not-json"))) await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
            using (var input = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Envelope(), ImportJson)[..^1] + ",\"UnrecognizedSecretField\":\"secret\"}")))
                await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization()));
        });
        await test.Check("Import cancellation and byte limits fail before accepting evidence", async () =>
        {
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            using (var input = Stream(Envelope())) await Throws<OperationCanceledException>(() => new ExportedEvidenceImporter().ImportAsync(input, Authorization(), cancelled.Token));
            using (var oversized = new MemoryStream(new byte[ExportedEvidenceImporter.MaximumFileBytes + 1]))
                await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(oversized, Authorization()));
        });
        await test.Check("Connector descriptors honestly advertise current implementation availability", () =>
        {
            var descriptors = new ConnectorRegistry().Descriptors;
            Assert(descriptors.Any(x => x.Id == "azure") && descriptors.Any(x => x.Id == "aws"), "Missing cloud extension descriptors.");
            Assert(descriptors.All(x => x.Status.Contains("not configured") || x.Status.Contains("not connected")), "Unimplemented live integration advertised as connected.");
        });
    }

    internal static EvidenceImportEnvelope Envelope() => new()
    {
        SchemaVersion = 1, SourceId = "azure", OrganizationId = "tenant-a", CollectedAt = DateTimeOffset.UtcNow,
        Assets = [new Asset { Id = "resource-1", Name = "Exported authorized VM", Kind = AssetKind.CloudResource, Address = "/subscriptions/qa/resources/vm", BusinessCriticality = 4 }],
        Findings = [new Finding { Id = "finding-1", Title = "Exported configuration issue", RootCauseKey = "cloud-config", Severity = Severity.High, Category = SecurityCategory.Cloud, AssetIds = ["resource-1"], EvidenceIds = ["resource-1"], Confidence = 1 }],
        Identities = [new Identity { Id = "user-1", DisplayName = "Exported authorized user", Provider = "Azure", MfaEnabled = null }]
    };
    internal static EvidenceImportAuthorization Authorization() => new() { AuthorizationConfirmed = true, AuthorizedBy = "SENTINEL QA import operator", AuthorizedAt = DateTimeOffset.UtcNow, SourceId = "azure", OrganizationId = "tenant-a" };
    internal static MemoryStream Stream(EvidenceImportEnvelope envelope) => new(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope, ImportJson)));

    private sealed class FixtureDns(string status, IReadOnlyList<string> records) : IDnsTxtResolver
    {
        public List<string> Names { get; } = [];
        public Task<DnsTxtResult> QueryTxtAsync(string name, TimeSpan timeout, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Names.Add(name); return Task.FromResult(new DnsTxtResult(status, records, "Authorized QA DNS fixture")); }
    }
}

internal sealed class LoopbackHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _work;
    public string Url { get; }
    public int Requests { get; private set; }
    public string? Method { get; private set; }
    public TaskCompletionSource RequestReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public LoopbackHttpServer(string? response)
    {
        _listener.Start(); Url = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/"; _work = Run(response);
    }
    private async Task Run(string? response)
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(_stop.Token); using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var request = await reader.ReadLineAsync(_stop.Token); Method = request?.Split(' ')[0]; Requests++;
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync(_stop.Token))) { }
                RequestReceived.TrySetResult();
                if (response is not null) await stream.WriteAsync(Encoding.ASCII.GetBytes(response), _stop.Token);
                else await Task.Delay(Timeout.Infinite, _stop.Token);
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or IOException) { }
    }
    public async ValueTask DisposeAsync() { _stop.Cancel(); _listener.Stop(); await _work; _stop.Dispose(); }
}
