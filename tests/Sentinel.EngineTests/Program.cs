using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Engines;

var failures = new List<string>();
var passed = 0;
async Task Check(string name, Func<Task> action)
{
    try { await action(); passed++; Console.WriteLine("PASS " + name); }
    catch (Exception exception) { failures.Add(name + ": " + exception.Message); Console.WriteLine("FAIL " + name + ": " + exception.Message); }
}
void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
async Task Throws<T>(Func<Task> action) where T : Exception
{
    try { await action(); } catch (T) { return; }
    throw new InvalidOperationException("Expected " + typeof(T).Name);
}
ScanScope Scope() => new() { AuthorizationConfirmed = true, AuthorizedBy = "Regression operator", AuthorizedAt = DateTimeOffset.UtcNow, TimeoutSeconds = 2, MaxConcurrency = 2 };

await Check("Authorization is mandatory", () => Throws<ArgumentException>(() => { ScopeGuard.Validate(new ScanScope()); return Task.CompletedTask; }));
await Check("Authorization expires", () => Throws<ArgumentException>(() => { var scope = Scope(); scope.AuthorizedAt = DateTimeOffset.UtcNow.AddDays(-2); ScopeGuard.Validate(scope); return Task.CompletedTask; }));
await Check("Exact host boundaries reject CIDR and wildcard", async () =>
{
    foreach (var host in new[] { "192.168.0.0/16", "*.example.org", "host.example:443", "256.256.256.256", "server..example.org" })
        await Throws<ArgumentException>(() => { var scope = Scope(); scope.Hosts.Add(host); ScopeGuard.Validate(scope); return Task.CompletedTask; });
});
await Check("Scope rejects credential URLs and query secrets", async () =>
{
    foreach (var url in new[] { "https://user:password@example.org/", "https://example.org/?token=secret", "ftp://example.org/", "https://example.org/#fragment" })
        await Throws<ArgumentException>(() => { var scope = Scope(); scope.WebUrls.Add(url); ScopeGuard.Validate(scope); return Task.CompletedTask; });
});
await Check("Ports and workload are bounded", async () =>
{
    await Throws<ArgumentException>(() => { var scope = Scope(); scope.Ports.Add(65535); ScopeGuard.Validate(scope); return Task.CompletedTask; });
    await Throws<ArgumentException>(() => { var scope = Scope(); scope.MaxConcurrency = 17; ScopeGuard.Validate(scope); return Task.CompletedTask; });
    await Throws<ArgumentException>(() => { var scope = Scope(); scope.Hosts = Enumerable.Range(1, 129).Select(i => "host" + i + ".example.org").ToList(); ScopeGuard.Validate(scope); return Task.CompletedTask; });
});
await Check("Pre-cancelled scans stop", async () =>
{
    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
    foreach (var engine in new IAssessmentEngine[] { new NetworkPostureEngine(), new WebPostureEngine(), new LocalEndpointEngine(), new EmailPostureEngine(new FakeDns("Success", ["v=spf1 -all"])) })
        await Throws<OperationCanceledException>(() => engine.AssessAsync(new ScanContext(Scope()), cancelled.Token));
});
await Check("Local endpoint unavailability is honest", async () =>
{
    if (!OperatingSystem.IsWindows())
    {
        var engine = new LocalEndpointEngine(); var scope = Scope(); scope.IncludeLocalEndpoint = true;
        var result = await engine.AssessAsync(new ScanContext(scope), default);
        Assert(!engine.Descriptor.IsAvailable && result.Assets.Count == 0 && result.Findings.Count == 0, "Non-Windows did not return honest unavailable collection.");
    }
});
await Check("DNS failure is unknown and DKIM is not guessed", async () =>
{
    var dns = new FakeDns("TimedOut", []); var scope = Scope(); scope.Hosts.Add("mail.example.org");
    var result = await new EmailPostureEngine(dns).AssessAsync(new ScanContext(scope), default);
    Assert(result.Findings.Count == 0, "Resolver failure was misreported as an absent-policy finding.");
    Assert(result.Observations.All(o => o.Property != "CategoryCoverage"), "Unknown DNS observations were marked assessed.");
    Assert(dns.Names.SequenceEqual(new[] { "mail.example.org", "_dmarc.mail.example.org" }), "Email scan expanded beyond exact records.");
    Assert(result.Observations.Any(o => o.Property == "DKIM" && o.Value.StartsWith("Unknown")), "Absent DKIM selectors were not marked unknown.");
});
await Check("Permissive SPF and monitor-only DMARC create real findings", async () =>
{
    var scope = Scope(); scope.Hosts.Add("example.org");
    var result = await new EmailPostureEngine(new FakeDns("Success", ["v=spf1 +all", "v=DMARC1; p=none"])).AssessAsync(new ScanContext(scope), default);
    Assert(result.Findings.Any(f => f.RootCauseKey == "spf-permissive") && result.Findings.Any(f => f.RootCauseKey == "dmarc-monitor-only"), "Expected policy findings were absent.");
    Assert(result.Observations.Any(o => o.Property == "CategoryCoverage" && o.Value == "assessed"), "Conclusive DNS posture was not marked assessed.");
    Assert(result.Findings.All(f => f.Source == "email") && result.Observations.All(o => o.EngineId == "email"), "Ownership is not stable.");
});
await Check("Web redirects are never followed and only HEAD is sent", async () =>
{
    await using var server = new HeaderServer("HTTP/1.1 302 Found\r\nLocation: http://outside-scope.invalid/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    var scope = Scope(); scope.WebUrls.Add(server.Url);
    var result = await new WebPostureEngine().AssessAsync(new ScanContext(scope), default);
    Assert(server.Requests == 1 && server.Method == "HEAD", "Collection followed a redirect or used a non-HEAD method.");
    Assert(result.Observations.Any(o => o.Property == "Redirect" && o.Value.Contains("Not followed")), "Redirect was not recorded.");
    Assert(result.Findings.All(f => f.RootCauseKey == "https-required"), "Missing application headers were falsely assessed on a redirect.");
});
await Check("Web cookie attributes do not store cookie credentials", async () =>
{
    await using var server = new HeaderServer("HTTP/1.1 200 OK\r\nSet-Cookie: session=SECRET_TEST_VALUE; Path=/\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    var scope = Scope(); scope.WebUrls.Add(server.Url);
    var result = await new WebPostureEngine().AssessAsync(new ScanContext(scope), default);
    Assert(result.Findings.Any(f => f.RootCauseKey == "cookie-httponly"), "Cookie review finding was missing.");
    Assert(!JsonSerializer.Serialize(result).Contains("SECRET_TEST_VALUE"), "Cookie value was persisted.");
});
await Check("Web cancellation interrupts an in-flight collection", async () =>
{
    await using var server = new HeaderServer(null); var scope = Scope(); scope.WebUrls.Add(server.Url);
    using var token = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
    await Throws<OperationCanceledException>(() => new WebPostureEngine().AssessAsync(new ScanContext(scope), token.Token));
});

var jsonOptions = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
EvidenceImportEnvelope Envelope() => new()
{
    SchemaVersion = 1, SourceId = "azure", OrganizationId = "tenant-a", CollectedAt = DateTimeOffset.UtcNow,
    Assets = [new Asset { Id = "resource-1", Name = "Actual exported VM", Kind = AssetKind.CloudResource, Address = "/subscriptions/sub/resourceGroups/rg/vm", BusinessCriticality = 4 }],
    Findings = [new Finding { Id = "finding-1", Title = "Exported configuration finding", RootCauseKey = "root-1", Severity = Severity.High, Category = SecurityCategory.Cloud, AssetIds = ["resource-1"], EvidenceIds = ["resource-1"], Confidence = 1 }],
    Identities = [new Identity { Id = "user-1", DisplayName = "Exported user", Provider = "Azure", MfaEnabled = null }]
};
EvidenceImportAuthorization Authorization() => new() { AuthorizationConfirmed = true, AuthorizedBy = "Import operator", AuthorizedAt = DateTimeOffset.UtcNow, SourceId = "azure", OrganizationId = "tenant-a" };
MemoryStream Stream(EvidenceImportEnvelope envelope) => new(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope, jsonOptions)));
await Check("Export imports retain stable provenance and graph integrity", async () =>
{
    var envelope = Envelope(); using var a = Stream(envelope); using var b = Stream(envelope);
    var importer = new ExportedEvidenceImporter(); var first = await importer.ImportAsync(a, Authorization()); var second = await importer.ImportAsync(b, Authorization());
    Assert(first.Result.Assets[0].Id == second.Result.Assets[0].Id && first.Sha256 == second.Sha256, "Imported IDs or file provenance changed.");
    Assert(first.Result.Findings.All(f => f.Source == "import:azure" && f.Confidence <= .95), "Imported source/confidence is incorrect.");
    Assert(first.Identities[0].MfaEnabled is null, "Unknown MFA was changed.");
    var ids = first.Result.Nodes.Select(n => n.Id).ToHashSet();
    Assert(first.Result.Edges.All(e => ids.Contains(e.SourceId) && ids.Contains(e.TargetId)), "Imported graph contains dangling links.");
});
await Check("Export scope rejects the wrong organization", async () =>
{
    var envelope = Envelope(); envelope.OrganizationId = "unapproved-tenant"; using var stream = Stream(envelope);
    await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(stream, Authorization()));
});
await Check("Export validation rejects dangling references and plaintext secret properties", async () =>
{
    var envelope = Envelope(); envelope.Findings[0].AssetIds = ["unknown-asset"]; using var badReference = Stream(envelope);
    await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(badReference, Authorization()));
    envelope = Envelope(); envelope.Assets[0].Properties["access_token"] = "secret-value"; using var secret = Stream(envelope);
    await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(secret, Authorization()));
});
await Check("Export validation rejects malformed JSON and duplicate identities", async () =>
{
    using var malformed = new MemoryStream(Encoding.UTF8.GetBytes("{ not-json"));
    await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(malformed, Authorization()));
    var envelope = Envelope(); envelope.Identities.Add(envelope.Identities[0]); using var duplicate = Stream(envelope);
    await Throws<InvalidDataException>(() => new ExportedEvidenceImporter().ImportAsync(duplicate, Authorization()));
});
await Check("Connector availability never claims an unimplemented connection", () =>
{
    Assert(new ConnectorRegistry().Descriptors.All(d => d.Status.Contains("not configured") || d.Status.Contains("not connected")), "A connector advertised unsupported live capabilities.");
    return Task.CompletedTask;
});
Console.WriteLine($"Engine regression checks: {passed} passed, {failures.Count} failed.");
return failures.Count == 0 ? 0 : 1;

sealed class FakeDns(string status, IReadOnlyList<string> records) : IDnsTxtResolver
{
    public List<string> Names { get; } = [];
    public Task<DnsTxtResult> QueryTxtAsync(string name, TimeSpan timeout, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Names.Add(name);
        return Task.FromResult(new DnsTxtResult(status, records, "Regression fixture"));
    }
}
sealed class HeaderServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Task work;
    public string Url { get; }
    public int Requests { get; private set; }
    public string? Method { get; private set; }
    public HeaderServer(string? response)
    {
        listener.Start(); Url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        work = Run(response);
    }
    private async Task Run(string? response)
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(stop.Token);
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var request = await reader.ReadLineAsync(stop.Token); Method = request?.Split(' ')[0]; Requests++;
                string? line; while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(stop.Token))) { }
                if (response is not null) await stream.WriteAsync(Encoding.ASCII.GetBytes(response), stop.Token);
                else await Task.Delay(Timeout.Infinite, stop.Token);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException) { }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await work; stop.Dispose(); }
}
