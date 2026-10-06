using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Engines;

public sealed record DnsTxtResult(string Status, IReadOnlyList<string> Records, string Source);
public interface IDnsTxtResolver
{
    Task<DnsTxtResult> QueryTxtAsync(string name, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Queries only domain TXT, _dmarc, and explicitly supplied DKIM selectors.</summary>
public sealed class EmailPostureEngine : IAssessmentEngine
{
    private readonly IDnsTxtResolver resolver;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> selectors;
    public EmailPostureEngine(IDnsTxtResolver? resolver = null, IReadOnlyDictionary<string, IReadOnlyList<string>>? dkimSelectors = null)
    {
        this.resolver = resolver ?? new SystemDnsTxtResolver();
        selectors = dkimSelectors ?? new Dictionary<string, IReadOnlyList<string>>();
    }
    public EngineDescriptor Descriptor { get; } = new("email", "Email and DNS posture", "SPF and exact-domain DMARC TXT posture through the system DNS resolver. DKIM is checked only for explicitly configured selectors; no selector guessing.", true, "Available when a system DNS resolver is reachable. DKIM requires known selectors.");

    public async Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken)
    {
        context = ScopeGuard.Snapshot(context, cancellationToken);
        var evidence = new EvidenceBuilder(Descriptor.Id);
        var domains = context.Scope.Hosts.Select(ScopeGuard.NormalizeHost).Concat(context.Scope.WebUrls.Select(url => ScopeGuard.ParseWebUrl(url).IdnHost))
            .Where(host => !IPAddress.TryParse(host, out _) && host.Contains('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        foreach (var pair in selectors)
        {
            if (!ScopeGuard.IsAuthorizedHost(context.Scope, pair.Key) || pair.Value is null || pair.Value.Count > 10 || pair.Value.Any(selector => !ValidSelector(selector)))
                throw new ArgumentException("DKIM selectors must be explicit valid DNS labels for exact authorized domains, with at most ten selectors per domain.", nameof(selectors));
        }
        await Parallel.ForEachAsync(domains, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(context.Scope.MaxConcurrency, 4), CancellationToken = cancellationToken }, async (domain, token) =>
        {
            ScopeGuard.EnsureActive(context.Scope, token);
            context.Progress?.Report($"Checking email DNS posture for {domain}");
            var asset = evidence.Asset(domain, AssetKind.NetworkDevice, domain);
            var domainId = EvidenceBuilder.StableId("domain", domain);
            evidence.Node(new EvidenceNode { Id = domainId, Label = domain, Kind = EvidenceKind.Domain, Source = Descriptor.Id });
            evidence.Edge(asset.Id, domainId, "uses-domain");
            var timeout = TimeSpan.FromSeconds(context.Scope.TimeoutSeconds);
            var spf = await resolver.QueryTxtAsync(domain, timeout, token);
            ScopeGuard.EnsureActive(context.Scope, token);
            var dmarc = await resolver.QueryTxtAsync("_dmarc." + domain, timeout, token);
            AnalyzeSpf(evidence, asset, spf);
            AnalyzeDmarc(evidence, asset, dmarc);
            evidence.Observe(asset, "DNSSEC", "Unknown — system-resolver TXT responses do not independently prove DNSSEC validation.");
            var configured = selectors.FirstOrDefault(pair => ScopeGuard.NormalizeHost(pair.Key) == domain).Value;
            if (configured is null || configured.Count == 0)
                evidence.Observe(asset, "DKIM", "Unknown — no known selector configured. Selector enumeration was not attempted.");
            else
            {
                foreach (var selector in configured.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    ScopeGuard.EnsureActive(context.Scope, token);
                    var result = await resolver.QueryTxtAsync(selector + "._domainkey." + domain, timeout, token);
                    var keyRecords = result.Records.Where(record => record.Contains("p=", StringComparison.OrdinalIgnoreCase)).ToArray();
                    evidence.Observe(asset, "DKIM selector " + selector, result.Status == "Success" && keyRecords.Length > 0 ? "Published key-like TXT record observed; signing use and message alignment were not verified." : result.Status == "NoRecords" || (result.Status == "Success" && keyRecords.Length == 0) ? "No key-like TXT record observed for this known selector; message signing remains unknown." : "Unknown — " + result.Status);
                    // A missing historical or rotated selector is not proof that mail lacks DKIM.
                }
            }
        });
        cancellationToken.ThrowIfCancellationRequested();
        evidence.Message("Email posture covers exact authorized domains only. DMARC organizational-domain fallback, SPF include-chain expansion, mail delivery and actual DKIM signing were not assessed.");
        return evidence.Build();
    }

    private static bool ValidSelector(string selector) => !string.IsNullOrWhiteSpace(selector) && selector.Length <= 63 && selector[0] != '-' && selector[^1] != '-' && selector.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    private static void AnalyzeSpf(EvidenceBuilder evidence, Asset asset, DnsTxtResult result)
    {
        evidence.Observe(asset, "SPF query", result.Status, result.Source);
        if (result.Status is not ("Success" or "NoRecords")) return;
        evidence.Observe(asset, "CategoryCoverage", "assessed");
        var records = result.Records.Where(record => record.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).ToArray();
        evidence.Observe(asset, "SPF policy", records.Length == 0 ? "No SPF record observed." : string.Join(" | ", records.Select(record => record.Length > 1024 ? record[..1024] : record)), result.Source);
        if (records.Length == 0)
            evidence.Finding(asset, "spf-absent", "SPF record was not observed for the authorized domain", "A successful system DNS query found no SPF TXT policy at this exact domain. Whether the domain sends mail was not established.", Severity.Low, SecurityCategory.Email, "Identify legitimate senders and publish an appropriate SPF policy; non-sending domains may use v=spf1 -all.", "Query the exact domain TXT policy and validate legitimate sender coverage.", .85);
        else if (records.Length > 1)
            evidence.Finding(asset, "spf-multiple", "Multiple SPF policies were observed", "More than one v=spf1 TXT record can produce SPF evaluation errors.", Severity.Medium, SecurityCategory.Email, "Consolidate approved sender mechanisms into a single valid SPF policy.", "Confirm exactly one SPF TXT policy exists and validate it with the mail administrator.");
        else if (records[0].Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(term => term.Equals("+all", StringComparison.OrdinalIgnoreCase) || term.Equals("all", StringComparison.OrdinalIgnoreCase)))
            evidence.Finding(asset, "spf-permissive", "SPF policy permits every sender", "The observed SPF policy includes an unqualified or +all mechanism, which authorizes any source.", Severity.High, SecurityCategory.Email, "Remove permissive all mechanisms after identifying approved senders; use an appropriate reject policy.", "Validate the updated policy and approved sender set.");
    }
    private static void AnalyzeDmarc(EvidenceBuilder evidence, Asset asset, DnsTxtResult result)
    {
        evidence.Observe(asset, "DMARC query", result.Status, result.Source);
        if (result.Status is not ("Success" or "NoRecords")) return;
        evidence.Observe(asset, "CategoryCoverage", "assessed");
        var records = result.Records.Where(record => record.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (records.Length == 0)
        {
            evidence.Observe(asset, "DMARC policy", "No exact-domain DMARC policy observed; organizational-domain inheritance was not checked.");
            evidence.Finding(asset, "dmarc-absent", "Review absent exact-domain DMARC policy", "No DMARC policy was observed at the exact authorized domain. A policy inherited from an organizational domain may still apply; that parent domain was not assessed without explicit scope.", Severity.Low, SecurityCategory.Email, "Verify DMARC inheritance and mail alignment; publish an appropriate policy through the authorized domain owner if required.", "Check the effective organizational and exact-domain policy and repeat the authorized query.", .65);
            return;
        }
        var tags = records[0].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var policy = tags.FirstOrDefault(tag => tag.StartsWith("p=", StringComparison.OrdinalIgnoreCase))?[2..].Trim() ?? "Unknown";
        evidence.Observe(asset, "DMARC policy", policy, result.Source);
        if (records.Length > 1 || policy == "Unknown" || !new[] { "none", "quarantine", "reject" }.Contains(policy.ToLowerInvariant()))
            evidence.Finding(asset, "dmarc-invalid", "DMARC policy requires validation", "The observed exact-domain records contain multiple DMARC policies or no recognized enforcement policy.", Severity.Medium, SecurityCategory.Email, "Publish one valid DMARC record with an appropriate p tag after sender-alignment review.", "Validate the policy with the mail administrator and repeat the DNS query.");
        else if (policy.Equals("none", StringComparison.OrdinalIgnoreCase))
            evidence.Finding(asset, "dmarc-monitor-only", "DMARC policy is in monitoring mode", "The exact-domain p=none policy requests monitoring without quarantine or rejection. This may be intentional during deployment.", Severity.Medium, SecurityCategory.Email, "Review reporting and legitimate sender alignment, then stage enforcement with the mail administrator.", "Confirm p=quarantine or p=reject after approved rollout and verify mail delivery.", .95);
    }
}

/// <summary>Bounded DNS TXT queries to an OS-configured resolver; no external hard-coded resolver.</summary>
public sealed class SystemDnsTxtResolver : IDnsTxtResolver
{
    public async Task<DnsTxtResult> QueryTxtAsync(string name, TimeSpan timeout, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (timeout < TimeSpan.FromSeconds(1) || timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(timeout));
        if (name.Length > 253 || name.Split('.').Any(label => label.Length is < 1 or > 63 || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))))
            throw new ArgumentException("Malformed DNS record name.", nameof(name));
        IPAddress? dns;
        try
        {
            dns = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().DnsAddresses).FirstOrDefault(ip => !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any));
        }
        catch (NetworkInformationException) { return new("ResolverUnavailable", [], "System DNS"); }
        if (dns is null) return new("ResolverUnavailable", [], "System DNS");
        var source = "System DNS resolver " + dns;
        var id = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        var request = CreateQuery(id, name);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout);
        using var udp = new UdpClient(dns.AddressFamily);
        try
        {
            udp.Connect(new IPEndPoint(dns, 53));
            await udp.SendAsync(request.AsMemory(), linked.Token);
            var response = await udp.ReceiveAsync(linked.Token);
            if (response.Buffer.Length > 8192) return new("ResponseLimitExceeded", [], source);
            return ParseResponse(response.Buffer, id, source);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return new("TimedOut", [], source); }
        catch (SocketException) { return new("ResolverUnavailable", [], source); }
    }

    private static byte[] CreateQuery(ushort id, string name)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        header.Clear();
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        stream.Write(header);
        foreach (var label in name.Split('.')) { var bytes = Encoding.ASCII.GetBytes(label); stream.WriteByte((byte)bytes.Length); stream.Write(bytes); }
        stream.Write([0, 0, 16, 0, 1]);
        return stream.ToArray();
    }

    private static DnsTxtResult ParseResponse(byte[] data, ushort id, string source)
    {
        try
        {
            if (data.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(data) != id) return new("InvalidResponse", [], source);
            var flags = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(2));
            if ((flags & 0x8000) == 0 || (flags & 0x0200) != 0) return new("IncompleteResponse", [], source);
            var rcode = flags & 0xF;
            if (rcode == 3) return new("NoRecords", [], source);
            if (rcode != 0) return new("ResolverError", [], source);
            var questions = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4));
            var answers = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(6));
            if (questions != 1 || answers > 64) return new("InvalidResponse", [], source);
            var offset = 12;
            SkipName(data, ref offset);
            offset = checked(offset + 4);
            var records = new List<string>();
            for (var i = 0; i < answers; i++)
            {
                SkipName(data, ref offset);
                if (offset + 10 > data.Length) return new("InvalidResponse", [], source);
                var type = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset));
                var recordClass = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 2));
                var length = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 8));
                offset += 10;
                var end = checked(offset + length);
                if (end > data.Length) return new("InvalidResponse", [], source);
                if (type == 16 && recordClass == 1)
                {
                    var text = new StringBuilder();
                    var cursor = offset;
                    while (cursor < end)
                    {
                        var partLength = data[cursor++];
                        if (cursor + partLength > end) return new("InvalidResponse", [], source);
                        text.Append(Encoding.UTF8.GetString(data, cursor, partLength));
                        cursor += partLength;
                    }
                    records.Add(text.ToString());
                }
                offset = end;
            }
            return new(records.Count == 0 ? "NoRecords" : "Success", records, source);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or OverflowException) { return new("InvalidResponse", [], source); }
    }
    private static void SkipName(byte[] data, ref int offset)
    {
        var labels = 0;
        while (true)
        {
            if (offset >= data.Length || ++labels > 128) throw new ArgumentOutOfRangeException(nameof(offset));
            var length = data[offset++];
            if (length == 0) return;
            if ((length & 0xC0) == 0xC0)
            {
                if (offset >= data.Length) throw new ArgumentOutOfRangeException(nameof(offset));
                var pointer = ((length & 0x3F) << 8) | data[offset++];
                if (pointer >= data.Length) throw new ArgumentOutOfRangeException(nameof(offset));
                return;
            }
            if (length > 63 || offset + length > data.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            offset += length;
        }
    }
}
