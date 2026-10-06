using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Sentinel.Core;

namespace Sentinel.Engines;

public sealed class EvidenceImportAuthorization
{
    public bool AuthorizationConfirmed { get; set; }
    public string AuthorizedBy { get; set; } = "";
    public DateTimeOffset AuthorizedAt { get; set; }
    public string SourceId { get; set; } = "";
    public string OrganizationId { get; set; } = "";
}

public sealed class EvidenceImportEnvelope
{
    public int SchemaVersion { get; set; }
    public string SourceId { get; set; } = "";
    public string OrganizationId { get; set; } = "";
    public DateTimeOffset CollectedAt { get; set; }
    public List<Asset> Assets { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public List<Identity> Identities { get; set; } = [];
    public List<EvidenceNode> Nodes { get; set; } = [];
    public List<EvidenceEdge> Edges { get; set; } = [];
    public List<Observation> Observations { get; set; } = [];
    public List<CertificateRecord> Certificates { get; set; } = [];
}

public sealed record ImportedEvidence(EngineResult Result, IReadOnlyList<Identity> Identities, string SourceId, string OrganizationId, DateTimeOffset CollectedAt, string Sha256);

/// <summary>Imports explicitly authorized exports; never connects to the represented services.</summary>
public sealed partial class ExportedEvidenceImporter
{
    public const int MaximumFileBytes = 16 * 1024 * 1024;
    private static readonly HashSet<string> SupportedSources = ["azure", "m365", "aws", "gcp", "ad", "vulnerability-intel"];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 32,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };

    public async Task<ImportedEvidence> ImportAsync(Stream input, EvidenceImportAuthorization authorization, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(authorization);
        ValidateAuthorization(authorization);
        cancellationToken.ThrowIfCancellationRequested();
        using var buffer = new MemoryStream();
        var block = new byte[8192];
        int read;
        while ((read = await input.ReadAsync(block, cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaximumFileBytes) throw new InvalidDataException("Evidence import exceeds the 16 MiB limit.");
            await buffer.WriteAsync(block.AsMemory(0, read), cancellationToken);
        }
        var bytes = buffer.ToArray();
        EvidenceImportEnvelope envelope;
        try { envelope = JsonSerializer.Deserialize<EvidenceImportEnvelope>(bytes, JsonOptions) ?? throw new InvalidDataException("Evidence import must contain an object."); }
        catch (JsonException ex) { throw new InvalidDataException("The exported evidence is malformed or does not match schema version 1.", ex); }
        ValidateEnvelope(envelope, authorization);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateAuthorization(authorization);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var source = "import:" + envelope.SourceId;
        var prefix = EvidenceBuilder.StableId("import", envelope.SourceId + ":" + envelope.OrganizationId) + ":";
        var idMap = envelope.Assets.Select(a => a.Id).Concat(envelope.Identities.Select(i => i.Id)).Concat(envelope.Nodes.Select(n => n.Id)).Concat(envelope.Findings.Select(f => f.Id)).Concat(envelope.Certificates.Select(c => c.Id)).Distinct().ToDictionary(id => id, id => prefix + id, StringComparer.Ordinal);
        string Map(string id) => idMap[id];
        foreach (var asset in envelope.Assets)
        {
            asset.Id = Map(asset.Id); asset.Environment = "Live";
            asset.Properties["import.source"] = envelope.SourceId;
            asset.Properties["import.organization"] = envelope.OrganizationId;
            asset.Properties["import.sha256"] = sha256;
            asset.FirstSeen = asset.LastSeen = envelope.CollectedAt;
        }
        foreach (var identity in envelope.Identities) identity.Id = Map(identity.Id);
        foreach (var node in envelope.Nodes)
        {
            node.Id = Map(node.Id); node.Source = source; node.ObservedAt = envelope.CollectedAt;
            if (node.Properties.TryGetValue("assetId", out var referencedAsset)) node.Properties["assetId"] = Map(referencedAsset);
            node.Confidence = Math.Min(node.Confidence, .95);
            node.Properties["provenance"] = $"Operator-supplied export; not independently verified. SHA256 {sha256}";
        }
        foreach (var asset in envelope.Assets.Where(asset => envelope.Nodes.All(node => node.Id != asset.Id)))
            envelope.Nodes.Add(new EvidenceNode { Id = asset.Id, Label = asset.Name, Kind = asset.Kind == AssetKind.CloudResource ? EvidenceKind.CloudResource : EvidenceKind.Asset, Source = source, ObservedAt = envelope.CollectedAt, Confidence = .95 });
        foreach (var identity in envelope.Identities.Where(identity => envelope.Nodes.All(node => node.Id != identity.Id)))
            envelope.Nodes.Add(new EvidenceNode { Id = identity.Id, Label = identity.DisplayName, Kind = EvidenceKind.Identity, Source = source, Confidence = .95, ObservedAt = envelope.CollectedAt, Properties = new() { ["privileged"] = identity.IsPrivileged.ToString(), ["mfa"] = identity.MfaEnabled?.ToString() ?? "Unknown", ["provider"] = identity.Provider } });
        foreach (var certificate in envelope.Certificates)
        {
            var mappedCertificateId = Map(certificate.Id);
            if (envelope.Nodes.All(node => node.Id != mappedCertificateId))
                envelope.Nodes.Add(new EvidenceNode { Id = mappedCertificateId, Label = string.IsNullOrWhiteSpace(certificate.Subject) ? "Imported certificate" : certificate.Subject, Kind = EvidenceKind.Certificate, Source = source, Confidence = .95, ObservedAt = envelope.CollectedAt, Properties = new() { ["notAfter"] = certificate.NotAfter.ToString("O") } });
        }
        foreach (var finding in envelope.Findings)
        {
            finding.Id = Map(finding.Id); finding.AssetIds = finding.AssetIds.Select(Map).ToList(); finding.EvidenceIds = finding.EvidenceIds.Select(Map).ToList();
            finding.Source = source; finding.FirstSeen = finding.LastSeen = envelope.CollectedAt;
            finding.Confidence = Math.Min(finding.Confidence, .95);
            if (envelope.Nodes.All(node => node.Id != finding.Id)) envelope.Nodes.Add(new EvidenceNode { Id = finding.Id, Label = finding.Title, Kind = EvidenceKind.Finding, Source = source, Confidence = finding.Confidence, ObservedAt = envelope.CollectedAt });
            if (!finding.EvidenceIds.Contains(finding.Id)) finding.EvidenceIds.Add(finding.Id);
        }
        foreach (var edge in envelope.Edges)
        {
            edge.Id = prefix + edge.Id; edge.SourceId = Map(edge.SourceId); edge.TargetId = Map(edge.TargetId); edge.FindingIds = edge.FindingIds.Select(Map).ToList(); edge.Confidence = Math.Min(edge.Confidence, .95);
        }
        foreach (var observation in envelope.Observations)
        {
            observation.Id = prefix + observation.Id; observation.AssetId = Map(observation.AssetId); observation.EngineId = source; observation.Source = source; observation.ObservedAt = envelope.CollectedAt;
        }
        foreach (var certificate in envelope.Certificates) { certificate.Id = Map(certificate.Id); certificate.AssetId = Map(certificate.AssetId); }
        foreach (var finding in envelope.Findings)
            foreach (var assetId in finding.AssetIds)
                if (envelope.Edges.All(edge => edge.SourceId != assetId || edge.TargetId != finding.Id))
                    envelope.Edges.Add(new EvidenceEdge { Id = EvidenceBuilder.StableId("edge", assetId + ":finding:" + finding.Id), SourceId = assetId, TargetId = finding.Id, Relationship = "has-finding", FindingIds = [finding.Id], Confidence = finding.Confidence });
        foreach (var certificate in envelope.Certificates)
            if (envelope.Edges.All(edge => edge.SourceId != certificate.AssetId || edge.TargetId != certificate.Id))
                envelope.Edges.Add(new EvidenceEdge { Id = EvidenceBuilder.StableId("edge", certificate.AssetId + ":certificate:" + certificate.Id), SourceId = certificate.AssetId, TargetId = certificate.Id, Relationship = "presents-certificate", Confidence = .95 });
        var result = new EngineResult(envelope.Assets, envelope.Findings, envelope.Nodes, envelope.Edges, envelope.Observations, envelope.Certificates,
            [$"Imported {envelope.SourceId} evidence for exact organization {envelope.OrganizationId}; collected {envelope.CollectedAt:u}; SHA256 {sha256}. Provenance is operator supplied and was not independently verified. No live API connection was made."]);
        return new(result, envelope.Identities, envelope.SourceId, envelope.OrganizationId, envelope.CollectedAt, sha256);
    }

    private static void ValidateAuthorization(EvidenceImportAuthorization authorization)
    {
        var now = DateTimeOffset.UtcNow;
        if (!authorization.AuthorizationConfirmed || string.IsNullOrWhiteSpace(authorization.AuthorizedBy) || authorization.AuthorizedBy.Length > 200 || authorization.AuthorizedAt < now - ScopeGuard.AuthorizationLifetime || authorization.AuthorizedAt > now.AddMinutes(2))
            throw new ArgumentException("Confirm ownership or authorization for the exact exported organization with a current operator attestation.", nameof(authorization));
        if (!SupportedSources.Contains(authorization.SourceId) || string.IsNullOrWhiteSpace(authorization.OrganizationId) || authorization.OrganizationId.Length > 200)
            throw new ArgumentException("Select a supported export source and the exact tenant, account or organization ID.", nameof(authorization));
    }

    private static void ValidateEnvelope(EvidenceImportEnvelope envelope, EvidenceImportAuthorization authorization)
    {
        if (envelope.SchemaVersion != 1 || envelope.SourceId != authorization.SourceId || envelope.OrganizationId != authorization.OrganizationId)
            throw new InvalidDataException("The export schema, source or exact organization does not match the authorized import scope.");
        if (envelope.CollectedAt > DateTimeOffset.UtcNow.AddMinutes(2) || envelope.CollectedAt < DateTimeOffset.UtcNow.AddYears(-5))
            throw new InvalidDataException("The export collection time is absent, too old or in the future.");
        if (envelope.Assets is null || envelope.Findings is null || envelope.Identities is null || envelope.Nodes is null || envelope.Edges is null || envelope.Observations is null || envelope.Certificates is null)
            throw new InvalidDataException("Export collections cannot be null.");
        if (envelope.Assets.Count > 10000 || envelope.Findings.Count > 20000 || envelope.Identities.Count > 20000 || envelope.Nodes.Count > 40000 || envelope.Edges.Count > 80000 || envelope.Observations.Count > 50000 || envelope.Certificates.Count > 10000)
            throw new InvalidDataException("The export exceeds a supported entity-count limit.");
        var assets = UniqueIds(envelope.Assets.Select(a => a?.Id), "asset");
        var identities = UniqueIds(envelope.Identities.Select(i => i?.Id), "identity");
        var nodes = UniqueIds(envelope.Nodes.Select(n => n?.Id), "node");
        var findings = UniqueIds(envelope.Findings.Select(f => f?.Id), "finding");
        var certificates = UniqueIds(envelope.Certificates.Select(c => c?.Id), "certificate");
        _ = UniqueIds(envelope.Edges.Select(e => e?.Id), "edge");
        _ = UniqueIds(envelope.Observations.Select(o => o?.Id), "observation");
        var known = assets.Concat(identities).Concat(nodes).Concat(findings).Concat(certificates).ToHashSet(StringComparer.Ordinal);
        foreach (var asset in envelope.Assets)
        {
            RequireText(asset.Name, 200, "asset name"); RequireText(asset.Address, 2048, "asset address");
            if (!Enum.IsDefined(asset.Kind) || asset.BusinessCriticality is < 1 or > 5 || !Unit(asset.Exposure)) throw new InvalidDataException("Invalid asset kind, criticality or exposure.");
            ValidateProperties(asset.Properties);
        }
        foreach (var finding in envelope.Findings)
        {
            RequireText(finding.Title, 300, "finding title"); RequireText(finding.RootCauseKey, 200, "root-cause key");
            if (!Enum.IsDefined(finding.Severity) || !Enum.IsDefined(finding.Category) || !Enum.IsDefined(finding.Status) || !double.IsFinite(finding.Cvss) || finding.Cvss is < 0 or > 10 || !Unit(finding.Confidence) || !Unit(finding.Exploitability) || !Unit(finding.PrivilegeImpact) || !Unit(finding.IdentityReach) || !Unit(finding.CompensatingControl)) throw new InvalidDataException("Invalid finding scoring or enumeration.");
            if (finding.Cve is not null && !CvePattern().IsMatch(finding.Cve)) throw new InvalidDataException("CVE identifiers must use CVE-YYYY-NNNN format.");
            if (finding.AssetIds is null || finding.AssetIds.Count == 0 || finding.AssetIds.Any(id => !assets.Contains(id)) || finding.EvidenceIds is null || finding.EvidenceIds.Any(id => !known.Contains(id))) throw new InvalidDataException("A finding references unknown assets or evidence.");
            if (finding.References is null || finding.References.Count > 32 || finding.References.Any(reference => !Uri.TryCreate(reference, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0)) throw new InvalidDataException("Finding references must be credential-free HTTPS URLs.");
            if (finding.ControlIds is null || finding.ControlIds.Count > 64) throw new InvalidDataException("Invalid control mapping.");
            if (finding.Description is null || finding.Description.Length > 16000 || finding.Remediation is null || finding.Remediation.Length > 16000 || finding.Verification is null || finding.Verification.Length > 16000) throw new InvalidDataException("Finding text exceeds the limit.");
        }
        foreach (var identity in envelope.Identities)
        {
            RequireText(identity.DisplayName, 200, "identity display name"); RequireText(identity.Provider, 100, "identity provider");
            if (identity.Groups is null || identity.Permissions is null || identity.Groups.Count > 1000 || identity.Permissions.Count > 1000 || identity.Groups.Concat(identity.Permissions).Any(item => item is null || item.Length > 500)) throw new InvalidDataException("Invalid identity relationships.");
        }
        foreach (var node in envelope.Nodes)
        {
            RequireText(node.Label, 500, "node label");
            if (!Enum.IsDefined(node.Kind) || !Unit(node.Confidence)) throw new InvalidDataException("Invalid evidence node.");
            ValidateProperties(node.Properties);
            if (node.Properties.TryGetValue("assetId", out var assetId) && !assets.Contains(assetId)) throw new InvalidDataException("Evidence assetId property references an unknown asset.");
            if (node.Kind is EvidenceKind.Asset or EvidenceKind.CloudResource && !assets.Contains(node.Id) && !node.Properties.ContainsKey("assetId")) throw new InvalidDataException("Asset evidence nodes must refer to a declared asset by ID or assetId property.");
            if (assets.Contains(node.Id) && node.Kind is not (EvidenceKind.Asset or EvidenceKind.CloudResource) || identities.Contains(node.Id) && node.Kind != EvidenceKind.Identity || findings.Contains(node.Id) && node.Kind != EvidenceKind.Finding || certificates.Contains(node.Id) && node.Kind != EvidenceKind.Certificate) throw new InvalidDataException("Evidence node identity conflicts with the referenced entity type.");
        }
        if (assets.Overlaps(identities) || assets.Overlaps(findings) || identities.Overlaps(findings) || certificates.Overlaps(assets) || certificates.Overlaps(identities) || certificates.Overlaps(findings)) throw new InvalidDataException("Different entity types cannot share the same ID.");
        foreach (var edge in envelope.Edges)
        {
            RequireText(edge.Relationship, 200, "edge relationship");
            if (!known.Contains(edge.SourceId) || !known.Contains(edge.TargetId) || !Unit(edge.Confidence) || edge.FindingIds is null || edge.FindingIds.Any(id => !findings.Contains(id))) throw new InvalidDataException("An edge references unknown evidence or findings.");
        }
        foreach (var observation in envelope.Observations)
        {
            RequireText(observation.Property, 200, "observation property"); RequireText(observation.Value, 4096, "observation value");
            if (!assets.Contains(observation.AssetId)) throw new InvalidDataException("Observation asset does not exist.");
        }
        foreach (var certificate in envelope.Certificates)
            if (!assets.Contains(certificate.AssetId) || string.IsNullOrWhiteSpace(certificate.Thumbprint) || certificate.Thumbprint.Length > 128) throw new InvalidDataException("Invalid certificate record.");
    }

    private static HashSet<string> UniqueIds(IEnumerable<string?> values, string kind)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in values)
            if (id is null || !IdPattern().IsMatch(id) || !result.Add(id)) throw new InvalidDataException($"Invalid or duplicated {kind} ID. IDs must be 1–128 letters, digits, underscores, dots, colons or hyphens.");
        return result;
    }
    private static bool Unit(double value) => double.IsFinite(value) && value is >= 0 and <= 1;
    private static void RequireText(string? value, int max, string name) { if (string.IsNullOrWhiteSpace(value) || value.Length > max || value.Any(char.IsControl)) throw new InvalidDataException($"Invalid {name}."); }
    private static void ValidateProperties(Dictionary<string, string>? properties)
    {
        if (properties is null || properties.Count > 64 || properties.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Key.Length > 100 || pair.Value is null || pair.Value.Length > 4096)) throw new InvalidDataException("Invalid evidence property map.");
        var secretNames = new[] { "password", "secret", "token", "privatekey", "private_key", "credential", "connectionstring" };
        if (properties.Keys.Any(key => secretNames.Any(secret => key.Contains(secret, StringComparison.OrdinalIgnoreCase)))) throw new InvalidDataException("Exports must not contain secret or credential properties.");
    }
    [GeneratedRegex("^[A-Za-z0-9_.:-]{1,128}$", RegexOptions.CultureInvariant)] private static partial Regex IdPattern();
    [GeneratedRegex("^CVE-[0-9]{4}-[0-9]{4,}$", RegexOptions.CultureInvariant)] private static partial Regex CvePattern();
}

/// <summary>Dedicated CVE import entry point, requiring vulnerability-intel provenance.</summary>
public sealed class VulnerabilityIntelImporter
{
    public Task<ImportedEvidence> ImportAsync(Stream input, EvidenceImportAuthorization authorization, CancellationToken cancellationToken = default)
    {
        if (authorization.SourceId != "vulnerability-intel") throw new ArgumentException("Select vulnerability-intel as the authorized source.", nameof(authorization));
        return new ExportedEvidenceImporter().ImportAsync(input, authorization, cancellationToken);
    }
}
