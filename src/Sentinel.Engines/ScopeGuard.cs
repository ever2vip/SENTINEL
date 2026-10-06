using System.Globalization;
using System.Collections.Frozen;
using System.Net;
using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>Enforces the operator's exact, short-lived authorization before any collection.</summary>
public static class ScopeGuard
{
    public static readonly TimeSpan AuthorizationLifetime = TimeSpan.FromHours(24);
    public static IReadOnlySet<int> AllowedPorts { get; } = new[]
    { 21, 22, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017 }.ToFrozenSet();

    public static void Validate(ScanScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var now = DateTimeOffset.UtcNow;
        if (!scope.AuthorizationConfirmed || string.IsNullOrWhiteSpace(scope.AuthorizedBy) || scope.AuthorizedBy.Length > 200)
            throw new ArgumentException("Confirm that you own or are authorized to assess this environment and identify the authorizing operator.", nameof(scope));
        if (scope.AuthorizedAt > now.AddMinutes(2) || scope.AuthorizedAt < now - AuthorizationLifetime)
            throw new ArgumentException("Assessment authorization has expired or has an invalid date. Confirm the exact scope again.", nameof(scope));
        if (scope.Hosts is null || scope.WebUrls is null || scope.Ports is null)
            throw new ArgumentException("Scope target lists must be supplied.", nameof(scope));
        if (scope.Hosts.Count > 128 || scope.WebUrls.Count > 64 || scope.Ports.Count > 32)
            throw new ArgumentException("An assessment is limited to 128 exact hosts, 64 URLs and 32 selected ports.", nameof(scope));
        if (scope.TimeoutSeconds is < 1 or > 30 || scope.MaxConcurrency is < 1 or > 16)
            throw new ArgumentException("Use a timeout of 1–30 seconds and concurrency of 1–16.", nameof(scope));
        if ((long)scope.Hosts.Count * scope.Ports.Count > 4096)
            throw new ArgumentException("The selected scope exceeds 4,096 host/port checks.", nameof(scope));
        foreach (var host in scope.Hosts) _ = NormalizeHost(host);
        foreach (var url in scope.WebUrls) _ = ParseWebUrl(url);
        if (scope.Ports.Any(port => !AllowedPorts.Contains(port)))
            throw new ArgumentException("Select only supported defensive posture ports from ScopeGuard.AllowedPorts.", nameof(scope));
    }

    public static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || host != host.Trim() || host.Any(char.IsWhiteSpace) || host.IndexOfAny(['/', '\\', '*', '?', '@', '#', '%']) >= 0)
            throw new ArgumentException("Use exact IP addresses or hostnames; ranges, CIDR, wildcards and credentials are not allowed.", nameof(host));
        if (IPAddress.TryParse(host, out var address)) return address.ToString();
        string canonical;
        try { canonical = new IdnMapping().GetAscii(host).ToLowerInvariant(); }
        catch (ArgumentException) { throw new ArgumentException("The hostname is malformed.", nameof(host)); }
        if (canonical.EndsWith('.') || canonical.Contains(':') || canonical.Split('.').Any(label => label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-' || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("The hostname is malformed. Use an exact hostname without a trailing dot.", nameof(host));
        // A malformed address must not fall through as a hostname.
        if (canonical.All(c => char.IsAsciiDigit(c) || c == '.'))
            throw new ArgumentException("The IP address is malformed.", nameof(host));
        return canonical;
    }

    public static Uri ParseWebUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || value != value.Trim() || value.Contains('\\') || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.Query.Length != 0)
            throw new ArgumentException("Web scope requires exact HTTP/HTTPS URLs without credentials, query strings or fragments. Authorize a public resource path that does not embed secrets.", nameof(value));
        _ = NormalizeHost(uri.IdnHost);
        return uri;
    }

    public static bool IsAuthorizedHost(ScanScope scope, string host)
    {
        var normalized = NormalizeHost(host);
        return scope.Hosts.Any(candidate => NormalizeHost(candidate) == normalized)
            || scope.WebUrls.Any(url => ParseWebUrl(url).IdnHost.Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    internal static void EnsureActive(ScanScope scope, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Validate(scope);
    }

    internal static ScanContext Snapshot(ScanContext context, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(context);
        EnsureActive(context.Scope, token);
        var scope = new ScanScope
        {
            AuthorizationConfirmed = context.Scope.AuthorizationConfirmed,
            AuthorizedBy = context.Scope.AuthorizedBy,
            AuthorizedAt = context.Scope.AuthorizedAt,
            Hosts = context.Scope.Hosts.Select(NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            WebUrls = context.Scope.WebUrls.Select(url => ParseWebUrl(url).AbsoluteUri).Distinct().ToList(),
            Ports = context.Scope.Ports.Distinct().ToList(),
            IncludeLocalEndpoint = context.Scope.IncludeLocalEndpoint,
            TimeoutSeconds = context.Scope.TimeoutSeconds,
            MaxConcurrency = context.Scope.MaxConcurrency
        };
        Validate(scope);
        return context with { Scope = scope };
    }
}
