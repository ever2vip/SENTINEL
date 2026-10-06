using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>One HEAD request per exact authorized URL. Redirects are never followed.</summary>
public sealed class WebPostureEngine : IAssessmentEngine
{
    public EngineDescriptor Descriptor { get; } = new("web", "Web posture", "Read-only HEAD requests, strict system certificate validation, certificate lifetime, security headers and cookie attributes. Response bodies are never collected.", true, "Available");

    public async Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken)
    {
        context = ScopeGuard.Snapshot(context, cancellationToken);
        var evidence = new EvidenceBuilder(Descriptor.Id);
        var targets = context.Scope.WebUrls.Select(ScopeGuard.ParseWebUrl).DistinctBy(uri => uri.AbsoluteUri).ToArray();
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = context.Scope.MaxConcurrency, CancellationToken = cancellationToken }, async (uri, token) =>
        {
            ScopeGuard.EnsureActive(context.Scope, token);
            var asset = evidence.Asset(uri.AbsoluteUri, AssetKind.WebApplication, uri.IdnHost);
            X509Certificate2? collectedCertificate = null;
            SslPolicyErrors certificateErrors = SslPolicyErrors.None;
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                CheckCertificateRevocationList = true,
                MaxResponseHeadersLength = 32,
                ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                {
                    certificateErrors = errors;
                    if (certificate is not null) collectedCertificate = X509CertificateLoader.LoadCertificate(certificate.RawData);
                    return errors == SslPolicyErrors.None;
                }
            };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(context.Scope.TimeoutSeconds));
            using var request = new HttpRequestMessage(HttpMethod.Head, uri);
            request.Headers.UserAgent.ParseAdd("SENTINEL/1.0 DefensivePosture");
            try
            {
                context.Progress?.Report($"Checking web posture for {uri.IdnHost}");
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                evidence.Observe(asset, "HTTP status", ((int)response.StatusCode).ToString());
                evidence.Observe(asset, "Collection method", "HEAD only; response body not collected; redirects not followed.");
                evidence.Observe(asset, "TLS protocol coverage", uri.Scheme == "https" ? "Successful system-policy TLS handshake. Support for obsolete protocols was not probed." : "HTTP; TLS was not used.");
                if (uri.Scheme == "http")
                    evidence.Finding(asset, "https-required", "Authorized web URL uses unencrypted HTTP", "The exact authorized URL responded over HTTP. No HTTPS alternative was probed unless independently included in the scope.", Severity.Medium, SecurityCategory.Web, "Serve the application over HTTPS and redirect HTTP requests at the approved entry point.", "Authorize and assess the HTTPS URL; verify HTTP returns a redirect to that URL.");
                if ((int)response.StatusCode is >= 300 and < 400)
                {
                    var location = response.Headers.Location;
                    if (location is not null && Uri.TryCreate(uri, location, out var destination))
                        evidence.Observe(asset, "Redirect", $"Not followed. Destination host: {destination.IdnHost}; authorized host: {DestinationIsAuthorized(context.Scope, destination)}.");
                    else evidence.Observe(asset, "Redirect", "Not followed; destination was absent or malformed.");
                    evidence.Message($"{uri.IdnHost}: redirect was not followed. Authorize the final URL explicitly to assess its headers.");
                }
                else if (response.IsSuccessStatusCode)
                {
                    evidence.Observe(asset, "CategoryCoverage", "assessed");
                    CheckHeader(evidence, asset, response, "X-Content-Type-Options", "nosniff", Severity.Low, "Configure X-Content-Type-Options: nosniff.");
                    CheckHeader(evidence, asset, response, "Content-Security-Policy", null, Severity.Low, "Develop and deploy a Content-Security-Policy appropriate to this application's resources.");
                    if (!response.Headers.Contains("X-Frame-Options") && !(response.Headers.TryGetValues("Content-Security-Policy", out var policies) && policies.Any(p => p.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))))
                        evidence.Finding(asset, "frame-protection", "Frame embedding protection was not observed", "The HEAD response had neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive. Applicability depends on whether this endpoint serves an interactive page.", Severity.Low, SecurityCategory.Web, "For interactive pages, configure CSP frame-ancestors with approved origins.", "Inspect the actual page response and repeat the HEAD assessment.", .8);
                    if (uri.Scheme == "https") CheckHeader(evidence, asset, response, "Strict-Transport-Security", "max-age=", Severity.Low, "Configure HSTS after validating HTTPS coverage for the applicable domain.");
                    CheckCookies(evidence, asset, response, uri.Scheme == "https");
                }
                else
                {
                    evidence.Observe(asset, "Header posture", "Unknown — the HEAD response was not a successful application response.");
                    evidence.Message($"{uri.IdnHost}: HTTP {(int)response.StatusCode}. Application header coverage is unknown; no alternative request or authentication was attempted.");
                }
                if (collectedCertificate is not null) AddCertificate(evidence, asset, collectedCertificate, certificateErrors == SslPolicyErrors.None);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                evidence.Observe(asset, "Web posture", "Unknown — the authorized HEAD request timed out.");
            }
            catch (HttpRequestException ex)
            {
                evidence.Observe(asset, "Web posture", $"Unknown — request failed ({ex.HttpRequestError}). No certificate validation was bypassed.");
                if (collectedCertificate is not null && certificateErrors != SslPolicyErrors.None)
                {
                    evidence.Observe(asset, "Certificate validation", certificateErrors.ToString());
                    AddCertificate(evidence, asset, collectedCertificate, false);
                    evidence.Finding(asset, "certificate-validation", "TLS certificate failed system validation", "The presented certificate failed strict system trust, name or chain validation. The HTTP request was blocked. Local trust configuration can affect this result.", Severity.High, SecurityCategory.Web, "Confirm the certificate hostname, lifetime and issuer chain with the owner; deploy a certificate trusted by the intended clients.", "Repeat this exact authorized URL using strict certificate validation.", .95);
                }
            }
            finally { collectedCertificate?.Dispose(); }
        });
        cancellationToken.ThrowIfCancellationRequested();
        evidence.Message("Web posture is based on exact-URL HEAD responses. DNS, obsolete TLS versions and application vulnerabilities require separate authorized evidence.");
        return evidence.Build();
    }

    private static void CheckHeader(EvidenceBuilder evidence, Asset asset, HttpResponseMessage response, string name, string? expected, Severity severity, string remediation)
    {
        var found = response.Headers.TryGetValues(name, out var values) && values.Any(v => !string.IsNullOrWhiteSpace(v) && (expected is null || v.Contains(expected, StringComparison.OrdinalIgnoreCase)));
        evidence.Observe(asset, name, found ? "Observed in HEAD response." : "Expected policy was not observed in HEAD response.");
        if (!found) evidence.Finding(asset, "header-" + name.ToLowerInvariant(), $"{name} policy was not observed", "The expected policy was not present in a successful HEAD response. Header coverage on actual pages and the application's requirements should be verified.", severity, SecurityCategory.Web, remediation, "Inspect an application response and repeat the authorized HEAD assessment.", .85);
    }

    private static bool DestinationIsAuthorized(ScanScope scope, Uri destination)
    {
        try { return destination.Scheme is "https" or "http" && ScopeGuard.IsAuthorizedHost(scope, destination.IdnHost); }
        catch (ArgumentException) { return false; }
    }

    private static void CheckCookies(EvidenceBuilder evidence, Asset asset, HttpResponseMessage response, bool https)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            evidence.Observe(asset, "Cookie posture", "Unknown — no Set-Cookie headers were observed in the HEAD response.");
            return;
        }
        var all = cookies.Take(128).ToArray();
        var missingSecure = all.Count(c => !c.Split(';').Skip(1).Any(a => a.Trim().Equals("Secure", StringComparison.OrdinalIgnoreCase)));
        var missingHttpOnly = all.Count(c => !c.Split(';').Skip(1).Any(a => a.Trim().Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)));
        var missingSameSite = all.Count(c => !c.Split(';').Skip(1).Any(a => a.Trim().StartsWith("SameSite=", StringComparison.OrdinalIgnoreCase)));
        evidence.Observe(asset, "Cookie posture", $"{all.Length} Set-Cookie headers; Secure missing: {missingSecure}; HttpOnly missing: {missingHttpOnly}; SameSite missing: {missingSameSite}. Cookie names and values were not collected.");
        if (https && missingSecure > 0) evidence.Finding(asset, "cookie-secure", "Cookies without Secure attribute observed", $"{missingSecure} Set-Cookie headers lacked Secure. Cookie sensitivity was not collected or inferred.", Severity.Medium, SecurityCategory.Web, "Mark security-sensitive cookies Secure; review each cookie's intended use.", "Inspect cookie attributes over HTTPS and repeat the assessment.", .9);
        if (missingHttpOnly > 0) evidence.Finding(asset, "cookie-httponly", "Review cookies without HttpOnly", $"{missingHttpOnly} Set-Cookie headers lacked HttpOnly. Some client-readable cookies may intentionally omit this attribute.", Severity.Low, SecurityCategory.Web, "Set HttpOnly for authentication and sensitive cookies that do not require script access.", "Review cookie purpose and attributes; repeat the assessment.", .7);
        if (missingSameSite > 0) evidence.Finding(asset, "cookie-samesite", "Explicit SameSite cookie policy was not observed", $"{missingSameSite} Set-Cookie headers lacked an explicit SameSite attribute. Browser defaults and application workflow affect risk.", Severity.Low, SecurityCategory.Web, "Choose and configure an explicit SameSite policy compatible with the approved workflow.", "Inspect the application's cookie attributes and cross-site request protections.", .75);
    }

    private static void AddCertificate(EvidenceBuilder evidence, Asset asset, X509Certificate2 certificate, bool trusted)
    {
        var id = EvidenceBuilder.StableId("certificate", certificate.Thumbprint);
        evidence.Certificate(new CertificateRecord { Id = id, AssetId = asset.Id, Subject = certificate.Subject, Issuer = certificate.Issuer, Thumbprint = certificate.Thumbprint, NotAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()) });
        evidence.Node(new EvidenceNode { Id = id, Label = certificate.Subject, Kind = EvidenceKind.Certificate, Source = "web", Properties = new() { ["notAfter"] = certificate.NotAfter.ToUniversalTime().ToString("O"), ["trusted"] = trusted.ToString() } });
        evidence.Edge(asset.Id, id, "presents-certificate");
        var days = (certificate.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;
        evidence.Observe(asset, "Certificate expiration", certificate.NotAfter.ToUniversalTime().ToString("O"));
        if (days <= 30) evidence.Finding(asset, "certificate-expiry", days < 0 ? "TLS certificate is expired" : "TLS certificate expires within 30 days", $"Presented certificate expires at {certificate.NotAfter.ToUniversalTime():u}.", days < 0 ? Severity.High : Severity.Medium, SecurityCategory.Web, "Renew and deploy the certificate through the approved certificate-management process.", "Repeat the exact authorized URL and confirm a new certificate with a later expiration.");
    }
}
