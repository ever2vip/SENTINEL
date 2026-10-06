using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>Fixed read-only local Windows queries. No arbitrary command or remote execution.</summary>
public sealed class LocalEndpointEngine : IAssessmentEngine
{
    public EngineDescriptor Descriptor => new("endpoint", "Local Windows endpoint", "Read-only OS, firewall, Defender, BitLocker, installed hotfix and UAC observations on this computer. Inaccessible values remain unknown.", OperatingSystem.IsWindows(), OperatingSystem.IsWindows() ? "Available on this Windows computer; some observations require elevated read access." : "Windows-only collection is unavailable on this operating system.");

    private const string QueryScript = """
        $ErrorActionPreference = 'SilentlyContinue'
        $ProgressPreference = 'SilentlyContinue'
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $firewall = @(Get-NetFirewallProfile | Select-Object Name, Enabled)
        $defender = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
        $antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState)
        $drive = $env:SystemDrive
        $encryption = Get-BitLockerVolume -MountPoint $drive | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage, VolumeStatus
        $hotfix = Get-CimInstance -ClassName Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $latest = $null
        if ($hotfix.InstalledOn) { try { $latest = ([datetime]$hotfix.InstalledOn).ToUniversalTime().ToString('O') } catch {} }
        $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA
        $edition = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID
        [ordered]@{
          osName = $os.Caption; osVersion = $os.Version; osBuild = $os.BuildNumber;
          edition = $edition.EditionID; firewall = $firewall; defender = $defender;
          antivirus = $antivirus; encryption = $encryption; latestHotfix = $latest;
          latestHotfixId = $hotfix.HotFixID; uac = $policy.EnableLUA
        } | ConvertTo-Json -Depth 5 -Compress
        """;

    public async Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken)
    {
        context = ScopeGuard.Snapshot(context, cancellationToken);
        var evidence = new EvidenceBuilder(Descriptor.Id);
        if (!context.Scope.IncludeLocalEndpoint)
        {
            evidence.Message("Local endpoint collection was not selected in the authorized scope.");
            return evidence.Build();
        }
        if (!OperatingSystem.IsWindows())
        {
            evidence.Message(Descriptor.AvailabilityReason);
            return evidence.Build();
        }
        var asset = evidence.Asset(Environment.MachineName.ToLowerInvariant(), AssetKind.Endpoint, Environment.MachineName);
        asset.OperatingSystem = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
        evidence.Observe(asset, "Collector", "Fixed local read-only PowerShell/CIM queries; no remote commands or configuration changes.");
        context.Progress?.Report("Reading authorized local Windows posture");
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(executable))
        {
            evidence.Observe(asset, "Endpoint posture", "Unknown — Windows PowerShell was not available at the expected system location.");
            return evidence.Build();
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(context.Scope.TimeoutSeconds));
        using var process = new Process { StartInfo = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-EncodedCommand");
        process.StartInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(QueryScript)));
        try
        {
            process.Start();
            var outputTask = ReadBoundedAsync(process.StandardOutput, 131072, timeout.Token);
            var errorTask = ReadBoundedAsync(process.StandardError, 16384, timeout.Token);
            await Task.WhenAll(process.WaitForExitAsync(timeout.Token), outputTask, errorTask);
            if (process.ExitCode != 0)
            {
                evidence.Observe(asset, "Endpoint posture", "Unknown — local query could not complete. Review application logs and required read permissions.");
                return evidence.Build();
            }
            using var document = JsonDocument.Parse(await outputTask, new JsonDocumentOptions { MaxDepth = 12 });
            Analyze(evidence, asset, document.RootElement);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            evidence.Observe(asset, "Endpoint posture", "Unknown — local collection timed out.");
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            evidence.Observe(asset, "Endpoint posture", "Unknown — local collection was unavailable or returned an unsupported result.");
            evidence.Message("Local endpoint read access or result parsing failed. No failed check is counted as a passed security control.");
        }
        finally
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return evidence.Build();
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars, CancellationToken token)
    {
        var result = new StringBuilder();
        var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), token)) > 0)
        {
            if (result.Length + read > maxChars) throw new IOException("Local query output exceeded the collector limit.");
            result.Append(buffer, 0, read);
        }
        return result.ToString();
    }

    private static void Analyze(EvidenceBuilder evidence, Asset asset, JsonElement root)
    {
        var osName = Text(root, "osName");
        var version = Text(root, "osVersion");
        var build = Text(root, "osBuild");
        asset.OperatingSystem = osName == "Unknown" ? asset.OperatingSystem : $"{osName} {version} (build {build})";
        evidence.Observe(asset, "Operating system", asset.OperatingSystem);
        evidence.Observe(asset, "OS edition", Text(root, "edition"));
        var softwareId = EvidenceBuilder.StableId("software", asset.Id + ":windows:" + version + ":" + build);
        evidence.Node(new EvidenceNode { Id = softwareId, Label = asset.OperatingSystem, Kind = EvidenceKind.Software, Source = "endpoint" });
        evidence.Edge(asset.Id, softwareId, "runs-software");
        if (osName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) && !Text(root, "edition").Contains("EnterpriseS", StringComparison.OrdinalIgnoreCase))
            evidence.Finding(asset, "windows10-support", "Verify Windows 10 extended support coverage", "Standard Windows 10 support ended on 14 October 2025. Extended Security Updates or a supported specialized edition may apply; enrollment was not collected.", Severity.Medium, SecurityCategory.Endpoint, "Document valid support coverage or plan migration to a supported Windows release.", "Verify edition lifecycle and approved extended-support enrollment.", .8);
        if (Version.TryParse(version, out var parsed) && parsed.Major < 10)
            evidence.Finding(asset, "legacy-windows", "Legacy Windows version requires lifecycle review", "The collected Windows version predates Windows 10. Standard vendor support may have ended; extended contractual coverage must be verified.", Severity.High, SecurityCategory.Endpoint, "Check the exact edition's vendor lifecycle and upgrade or document valid extended support.", "Verify the installed version and vendor support agreement.", .85);
        if (root.TryGetProperty("firewall", out var firewall) && firewall.ValueKind == JsonValueKind.Array && firewall.GetArrayLength() > 0)
        {
            foreach (var profile in firewall.EnumerateArray())
            {
                var name = Text(profile, "Name");
                var enabled = Flag(profile, "Enabled");
                evidence.Observe(asset, "Firewall " + name, enabled?.ToString() ?? "Unknown");
                if (enabled is not null) evidence.Observe(asset, "CategoryCoverage", "assessed");
                if (enabled == false) evidence.Finding(asset, "firewall-disabled-" + name.ToLowerInvariant(), $"Windows firewall profile {name} is disabled", "The local firewall profile reported disabled. Determine whether this profile is active and whether approved compensating network controls apply.", Severity.High, SecurityCategory.Endpoint, "Enable the required firewall profile through approved management policy and review rule scope.", "Repeat local collection and verify Enabled for the relevant profile.", .95);
            }
        }
        else evidence.Observe(asset, "Firewall", "Unknown — profile data was inaccessible.");
        if (root.TryGetProperty("encryption", out var encryption) && encryption.ValueKind == JsonValueKind.Object)
        {
            var state = Text(encryption, "ProtectionStatus");
            if (state is "0" or "1" or "Off" or "On") evidence.Observe(asset, "CategoryCoverage", "assessed");
            evidence.Observe(asset, "System disk encryption", $"ProtectionStatus={state}; encrypted={Text(encryption, "EncryptionPercentage")}%.");
            if (state is "0" or "Off") evidence.Finding(asset, "disk-protection-off", "System disk BitLocker protection is disabled", "The system volume reported BitLocker protection Off. Encryption percentage alone does not confirm that key protection is active.", Severity.High, SecurityCategory.Endpoint, "Enable approved disk encryption and verify recovery-key custody through the organization's management process.", "Verify BitLocker ProtectionStatus is On and encryption is complete.");
        }
        else evidence.Observe(asset, "System disk encryption", "Unknown — BitLocker state was inaccessible or unsupported.");
        if (root.TryGetProperty("defender", out var defender) && defender.ValueKind == JsonValueKind.Object)
        {
            var realtime = Flag(defender, "RealTimeProtectionEnabled");
            if (realtime is not null) evidence.Observe(asset, "CategoryCoverage", "assessed");
            evidence.Observe(asset, "Defender real-time protection", realtime?.ToString() ?? "Unknown");
            if (realtime == false)
                evidence.Finding(asset, "defender-realtime-off", "Verify protection while Defender real-time protection is off", "Defender reported real-time protection disabled. A third-party provider or managed passive mode may provide protection; this check does not establish that the endpoint is unprotected.", Severity.Medium, SecurityCategory.Endpoint, "Verify the approved active endpoint protection provider and its current health; enable real-time protection where Defender is the intended provider.", "Confirm active provider health and repeat the local posture collection.", .8);
        }
        else evidence.Observe(asset, "Defender", "Unknown — Defender status was inaccessible or the provider is not installed.");
        if (root.TryGetProperty("antivirus", out var antivirus) && antivirus.ValueKind == JsonValueKind.Array)
            evidence.Observe(asset, "Registered antivirus providers", antivirus.GetArrayLength() > 0 ? string.Join(", ", antivirus.EnumerateArray().Select(item => Text(item, "displayName"))) + ". Registration alone does not prove current provider health." : "No Security Center registrations observed; this source may be unavailable on servers.");
        var latestHotfix = Text(root, "latestHotfix");
        evidence.Observe(asset, "Latest inventoried hotfix", latestHotfix);
        if (DateTimeOffset.TryParse(latestHotfix, out var installed) && DateTimeOffset.UtcNow - installed > TimeSpan.FromDays(60))
            evidence.Finding(asset, "patch-freshness-review", "Installed hotfix inventory is older than 60 days", $"The latest hotfix exposed by Win32_QuickFixEngineering was installed at {installed:u}. This inventory does not include every update type and is not proof of a missing specific patch.", Severity.Medium, SecurityCategory.Endpoint, "Review current Windows Update or enterprise patch-management compliance and install applicable approved updates.", "Confirm authoritative patch-management compliance and repeat endpoint collection.", .7);
        var uac = Text(root, "uac");
        if (uac is "0" or "1") evidence.Observe(asset, "CategoryCoverage", "assessed");
        evidence.Observe(asset, "User Account Control", uac == "0" ? "Disabled" : uac == "1" ? "Enabled" : "Unknown");
        if (uac == "0") evidence.Finding(asset, "uac-disabled", "User Account Control is disabled", "The local EnableLUA policy is 0. This reduces the separation between standard and elevated process execution.", Severity.Medium, SecurityCategory.Endpoint, "Enable User Account Control through approved policy after compatibility review.", "Repeat collection after the approved policy and restart take effect.");
    }

    private static string Text(JsonElement element, string name) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : "Unknown";
    private static bool? Flag(JsonElement element, string name)
    {
        var value = Text(element, name);
        return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1" ? true : value.Equals("false", StringComparison.OrdinalIgnoreCase) || value == "0" ? false : null;
    }
}
