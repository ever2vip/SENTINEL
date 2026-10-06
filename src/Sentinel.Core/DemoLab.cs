using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core;

/// <summary>
/// Deterministic, completely offline fixtures. All addresses and identities are synthetic.
/// Historical scores are reconstructed fixture scenarios, not claims that real scans occurred.
/// </summary>
public sealed class DemoLab : IDemoLab
{
    public const string Source = "Synthetic demo";

    public EnvironmentSnapshot Create(DateTimeOffset? now = null)
    {
        var at = now ?? DateTimeOffset.UtcNow;
        var snapshot = new EnvironmentSnapshot
        {
            Id = "sentinel-demo-northstar", Name = "Northstar Industries · Synthetic Demo Organization",
            Mode = EnvironmentMode.Demo, CreatedAt = at.AddDays(-90), UpdatedAt = at
        };
        var assets = new Dictionary<string, Asset>(StringComparer.Ordinal);
        AddNode("internet", "Internet (synthetic exposure)", EvidenceKind.Internet);

        for (var i = 1; i <= 250; i++)
        {
            var department = i <= 80 ? "Operations" : i <= 145 ? "Finance" : i <= 210 ? "Engineering" : "Corporate";
            var os = i <= 210 ? "Windows 11 Enterprise 24H2" : i <= 240 ? "Windows 10 Enterprise 22H2" : "Ubuntu 24.04 LTS";
            var asset = AddAsset($"endpoint-{i:000}", $"NS-{(i > 240 ? "LIN" : "WKS")}-{i:000}", AssetKind.Endpoint,
                $"10.24.{10 + (i - 1) / 100}.{10 + (i - 1) % 100}", os, department, department == "Finance" ? 4 : 2, 0.08);
            asset.Properties["diskEncryption"] = i % 19 == 0 ? "Not enabled (synthetic)" : "Enabled (synthetic)";
            asset.Properties["firewall"] = i % 31 == 0 ? "Disabled (synthetic)" : "Enabled (synthetic)";
            asset.Properties["endpointProtection"] = i % 43 == 0 ? "Stale signatures (synthetic)" : "Healthy (synthetic)";
            asset.Properties["patchAgeDays"] = (i % 29 == 0 ? 74 : 6 + i % 16).ToString(System.Globalization.CultureInfo.InvariantCulture);
            asset.Properties["supportedOs"] = (i <= 210 || i > 240).ToString();
            Observe(asset.Id, "demo-endpoint", "OperatingSystem", os);
            Observe(asset.Id, "demo-endpoint", "Firewall", asset.Properties["firewall"]);
            Observe(asset.Id, "demo-endpoint", "DiskEncryption", asset.Properties["diskEncryption"]);
        }

        var servers = new[]
        {
            ("server-dc01", "NS-DC01", "Windows Server 2022", 5), ("server-dc02", "NS-DC02", "Windows Server 2022", 5),
            ("server-file01", "NS-FILE01", "Windows Server 2022", 4), ("server-sql01", "NS-SQL01", "Windows Server 2022", 5),
            ("server-erp01", "NS-ERP01", "Ubuntu 22.04 LTS", 5), ("server-vpn01", "NS-VPN01", "Ubuntu 22.04 LTS", 3),
            ("server-web01", "NS-WEB01", "Ubuntu 22.04 LTS", 3), ("server-jump01", "NS-JUMP01", "Windows Server 2022", 3),
            ("server-backup01", "NS-BACKUP01", "Windows Server 2022", 5), ("server-git01", "NS-GIT01", "Ubuntu 24.04 LTS", 3),
            ("server-monitor01", "NS-MONITOR01", "Ubuntu 24.04 LTS", 3), ("server-print01", "NS-PRINT01", "Windows Server 2016", 2)
        };
        for (var i = 0; i < servers.Length; i++)
        {
            var s = servers[i];
            AddAsset(s.Item1, s.Item2, AssetKind.Server, $"10.24.1.{10 + i}", s.Item3, "Infrastructure", s.Item4,
                s.Item1 is "server-vpn01" or "server-web01" ? 0.95 : 0.12);
            Observe(s.Item1, "demo-endpoint", "PatchPosture", i == 4 ? "Application updates overdue (synthetic)" : "Current baseline (synthetic)");
        }
        for (var i = 1; i <= 10; i++)
        {
            AddAsset($"network-{i:00}", i == 1 ? "NS-EDGE-FW01" : i == 2 ? "NS-CORE-SW01" : $"NS-ACCESS-SW{i:00}",
                AssetKind.NetworkDevice, $"10.24.0.{i}", "Network appliance firmware (synthetic)", "Network Operations", i <= 2 ? 4 : 2, i == 1 ? 0.7 : 0.1);
            Observe($"network-{i:00}", "demo-network", "ManagementProtocol", i == 4 ? "HTTP management enabled (synthetic)" : "HTTPS management (synthetic)");
        }

        var clouds = new[]
        {
            ("cloud-azure-storage", "Finance archive storage", "Azure", 5, 0.9),
            ("cloud-azure-vm", "Production API virtual machine", "Azure", 4, 0.65),
            ("cloud-azure-vault", "Production key vault", "Azure", 5, 0.1),
            ("cloud-azure-nsg", "Production network security group", "Azure", 4, 0.5),
            ("cloud-azure-sub", "Northstar production subscription", "Azure", 5, 0.0),
            ("cloud-aws-bucket", "Customer exports S3 bucket", "AWS", 5, 0.95),
            ("cloud-aws-ec2", "Partner portal EC2 instance", "AWS", 4, 0.8),
            ("cloud-aws-role", "Deployment automation role", "AWS", 4, 0.1),
            ("cloud-aws-rds", "Orders RDS database", "AWS", 5, 0.1),
            ("cloud-aws-trail", "Central audit trail", "AWS", 4, 0.0),
            ("cloud-m365", "Northstar Microsoft 365 tenant", "Microsoft 365", 5, 0.8),
            ("cloud-gcp-project", "Analytics sandbox project", "Google Cloud", 3, 0.1)
        };
        foreach (var c in clouds)
        {
            var asset = AddAsset(c.Item1, c.Item2, AssetKind.CloudResource, $"synthetic://{c.Item3.ToLowerInvariant().Replace(' ', '-')}/{c.Item1}",
                "Managed cloud resource", "Cloud Platform", c.Item4, c.Item5);
            asset.Properties["provider"] = c.Item3;
            asset.Properties["accountId"] = "SYNTHETIC-NORTHSTAR-NO-REAL-ACCOUNT";
            Observe(asset.Id, "demo-cloud", "Provider", c.Item3);
        }
        var webNames = new[] { "portal", "api", "partners", "careers", "status" };
        for (var i = 0; i < webNames.Length; i++)
        {
            var name = webNames[i];
            var asset = AddAsset($"web-{name}", $"{name}.northstar.example.invalid", AssetKind.WebApplication,
                $"https://{name}.northstar.example.invalid", "HTTPS application", "Digital Services", i < 3 ? 4 : 2, 1);
            AddNode($"domain-{name}", asset.Name, EvidenceKind.Domain);
            AddEdge($"edge-domain-{name}", $"domain-{name}", asset.Id, "resolves-to", false);
            AddNode($"service-{name}-https", "HTTPS :443 (synthetic)", EvidenceKind.Service);
            AddEdge($"edge-webservice-{name}", $"service-{name}-https", asset.Id, "hosted-by", false);
            Observe(asset.Id, "demo-web", "Headers", name == "partners" ? "HSTS absent (synthetic)" : "HSTS observed (synthetic)");
            var cert = new CertificateRecord
            {
                Id = $"certificate-{name}", AssetId = asset.Id, Subject = $"CN={asset.Name}", Issuer = "Synthetic Demo Certificate Authority",
                NotAfter = at.AddDays(i == 2 ? 11 : 90 + i * 20), Thumbprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"SYNTHETIC-{name}")))
            };
            snapshot.Certificates.Add(cert);
            AddNode(cert.Id, $"Certificate: {asset.Name}", EvidenceKind.Certificate, properties: new() { ["notAfter"] = cert.NotAfter.ToString("O"), ["assetId"] = asset.Id, ["synthetic"] = "true" });
            AddEdge($"edge-cert-{name}", cert.Id, asset.Id, "secures", false);
        }
        AddNode("domain-mail", "northstar.example.invalid", EvidenceKind.Domain);

        for (var i = 1; i <= 220; i++)
        {
            var identity = new Identity
            {
                Id = $"identity-{i:000}", DisplayName = i <= 12 ? $"Demo administrator {i:00}" : $"Demo user {i:000}",
                PrincipalName = $"demo.user{i:000}@northstar.example.invalid", Provider = i <= 140 ? "Active Directory (synthetic)" : "Microsoft Entra ID (synthetic)",
                IsPrivileged = i <= 12, MfaEnabled = i <= 4 || i % 37 == 0 ? false : true,
                LastSignIn = at.AddDays(i % 23 == 0 ? -140 : -(i % 9)),
                Groups = i <= 4 ? ["group-domain-admins"] : i <= 12 ? ["group-cloud-admins"] : ["group-employees"],
                Permissions = i <= 4 ? ["Domain administration (synthetic)"] : i <= 12 ? ["Cloud resource contributor (synthetic)"] : []
            };
            snapshot.Identities.Add(identity);
            AddNode(identity.Id, identity.DisplayName, EvidenceKind.Identity, properties: new() { ["principal"] = identity.PrincipalName, ["privileged"] = identity.IsPrivileged.ToString(), ["synthetic"] = "true" });
        }
        foreach (var group in new[] { ("group-domain-admins", "Domain Administrators"), ("group-cloud-admins", "Cloud Administrators"), ("group-employees", "Employees") })
            AddNode(group.Item1, $"{group.Item2} (synthetic group)", EvidenceKind.Identity);
        foreach (var identity in snapshot.Identities)
            foreach (var group in identity.Groups) AddEdge($"member-{identity.Id}-{group}", identity.Id, group, "member-of", false);
        for (var i = 1; i <= 6; i++)
        {
            var identity = new Identity
            {
                Id = $"service-identity-{i:00}", DisplayName = $"Demo service account {i:00}", PrincipalName = $"svc.demo{i:00}@northstar.example.invalid",
                Provider = "Active Directory (synthetic)", IsPrivileged = i <= 2, MfaEnabled = null,
                LastSignIn = at.AddDays(-1), Groups = ["group-employees"], Permissions = i == 1 ? ["ERP service logon (synthetic)", "Finance share write (synthetic)"] : ["Service logon (synthetic)"]
            };
            snapshot.Identities.Add(identity);
            AddNode(identity.Id, identity.DisplayName, EvidenceKind.Identity);
        }

        // Framework nodes are reference mappings. Their presence alone never asserts assessment coverage.
        foreach (var control in ComplianceEngine.Controls)
            AddNode(control.Id, control.Title, EvidenceKind.Control, properties: new() { ["framework"] = control.Framework, ["description"] = control.Description, ["synthetic"] = "true" });

        var patchTargets = Enumerable.Range(1, 9).Select(i => $"endpoint-{i * 29:000}").Where(assets.ContainsKey).ToArray();
        for (var i = 0; i < patchTargets.Length; i++)
            AddFinding($"finding-patch-{i:00}", "Restore the managed endpoint patch baseline", SecurityCategory.Endpoint, Severity.High, [patchTargets[i]],
                "endpoint-patch-baseline", "Install approved cumulative updates using the enterprise patch process; restart within the maintenance window.",
                "Collect current OS build and pending-reboot state, then compare with the approved patch baseline.", ["NIST-CSF2.PR.PS-02", "CIS-v8.1-7.3"],
                "Synthetic endpoint management observation: cumulative update age exceeds 60 days.");
        AddFinding("finding-unencrypted", "Enable encryption on sensitive endpoints", SecurityCategory.Endpoint, Severity.High,
            Enumerable.Range(1, 250).Where(i => i % 19 == 0).Select(i => $"endpoint-{i:000}").ToArray(), "endpoint-encryption",
            "Enable managed disk encryption and escrow recovery material through the approved enterprise process; validate recovery before rollout.",
            "Collect encryption protection status and confirm recovery material is stored in the authorized recovery system.",
            ["NIST-CSF2.PR.DS-01", "CIS-v8.1-3.6"], "Synthetic protection inventory reports unencrypted system volumes.");
        AddFinding("finding-firewall", "Restore endpoint firewall enforcement", SecurityCategory.Endpoint, Severity.Medium,
            Enumerable.Range(1, 250).Where(i => i % 31 == 0).Select(i => $"endpoint-{i:000}").ToArray(), "endpoint-firewall",
            "Enable managed Windows Firewall profiles and review approved inbound exceptions before deployment.",
            "Reassess firewall profile state and confirm only documented inbound exceptions remain.", ["NIST-CSF2.PR.PS-01", "CIS-v8.1-4.5"],
            "Synthetic endpoint posture observation: one or more firewall profiles are disabled.");
        AddFinding("finding-legacy-os", "Migrate unsupported Windows 10 endpoints", SecurityCategory.Vulnerability, Severity.High,
            Enumerable.Range(211, 30).Select(i => $"endpoint-{i:000}").ToArray(), "unsupported-windows10",
            "Migrate compatible devices to supported Windows versions, or document applicable paid extended support and a retirement date.",
            "Verify each device has a supported OS or documented extended-support entitlement; reassess software inventory.",
            ["NIST-CSF2.PR.PS-02", "CIS-v8.1-2.2"], "Synthetic inventory contains Windows 10 22H2 devices with no recorded extended-support entitlement.");
        AddFinding("finding-signatures", "Refresh stale endpoint protection signatures", SecurityCategory.Endpoint, Severity.Medium,
            Enumerable.Range(1, 250).Where(i => i % 43 == 0).Select(i => $"endpoint-{i:000}").ToArray(), "endpoint-protection-signatures",
            "Restore connectivity to the approved protection update source and refresh signatures.", "Verify protection engine health and current signature timestamp.",
            ["NIST-CSF2.PR.PS-02"], "Synthetic protection telemetry shows definitions older than the approved threshold.");

        var sshFinding = AddFinding("finding-openssh", "Patch vulnerable OpenSSH on the gateway", SecurityCategory.Vulnerability, Severity.High,
            ["server-vpn01"], "openssh-upgrade", "Upgrade OpenSSH to the vendor-fixed package and restrict management access to the approved administrative network.",
            "Collect the installed vendor package build and compare its advisory status; verify management ACLs from an authorized scope.",
            ["NIST-CSF2.ID.RA-01", "CIS-v8.1-7.4"], "Synthetic package inventory: portable OpenSSH 9.3p1, without a vendor fix record.", "CVE-2024-6387", 8.1, 0.85);
        sshFinding.Software = "OpenSSH"; sshFinding.Version = "9.3p1";
        var log4j = AddFinding("finding-log4j", "Remove vulnerable Log4j from the ERP application", SecurityCategory.Vulnerability, Severity.Critical,
            ["server-erp01"], "erp-log4j-upgrade", "Deploy the vendor-supported ERP release with a fixed Log4j dependency and restrict the application to required callers.",
            "Collect a fresh application dependency inventory and verify the vulnerable component is absent; review allowed ingress.",
            ["NIST-CSF2.ID.RA-01", "NIST-CSF2.PR.PS-02", "CIS-v8.1-7.4"], "Synthetic software bill of materials: Log4j 2.14.1 in the ERP service.", "CVE-2021-44228", 10, 1);
        log4j.Software = "Apache Log4j"; log4j.Version = "2.14.1"; log4j.PrivilegeImpact = 0.7;
        log4j.FirstSeen = at.AddDays(-12);
        AddNode("software-log4j", "Apache Log4j 2.14.1 (synthetic inventory)", EvidenceKind.Software);
        AddEdge("edge-erp-software", "server-erp01", "software-log4j", "runs", false);
        AddNode("vulnerability-log4j", "CVE-2021-44228 (synthetic match)", EvidenceKind.Vulnerability);
        AddEdge("edge-software-vulnerability", "software-log4j", "vulnerability-log4j", "matched-to", false);
        var http2 = AddFinding("finding-http2", "Update the web reverse proxy HTTP/2 stack", SecurityCategory.Vulnerability, Severity.High,
            ["server-web01"], "http2-proxy-upgrade", "Update the reverse proxy to a vendor-supported fixed release and enable supported request-rate protections.",
            "Compare the running proxy build to the vendor advisory and inspect configured HTTP/2 request limits.",
            ["NIST-CSF2.PR.PS-02", "CIS-v8.1-7.4"], "Synthetic reverse-proxy package inventory matches an affected HTTP/2 implementation.", "CVE-2023-44487", 7.5, 0.95);
        http2.Software = "HTTP/2 reverse proxy"; http2.Version = "Synthetic affected release";

        var rdp = AddFinding("finding-rdp", "Restrict the internet-facing administrative service", SecurityCategory.Network, Severity.Critical,
            ["server-jump01"], "administration-ingress", "Remove public administrative ingress and require a managed access gateway with MFA and approved source restrictions.",
            "Reassess only the authorized public address and verify the administration port is unreachable outside the approved gateway.",
            ["NIST-CSF2.PR.IR-01", "CIS-v8.1-13.4"], "Synthetic firewall policy permits RDP from the synthetic Internet boundary.");
        assets["server-jump01"].Exposure = 1; rdp.PrivilegeImpact = 0.9;
        AddFinding("finding-network-management", "Enforce HTTPS for appliance administration", SecurityCategory.Network, Severity.Medium,
            ["network-04"], "appliance-management-tls", "Disable cleartext administrative HTTP and use validated HTTPS from the management segment.",
            "Inspect the appliance configuration and reassess the approved management ports.", ["NIST-CSF2.PR.DS-02", "CIS-v8.1-4.1"],
            "Synthetic appliance configuration has HTTP administration enabled.");
        var segmentation = AddFinding("finding-segmentation", "Separate the application tier from privileged infrastructure", SecurityCategory.Network, Severity.High,
            ["server-erp01", "server-dc01", "server-file01"], "tier-segmentation",
            "Apply documented network segmentation so application servers cannot access domain-management interfaces; allow only required business flows.",
            "Review the approved ACL policy and perform authorized connectivity checks for permitted and denied flows.",
            ["NIST-CSF2.PR.IR-01", "CIS-v8.1-13.4"], "Synthetic configuration evidence permits unnecessary application-to-management network reachability.");
        segmentation.IdentityReach = 0.8;

        var mfa = AddFinding("finding-admin-mfa", "Require phishing-resistant MFA for privileged identities", SecurityCategory.Identity, Severity.Critical,
            ["server-dc01", "cloud-m365", "cloud-azure-sub"], "privileged-mfa",
            "Require phishing-resistant MFA and managed access for privileged sign-ins, with documented emergency-access exclusions and monitored use.",
            "Review identity policy assignments and authorized sign-in evidence for each affected administrator.",
            ["NIST-CSF2.PR.AA-03", "CIS-v8.1-6.5"], "Synthetic identity policy export: four administrators lack an enforced MFA requirement.");
        mfa.PrivilegeImpact = 1; mfa.IdentityReach = 0.9; mfa.EvidenceIds.Add("identity-001");
        var excessive = AddFinding("finding-service-permission", "Reduce the ERP service identity permissions", SecurityCategory.Identity, Severity.High,
            ["server-erp01", "server-file01"], "erp-service-least-privilege",
            "Replace broad service-account permissions with the required service permissions and remove finance-share write access after owner review.",
            "Compare effective permissions before and after the change and validate the approved ERP business flow.",
            ["NIST-CSF2.PR.AA-05"], "Synthetic effective-permission evidence grants the ERP identity unnecessary finance-share write access.");
        excessive.PrivilegeImpact = 0.85; excessive.IdentityReach = 0.75; excessive.EvidenceIds.Add("service-identity-01");
        AddFinding("finding-dormant-identities", "Review dormant directory accounts", SecurityCategory.Identity, Severity.Medium,
            ["server-dc01", "cloud-m365"], "dormant-account-review", "Have identity owners review accounts without a recent authorized sign-in and disable accounts no longer required.",
            "Recollect last-sign-in and account-enabled state; document legitimate service-account exceptions.",
            ["NIST-CSF2.PR.AA-01", "CIS-v8.1-5.3"], "Synthetic identity inventory includes nine user accounts with no sign-in in 140 days.");
        AddFinding("finding-ad-delegation", "Review excessive Active Directory delegation", SecurityCategory.Identity, Severity.High,
            ["server-dc01", "server-dc02"], "directory-delegation", "Remove broad organizational-unit write delegations after documented owner review; apply least privilege.",
            "Export authorized directory ACLs again and confirm only documented delegation entries remain.",
            ["NIST-CSF2.PR.AA-05"], "Synthetic directory ACL evidence includes an unnecessarily broad delegated administration group.");

        var bucket = AddFinding("finding-public-bucket", "Remove public access from customer exports", SecurityCategory.Cloud, Severity.Critical,
            ["cloud-aws-bucket"], "public-customer-storage", "Enable S3 Block Public Access and remove public bucket policy grants after confirming approved partner-access requirements.",
            "Review the authorized bucket policy and access configuration using official APIs; verify approved partner access still works.",
            ["NIST-CSF2.PR.DS-01", "NIST-CSF2.PR.AA-05"], "Synthetic AWS configuration export shows a public-read policy on a customer export bucket.");
        bucket.Confidence = 0.96;
        AddFinding("finding-azure-storage", "Restrict anonymous access to the finance archive", SecurityCategory.Cloud, Severity.High,
            ["cloud-azure-storage"], "public-finance-storage", "Disable anonymous blob access and use authorized workload identities or time-limited approved access.",
            "Collect storage-account and container access settings through the official API and confirm anonymous access is disabled.",
            ["NIST-CSF2.PR.DS-01", "NIST-CSF2.PR.AA-05"], "Synthetic Azure configuration export shows anonymous container access enabled.");
        AddFinding("finding-cloud-role", "Scope the deployment automation role", SecurityCategory.Cloud, Severity.High,
            ["cloud-aws-role", "cloud-aws-rds"], "automation-role-scope", "Replace wildcard administrative actions and resources with the documented deployment permissions; use short-lived workload credentials.",
            "Review the authorized IAM policy and effective permissions, then validate normal deployment operation.",
            ["NIST-CSF2.PR.AA-05"], "Synthetic IAM policy export contains action and resource wildcards.");
        AddFinding("finding-audit-retention", "Restore centralized cloud audit retention", SecurityCategory.Cloud, Severity.Medium,
            ["cloud-aws-trail", "cloud-azure-sub"], "cloud-audit-retention", "Enable the approved audit destinations, retention policy, and alerting for audit configuration changes.",
            "Confirm official audit APIs show the configured destinations and recent records within the approved retention window.",
            ["NIST-CSF2.DE.CM-01"], "Synthetic cloud audit configuration has a seven-day retention gap.");
        AddFinding("finding-m365-legacy-auth", "Disable legacy Microsoft 365 authentication", SecurityCategory.Identity, Severity.High,
            ["cloud-m365"], "legacy-cloud-auth", "Disable unused legacy authentication protocols through approved identity policies; document necessary temporary exceptions.",
            "Review tenant policy and authorized sign-in logs to confirm legacy authentication is blocked.",
            ["NIST-CSF2.PR.AA-03", "CIS-v8.1-6.3"], "Synthetic Microsoft 365 policy export permits a legacy authentication exception.");

        AddFinding("finding-hsts", "Enforce a consistent HTTPS policy", SecurityCategory.Web, Severity.Medium,
            ["web-partners", "web-careers"], "web-hsts", "Enable HTTPS redirection and an appropriate HSTS policy after confirming all required subdomains support HTTPS.",
            "Perform an authorized HTTP HEAD/GET posture assessment and confirm HSTS and HTTPS redirection.",
            ["NIST-CSF2.PR.DS-02", "CIS-v8.1-4.1"], "Synthetic response headers omit Strict-Transport-Security.");
        AddFinding("finding-cookie", "Harden the partner portal session cookies", SecurityCategory.Web, Severity.High,
            ["web-partners"], "session-cookie-flags", "Set Secure, HttpOnly, and appropriate SameSite values on session cookies; validate normal sign-in flows.",
            "Inspect response cookie attributes during an authorized test session; no credentials are collected by SENTINEL.",
            ["NIST-CSF2.PR.DS-02"], "Synthetic response metadata includes a session cookie without the Secure flag.");
        AddFinding("finding-certificate", "Renew the partner portal certificate", SecurityCategory.Web, Severity.High,
            ["web-partners"], "certificate-renewal", "Renew and deploy the partner portal certificate through the approved certificate automation process.",
            "Recollect the presented certificate and verify hostname coverage, validity dates, and trusted chain.",
            ["NIST-CSF2.PR.DS-02"], "Synthetic certificate inventory shows expiration in eleven days.").EvidenceIds.Add("certificate-partners");
        AddFinding("finding-web-metadata", "Remove diagnostic version headers", SecurityCategory.Web, Severity.Low,
            ["web-api"], "web-diagnostic-headers", "Remove unnecessary detailed server and framework version headers from production responses.",
            "Reassess authorized response metadata and confirm detailed version values are absent.", ["NIST-CSF2.PR.PS-01"],
            "Synthetic response metadata discloses a detailed framework version; this is a low-confidence exposure contributor.", confidence: 0.8);
        AddFinding("finding-dmarc", "Enforce the enterprise email anti-spoofing policy", SecurityCategory.Email, Severity.High,
            ["cloud-m365"], "mail-domain-auth", "Review legitimate senders, align SPF and DKIM, then progress DMARC from monitoring to quarantine or reject while monitoring delivery.",
            "Collect authorized DNS TXT records and DMARC aggregate results; verify legitimate sender alignment before enforcing policy.",
            ["CIS-v8.1-9.5", "NIST-CSF2.PR.PS-01"], "Synthetic DNS evidence: DMARC p=none; SPF contains an obsolete include; DKIM selector exists but alignment needs review.").EvidenceIds.Add("domain-mail");
        Observe("cloud-m365", "demo-email", "DMARC", "v=DMARC1; p=none; rua=mailto:dmarc@northstar.example.invalid (synthetic)");
        AddFinding("finding-retention-policy", "Approve and verify evidence retention", SecurityCategory.Compliance, Severity.Medium,
            ["server-monitor01"], "evidence-retention-policy", "Have the governance owner approve evidence retention, access controls, and deletion requirements, then validate their operation.",
            "Review the approved policy and demonstrate retention and access-control behavior using authorized test evidence.",
            ["NIST-CSF2.PR.PS-01", "NIST-CSF2.DE.CM-01"], "Synthetic governance review identifies an unapproved evidence-retention standard.");

        // Include representative dispositions; accepted risks remain in analytics until actually fixed.
        var accepted = AddFinding("finding-accepted-print", "Isolate the legacy print service during migration", SecurityCategory.Endpoint, Severity.Medium,
            ["server-print01"], "legacy-print-migration", "Retire the legacy print service on the approved migration date; maintain restricted access and monitoring until then.",
            "Verify migration completion and reassess the remaining service exposure.", ["NIST-CSF2.PR.PS-02"],
            "Synthetic business exception documents an isolated legacy print dependency.");
        accepted.Status = FindingStatus.AcceptedRisk; accepted.AcceptedUntil = at.AddDays(21); accepted.DispositionReason = "Synthetic owner acceptance pending migration; review in 21 days."; accepted.CompensatingControl = 0.7;
        var fixedFinding = AddFinding("finding-fixed-backup", "Require encryption on the backup repository", SecurityCategory.Endpoint, Severity.High,
            ["server-backup01"], "backup-encryption", "Enable approved backup-at-rest encryption and manage keys through the enterprise key-management process.",
            "Verify encryption configuration and perform an authorized recovery validation.", ["NIST-CSF2.PR.DS-01"],
            "Synthetic follow-up evidence confirms encrypted backup storage.");
        fixedFinding.Status = FindingStatus.Fixed; fixedFinding.FixedAt = at.AddDays(-6); fixedFinding.LastSeen = at.AddDays(-6); fixedFinding.DispositionReason = "Synthetic follow-up verified configuration correction.";
        var falsePositive = AddFinding("finding-false-proxy", "Review a reported proxy version match", SecurityCategory.Vulnerability, Severity.Medium,
            ["server-web01"], "proxy-version-match", "Confirm the vendor build and backported fixes before applying a component version match.",
            "Compare the vendor package advisory to the exact installed build.", ["NIST-CSF2.ID.RA-01"], "Synthetic vendor evidence confirms the package contains a backported fix.");
        falsePositive.Status = FindingStatus.FalsePositive; falsePositive.DispositionReason = "Synthetic vendor package evidence confirms a backported fix; simple version-only match was invalid.";

        // Explicitly enabling paths are evidence relationships, never executable instructions.
        AddNode("service-rdp", "Public RDP administration (synthetic)", EvidenceKind.Service);
        AddNode("service-erp", "ERP application service (synthetic)", EvidenceKind.Service);
        AddNode("permission-admin", "Privileged administration relationship (synthetic)", EvidenceKind.Permission);
        AddNode("permission-finance", "Finance share write permission (synthetic)", EvidenceKind.Permission);
        AddNode("service-s3", "Public object access (synthetic)", EvidenceKind.Service);
        AddEdge("path-rdp-1", "internet", "service-rdp", "exposes", true, [rdp.Id], "Remove public RDP ingress; require the approved MFA-protected access gateway.");
        AddEdge("path-rdp-2", "service-rdp", "server-jump01", "hosted-by", true, [rdp.Id], "Restrict the administrative service to the managed access gateway.");
        AddEdge("path-rdp-3", "server-jump01", "identity-001", "administrative-session-relationship", true, [mfa.Id], "Require phishing-resistant MFA and privileged-access safeguards.", 0.9);
        AddEdge("path-rdp-4", "identity-001", "permission-admin", "has-permission", true, [mfa.Id], "Review and limit privileged account reach.");
        AddEdge("path-rdp-5", "permission-admin", "server-dc01", "administers", true, [mfa.Id], "Constrain domain administration to approved privileged workflows.");

        AddEdge("path-erp-1", "internet", "service-erp", "exposes", true, [log4j.Id], "Restrict public ERP ingress to approved application entry points.");
        AddEdge("path-erp-2", "service-erp", "server-erp01", "hosted-by", true, [log4j.Id], log4j.Remediation);
        // Continue beyond the critical ERP asset to model its identity's downstream permissions.
        AddEdge("path-finance-1", "server-erp01", "service-identity-01", "runs-with-identity", true, [log4j.Id, excessive.Id], log4j.Remediation, 0.82);
        AddEdge("path-finance-2", "service-identity-01", "permission-finance", "has-permission", true, [excessive.Id], excessive.Remediation);
        AddEdge("path-finance-3", "permission-finance", "server-file01", "can-write", true, [excessive.Id], "Remove unnecessary ERP service-account write access to finance data.");
        AddEdge("path-cloud-1", "internet", "service-s3", "exposes", true, [bucket.Id], bucket.Remediation);
        AddEdge("path-cloud-2", "service-s3", "cloud-aws-bucket", "publicly-accessible-resource", true, [bucket.Id], bucket.Remediation);
        AddEdge("path-vpn-1", "internet", "server-vpn01", "exposed-management-service", true, [sshFinding.Id], sshFinding.Remediation);
        AddEdge("path-vpn-2", "server-vpn01", "server-dc02", "unnecessary-management-reach", true, [segmentation.Id], segmentation.Remediation, 0.8);

        // Timeline records are labeled synthetic, including scenario scores recalculated by the production engine.
        AddChange("change-new-endpoint", at.AddDays(-2), "New asset", "Synthetic scenario: a new engineering endpoint entered the inventory.", "endpoint-250");
        AddChange("change-public-bucket", at.AddDays(-3), "New exposure", "Synthetic scenario: customer export storage gained public access.", bucket.Id);
        bucket.FirstSeen = at.AddDays(-3);
        AddChange("change-backup-fixed", at.AddDays(-6), "Resolved finding", "Synthetic scenario: backup encryption was verified and its finding closed.", fixedFinding.Id);
        AddChange("change-certificate", at.AddDays(-1), "Certificate expiration", "Synthetic scenario: the partner certificate entered the renewal window.", "certificate-partners");
        AddChange("change-policy", at.AddHours(-4), "Configuration change", "Synthetic scenario: a privileged identity policy exception was observed.", mfa.Id);
        AddChange("change-vulnerability", at.AddDays(-12), "New vulnerability", "Synthetic scenario: ERP dependency inventory matched a Log4j advisory.", log4j.Id);
        assets["endpoint-250"].FirstSeen = at.AddDays(-2);
        for (var i = 4; i >= 0; i--)
        {
            snapshot.Scans.Add(new ScanRun
            {
                Id = $"demo-scan-{i}", EngineId = "demo-fixture", ScopeSummary = "Offline synthetic fixture; no real targets contacted",
                Status = ScanStatus.Completed, StartedAt = at.AddDays(-7 * i).AddMinutes(-5), FinishedAt = at.AddDays(-7 * i),
                EventId = $"demo-event-{i}", Message = "Synthetic demo: reconstructed scenario assessment, not a real scan."
            });
            var scenario = HistoricalScenario(snapshot, at.AddDays(-7 * i));
            var score = new RiskEngine().Calculate(scenario, scenario.UpdatedAt);
            snapshot.ScoreHistory.Add(new ScoreHistory { At = scenario.UpdatedAt, Score = score.GlobalScore, Source = Source });
        }
        AddChange("change-score", at, "Security score", $"Synthetic scenario: current score is {snapshot.ScoreHistory[^1].Score:F1}; history represents reconstructed fixture scenarios.", snapshot.Id);
        snapshot.Changes = snapshot.Changes.OrderByDescending(x => x.At).ToList();
        return snapshot;

        Asset AddAsset(string id, string name, AssetKind kind, string address, string os, string owner, int criticality, double exposure)
        {
            var asset = new Asset
            {
                Id = id, Name = name, Kind = kind, Address = address, OperatingSystem = os, Owner = owner,
                Environment = "Synthetic Demo Organization", BusinessCriticality = criticality, Exposure = exposure,
                FirstSeen = at.AddDays(-90), LastSeen = at,
                Properties = new() { ["synthetic"] = "true", ["source"] = Source, ["businessService"] = owner, ["authorization"] = "Offline fixture; no live target" }
            };
            snapshot.Assets.Add(asset); assets[id] = asset;
            AddNode(id, name, kind == AssetKind.CloudResource ? EvidenceKind.CloudResource : EvidenceKind.Asset,
                properties: new() { ["assetId"] = id, ["criticality"] = criticality.ToString(System.Globalization.CultureInfo.InvariantCulture), ["synthetic"] = "true" });
            if (kind is AssetKind.Endpoint or AssetKind.Server or AssetKind.NetworkDevice)
            {
                AddNode($"ip-{id}", address, EvidenceKind.IP);
                AddEdge($"edge-ip-{id}", id, $"ip-{id}", "has-address", false);
            }
            return asset;
        }

        void AddNode(string id, string label, EvidenceKind kind, double confidence = 1, Dictionary<string, string>? properties = null) =>
            snapshot.Nodes.Add(new EvidenceNode { Id = id, Label = label, Kind = kind, Source = Source, Confidence = confidence, ObservedAt = at, Properties = properties ?? new() { ["synthetic"] = "true" } });

        void AddEdge(string id, string sourceId, string targetId, string relationship, bool enables, List<string>? dependencies = null, string defensiveBreak = "", double confidence = 1) =>
            snapshot.Edges.Add(new EvidenceEdge { Id = id, SourceId = sourceId, TargetId = targetId, Relationship = relationship, EnablesPath = enables, FindingIds = dependencies ?? [], DefensiveBreak = defensiveBreak, Confidence = confidence });

        void Observe(string assetId, string engineId, string property, string value) => snapshot.Observations.Add(new Observation
        { Id = $"observation-{assetId}-{property.ToLowerInvariant()}", AssetId = assetId, EngineId = engineId, Property = property, Value = value, Source = Source, ObservedAt = at });

        Finding AddFinding(string id, string title, SecurityCategory category, Severity severity, string[] assetIds, string root,
            string remediation, string verification, List<string> controls, string evidenceText, string? cve = null, double cvss = 0,
            double exploitability = 0, double confidence = 0.96)
        {
            var evidenceId = $"evidence-{id}";
            AddNode(evidenceId, evidenceText, EvidenceKind.Finding, confidence, new() { ["synthetic"] = "true", ["category"] = category.ToString(), ["observation"] = evidenceText });
            AddNode(id, title, EvidenceKind.Finding, confidence);
            AddEdge($"edge-finding-evidence-{id}", id, evidenceId, "supported-by", false);
            foreach (var assetId in assetIds) AddEdge($"edge-finding-asset-{id}-{assetId}", id, assetId, "affects", false);
            foreach (var control in controls) AddEdge($"edge-finding-control-{id}-{control}", id, control, "maps-to", false);
            var finding = new Finding
            {
                Id = id, Title = title, Description = $"{evidenceText} This is synthetic demonstration evidence; no real environment has been assessed.",
                RootCauseKey = root, Severity = severity, Category = category, Status = FindingStatus.Open, AssetIds = assetIds.ToList(),
                EvidenceIds = [evidenceId], ControlIds = controls, Confidence = confidence, Cvss = cvss, Cve = cve,
                Exploitability = exploitability, Remediation = remediation, Verification = verification, Source = Source,
                FirstSeen = at.AddDays(-45), LastSeen = at,
                References = cve is null ? ["https://www.nist.gov/cyberframework", "https://www.cisecurity.org/controls"] : [$"https://nvd.nist.gov/vuln/detail/{cve}"]
            };
            snapshot.Findings.Add(finding);
            return finding;
        }

        void AddChange(string id, DateTimeOffset date, string kind, string summary, string entityId) => snapshot.Changes.Add(new ChangeEvent
        { Id = id, At = date, Kind = kind, Summary = summary, EntityId = entityId, Source = Source });
    }

    private static EnvironmentSnapshot HistoricalScenario(EnvironmentSnapshot current, DateTimeOffset at)
    {
        // Retain the same actual graph and assets; introduced findings are absent before their fixture date.
        // The backup gap was active before its recorded remediation, so changing that disposition uses a copy.
        var findings = current.Findings.Where(x => x.FirstSeen <= at).Select(x => x.FixedAt > at ? new Finding
        {
            Id = x.Id, Title = x.Title, Description = x.Description, RootCauseKey = x.RootCauseKey, Severity = x.Severity,
            Category = x.Category, Status = FindingStatus.Open, Cvss = x.Cvss, Cve = x.Cve, Software = x.Software, Version = x.Version,
            Exploitability = x.Exploitability, Confidence = x.Confidence, PrivilegeImpact = x.PrivilegeImpact, IdentityReach = x.IdentityReach,
            CompensatingControl = x.CompensatingControl, AssetIds = x.AssetIds, EvidenceIds = x.EvidenceIds, ControlIds = x.ControlIds,
            Remediation = x.Remediation, Verification = x.Verification, Source = Source, FirstSeen = x.FirstSeen, LastSeen = at
        } : x).ToList();
        return new EnvironmentSnapshot
        {
            Id = current.Id, Name = current.Name, Mode = EnvironmentMode.Demo, CreatedAt = current.CreatedAt, UpdatedAt = at,
            Assets = current.Assets, Findings = findings, Identities = current.Identities, Nodes = current.Nodes, Edges = current.Edges,
            Observations = current.Observations, Scans = [], Certificates = current.Certificates
        };
    }
}
