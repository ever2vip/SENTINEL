namespace Sentinel.Core;

/// <summary>Maps observed gaps to framework outcomes; it cannot establish certification or complete compliance.</summary>
public sealed class ComplianceEngine : IComplianceEngine
{
    public static IReadOnlyList<ComplianceControl> Controls { get; } = Array.AsReadOnly(new[]
    {
        new ComplianceControl("NIST-CSF2.ID.AM-01", "NIST CSF 2.0", "Hardware inventories", "Maintain inventories of hardware managed by the organization."),
        new ComplianceControl("NIST-CSF2.ID.AM-02", "NIST CSF 2.0", "Software and service inventories", "Maintain inventories of software, systems, and services."),
        new ComplianceControl("NIST-CSF2.ID.RA-01", "NIST CSF 2.0", "Identify asset vulnerabilities", "Identify, validate, and record vulnerabilities in assets."),
        new ComplianceControl("NIST-CSF2.ID.RA-06", "NIST CSF 2.0", "Prioritize risk responses", "Choose, prioritize, plan, track, and communicate risk responses."),
        new ComplianceControl("NIST-CSF2.PR.AA-01", "NIST CSF 2.0", "Manage identities and credentials", "Manage identities and credentials for authorized users, services, and hardware."),
        new ComplianceControl("NIST-CSF2.PR.AA-03", "NIST CSF 2.0", "Authenticate users and services", "Authenticate users, services, and hardware."),
        new ComplianceControl("NIST-CSF2.PR.AA-05", "NIST CSF 2.0", "Least privilege and access review", "Define, manage, enforce, and review access permissions using least privilege and separation of duties."),
        new ComplianceControl("NIST-CSF2.PR.DS-01", "NIST CSF 2.0", "Protect data at rest", "Protect confidentiality, integrity, and availability of data at rest."),
        new ComplianceControl("NIST-CSF2.PR.DS-02", "NIST CSF 2.0", "Protect data in transit", "Protect confidentiality, integrity, and availability of data in transit."),
        new ComplianceControl("NIST-CSF2.PR.PS-01", "NIST CSF 2.0", "Configuration management", "Establish and apply configuration management practices."),
        new ComplianceControl("NIST-CSF2.PR.PS-02", "NIST CSF 2.0", "Maintain software", "Maintain, replace, and remove software commensurate with risk."),
        new ComplianceControl("NIST-CSF2.PR.IR-01", "NIST CSF 2.0", "Protect networks from unauthorized access", "Protect networks and environments from unauthorized logical access and usage."),
        new ComplianceControl("NIST-CSF2.DE.CM-01", "NIST CSF 2.0", "Monitor networks", "Monitor networks and network services to find potentially adverse events."),
        new ComplianceControl("CIS-v8.1-1.1", "CIS Controls v8.1", "Enterprise asset inventory", "Establish and maintain a detailed enterprise asset inventory."),
        new ComplianceControl("CIS-v8.1-2.2", "CIS Controls v8.1", "Supported software", "Ensure authorized software is currently supported."),
        new ComplianceControl("CIS-v8.1-3.6", "CIS Controls v8.1", "Encrypt end-user devices", "Encrypt data on end-user devices containing sensitive data."),
        new ComplianceControl("CIS-v8.1-4.1", "CIS Controls v8.1", "Secure configuration process", "Establish and maintain a secure configuration process."),
        new ComplianceControl("CIS-v8.1-4.5", "CIS Controls v8.1", "Firewall on end-user devices", "Implement and manage a firewall on end-user devices."),
        new ComplianceControl("CIS-v8.1-5.3", "CIS Controls v8.1", "Disable dormant accounts", "Delete or disable dormant accounts after the defined period where supported."),
        new ComplianceControl("CIS-v8.1-6.3", "CIS Controls v8.1", "MFA for externally exposed applications", "Require MFA for externally exposed applications where supported."),
        new ComplianceControl("CIS-v8.1-6.5", "CIS Controls v8.1", "MFA for administrative access", "Require MFA for administrative access where supported."),
        new ComplianceControl("CIS-v8.1-7.2", "CIS Controls v8.1", "Remediation process", "Establish and maintain a risk-based remediation process."),
        new ComplianceControl("CIS-v8.1-7.3", "CIS Controls v8.1", "Operating system patching", "Perform automated operating system patch management."),
        new ComplianceControl("CIS-v8.1-7.4", "CIS Controls v8.1", "Application patching", "Perform automated application patch management."),
        new ComplianceControl("CIS-v8.1-9.2", "CIS Controls v8.1", "DNS filtering", "Use DNS filtering services on enterprise assets."),
        new ComplianceControl("CIS-v8.1-9.5", "CIS Controls v8.1", "DMARC", "Implement DMARC to reduce forged or modified email from the enterprise domain."),
        new ComplianceControl("CIS-v8.1-13.4", "CIS Controls v8.1", "Traffic filtering between segments", "Perform traffic filtering between network segments where appropriate.")
    });

    public IReadOnlyList<ComplianceResult> Assess(EnvironmentSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        // Additional controls supplied as graph evidence are the framework extension boundary.
        var custom = snapshot.Nodes.Where(x => x.Kind == EvidenceKind.Control && x.Properties.ContainsKey("framework"))
            .Select(x => new ComplianceControl(x.Id, x.Properties["framework"], x.Label, x.Properties.GetValueOrDefault("description", "Organization-supplied control mapping.")));
        var controls = Controls.Concat(custom).GroupBy(x => x.Id, StringComparer.Ordinal).Select(x => x.First()).ToList();
        var results = new List<ComplianceResult>();
        foreach (var control in controls)
        {
            var mapped = snapshot.Findings.Where(x => x.ControlIds.Contains(control.Id, StringComparer.Ordinal)).ToList();
            var active = mapped.Where(RiskEngine.IsActive).OrderBy(x => x.Id, StringComparer.Ordinal).ToList();
            var controlEvidence = snapshot.Nodes.Any(x => x.Kind == EvidenceKind.Control &&
                (x.Id == control.Id || x.Properties.GetValueOrDefault("controlId") == control.Id) &&
                x.Properties.GetValueOrDefault("assessmentStatus") == "Assessed");
            var status = active.Count > 0 ? "Observed gap" : mapped.Any(x => x.Status == FindingStatus.Fixed) ?
                "No active mapped gaps; coverage incomplete" : controlEvidence ? "Evidence collected; review required" : "Not assessed";
            results.Add(new ComplianceResult(control, status, active.Select(x => x.Id).ToArray()));
        }
        return results;
    }
}
