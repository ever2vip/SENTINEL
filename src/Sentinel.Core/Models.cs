namespace Sentinel.Core;

public enum EnvironmentMode { Demo, Live }
public enum AssetKind { Endpoint, Server, NetworkDevice, CloudResource, WebApplication }
public enum Severity { Informational, Low, Medium, High, Critical }
public enum SecurityCategory { Network, Endpoint, Identity, Cloud, Vulnerability, Web, Email, Compliance }
public enum FindingStatus { Open, Fixed, AcceptedRisk, FalsePositive }
public enum EvidenceKind { Asset, Identity, IP, Domain, Service, Software, Vulnerability, CloudResource, Permission, Finding, Control, Certificate, Internet }
public enum ScanStatus { Running, Completed, Cancelled, Failed }
public enum ReportKind { Executive, Technical, Vulnerability, AssetInventory, Remediation, Compliance, SecurityProgress }
public enum ReportFormat { Json, Csv, Html, Pdf }

public sealed class Asset
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public AssetKind Kind { get; set; }
    public string Address { get; set; } = "";
    public string OperatingSystem { get; set; } = "Unknown";
    public string Owner { get; set; } = "Unassigned";
    public string Environment { get; set; } = "";
    public int BusinessCriticality { get; set; } = 3;
    public double Exposure { get; set; }
    public bool IsCritical => BusinessCriticality >= 4;
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
    public Dictionary<string, string> Properties { get; set; } = [];
}

public sealed class Finding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string RootCauseKey { get; set; } = "";
    public Severity Severity { get; set; }
    public SecurityCategory Category { get; set; }
    public FindingStatus Status { get; set; }
    public double Cvss { get; set; }
    public string? Cve { get; set; }
    public string Software { get; set; } = "";
    public string Version { get; set; } = "";
    public double Exploitability { get; set; }
    public double Confidence { get; set; } = 1;
    public double PrivilegeImpact { get; set; }
    public double IdentityReach { get; set; }
    public double CompensatingControl { get; set; }
    public List<string> AssetIds { get; set; } = [];
    public List<string> EvidenceIds { get; set; } = [];
    public List<string> ControlIds { get; set; } = [];
    public List<string> References { get; set; } = [];
    public string Remediation { get; set; } = "";
    public string Verification { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FixedAt { get; set; }
    public DateTimeOffset? AcceptedUntil { get; set; }
    public string DispositionReason { get; set; } = "";
}

public sealed class Identity
{
    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PrincipalName { get; set; } = "";
    public string Provider { get; set; } = "";
    public bool IsPrivileged { get; set; }
    public bool? MfaEnabled { get; set; }
    public DateTimeOffset? LastSignIn { get; set; }
    public List<string> Groups { get; set; } = [];
    public List<string> Permissions { get; set; } = [];
}

public sealed class EvidenceNode
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    public EvidenceKind Kind { get; set; }
    public string Source { get; set; } = "";
    public double Confidence { get; set; } = 1;
    public DateTimeOffset ObservedAt { get; set; } = DateTimeOffset.UtcNow;
    public Dictionary<string, string> Properties { get; set; } = [];
}

public sealed class EvidenceEdge
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SourceId { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string Relationship { get; set; } = "";
    public bool EnablesPath { get; set; }
    public double Confidence { get; set; } = 1;
    public List<string> FindingIds { get; set; } = [];
    public string DefensiveBreak { get; set; } = "";
}

public sealed class Observation
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string AssetId { get; set; } = "";
    public string EngineId { get; set; } = "";
    public string Property { get; set; } = "";
    public string Value { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset ObservedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ChangeEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;
    public string Kind { get; set; } = "";
    public string Summary { get; set; } = "";
    public string EntityId { get; set; } = "";
    public string Source { get; set; } = "";
}

public sealed class ScanRun
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string EngineId { get; set; } = "";
    public string ScopeSummary { get; set; } = "";
    public ScanStatus Status { get; set; }
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedAt { get; set; }
    public string EventId { get; set; } = "";
    public string Message { get; set; } = "";
}

public sealed class CertificateRecord
{
    public string Id { get; set; } = "";
    public string AssetId { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public DateTimeOffset NotAfter { get; set; }
    public string Thumbprint { get; set; } = "";
}

public sealed class ScoreHistory
{
    public DateTimeOffset At { get; set; }
    public double Score { get; set; }
    public string Source { get; set; } = "";
}

public sealed class IncidentRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = "";
    public string Owner { get; set; } = "Unassigned";
    public string Status { get; set; } = "Open";
    public List<string> FindingIds { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<ChangeEvent> Notes { get; set; } = [];
}

public sealed class EnvironmentSnapshot
{
    public int SchemaVersion { get; set; } = 1;
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public EnvironmentMode Mode { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<Asset> Assets { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public List<Identity> Identities { get; set; } = [];
    public List<EvidenceNode> Nodes { get; set; } = [];
    public List<EvidenceEdge> Edges { get; set; } = [];
    public List<Observation> Observations { get; set; } = [];
    public List<ChangeEvent> Changes { get; set; } = [];
    public List<ScanRun> Scans { get; set; } = [];
    public List<CertificateRecord> Certificates { get; set; } = [];
    public List<ScoreHistory> ScoreHistory { get; set; } = [];
    public List<IncidentRecord> Incidents { get; set; } = [];
}

public sealed record ScoredFinding(Finding Finding, double Risk, IReadOnlyList<string> Reasons);
public sealed record RiskAssessment(double GlobalScore, double TotalRisk, IReadOnlyDictionary<SecurityCategory, double> CategoryScores, IReadOnlyList<ScoredFinding> RankedFindings, DateTimeOffset CalculatedAt);
public sealed record AttackPath(string Id, string Title, IReadOnlyList<string> NodeIds, IReadOnlyList<string> EdgeIds, IReadOnlyList<string> FindingIds, string CriticalAssetId, double Risk, double Confidence, string BreakPoint, string RecommendedAction);
public sealed record RemediationAction(string Id, string Title, string Why, IReadOnlyList<string> FindingIds, IReadOnlyList<string> AssetIds, IReadOnlyList<string> EvidenceIds, double ModeledRiskReduction, double Confidence, string Instructions, string Verification);
public sealed record ComplianceControl(string Id, string Framework, string Title, string Description);
public sealed record ComplianceResult(ComplianceControl Control, string Status, IReadOnlyList<string> FindingIds);
public sealed record EngineDescriptor(string Id, string Name, string Description, bool IsAvailable, string AvailabilityReason);
public sealed record ConnectorDescriptor(string Id, string Name, string Status, IReadOnlyList<string> RequiredPermissions, string DocumentationUrl);
public sealed record EngineResult(IReadOnlyList<Asset> Assets, IReadOnlyList<Finding> Findings, IReadOnlyList<EvidenceNode> Nodes, IReadOnlyList<EvidenceEdge> Edges, IReadOnlyList<Observation> Observations, IReadOnlyList<CertificateRecord> Certificates, IReadOnlyList<string> Messages);
public sealed class ScanScope
{
    public bool AuthorizationConfirmed { get; set; }
    public string AuthorizedBy { get; set; } = "";
    public DateTimeOffset AuthorizedAt { get; set; }
    public List<string> Hosts { get; set; } = [];
    public List<string> WebUrls { get; set; } = [];
    public List<int> Ports { get; set; } = [22, 80, 443, 3389];
    public bool IncludeLocalEndpoint { get; set; }
    public int TimeoutSeconds { get; set; } = 5;
    public int MaxConcurrency { get; set; } = 8;
}
public sealed record ScanContext(ScanScope Scope, IProgress<string>? Progress = null);
public sealed class AppSettings
{
    public string Theme { get; set; } = "System";
    public EnvironmentMode? LastEnvironment { get; set; }
    public int RetentionDays { get; set; } = 90;
    public bool AiEnabled { get; set; }
    public string AiProvider { get; set; } = "";
    public string AiModel { get; set; } = "";
    public string AiEndpoint { get; set; } = "";
}
public sealed record AuditEntry(DateTimeOffset At, string Action, string EntityId, string Detail, string EventId);
public sealed record ReportArtifact(string Path, ReportKind Kind, ReportFormat Format, DateTimeOffset CreatedAt);
public sealed record AnalystAnswer(string Answer, IReadOnlyList<string> EvidenceIds, IReadOnlyList<string> Inferences, bool UsedAi);
public sealed record UserError(string Message, string TechnicalDetails, string EventId, bool CanRetry);
