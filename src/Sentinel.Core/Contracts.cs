namespace Sentinel.Core;

public interface IRiskEngine { RiskAssessment Calculate(EnvironmentSnapshot snapshot, DateTimeOffset? now = null); }
public interface IAttackPathEngine { IReadOnlyList<AttackPath> Analyze(EnvironmentSnapshot snapshot); }
public interface IRemediationEngine { IReadOnlyList<RemediationAction> Plan(EnvironmentSnapshot snapshot); }
public interface IComplianceEngine { IReadOnlyList<ComplianceResult> Assess(EnvironmentSnapshot snapshot); }
public interface IDemoLab { EnvironmentSnapshot Create(DateTimeOffset? now = null); }
public interface IAssessmentEngine
{
    EngineDescriptor Descriptor { get; }
    Task<EngineResult> AssessAsync(ScanContext context, CancellationToken cancellationToken);
}
public interface IEnvironmentRepository
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<EnvironmentSnapshot?> LoadAsync(EnvironmentMode mode, CancellationToken cancellationToken = default);
    Task SaveAsync(EnvironmentSnapshot snapshot, CancellationToken cancellationToken = default);
    Task<AppSettings> GetSettingsAsync(CancellationToken cancellationToken = default);
    Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default);
    Task AuditAsync(AuditEntry entry, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(int limit = 100, CancellationToken cancellationToken = default);
    Task ApplyRetentionAsync(int days, CancellationToken cancellationToken = default);
}
public interface ISecretStore
{
    Task SetAsync(string key, string value, CancellationToken cancellationToken = default);
    Task<string?> GetAsync(string key, CancellationToken cancellationToken = default);
    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}
public interface IReportingEngine
{
    Task<ReportArtifact> ExportAsync(EnvironmentSnapshot snapshot, ReportKind kind, ReportFormat format, string path, CancellationToken cancellationToken = default);
}
public interface IEvidenceAnalyst { AnalystAnswer Answer(EnvironmentSnapshot snapshot, string question); }
public interface IAiProvider
{
    string Name { get; }
    Task<AnalystAnswer> AnswerAsync(string question, IReadOnlyList<EvidenceNode> evidence, CancellationToken cancellationToken);
}
public interface IConnector
{
    ConnectorDescriptor Descriptor { get; }
    Task<EngineResult> CollectAsync(ScanContext context, ISecretStore secrets, CancellationToken cancellationToken);
}
