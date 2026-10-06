using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sentinel.Core;

namespace Sentinel.Infrastructure;

/// <summary>Standalone storage. Each save preserves an immutable historical snapshot and updates the current view atomically.</summary>
public sealed class SQLiteEnvironmentRepository : IEnvironmentRepository, IDisposable
{
    private const int DatabaseVersion = 2;
    private readonly string _databasePath;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initializeGate = new(1, 1);
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private bool _initialized;
    private bool _disposed;

    public SQLiteEnvironmentRepository(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _databasePath = Path.GetFullPath(databasePath);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            ForeignKeys = true,
            DefaultTimeout = 15
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_initialized) return;
        await _initializeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_initialized) return;
            var directory = Path.GetDirectoryName(_databasePath)!;
            var createdDirectory = !Directory.Exists(directory);
            Directory.CreateDirectory(directory);
            if (createdDirectory && !OperatingSystem.IsWindows())
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, null, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;", cancellationToken).ConfigureAwait(false);
            var version = Convert.ToInt32(await ScalarAsync(connection, null, "PRAGMA user_version;", cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
            if (version > DatabaseVersion)
                throw new InvalidDataException("This database was created by a newer SENTINEL version. Install that version before opening it.");
            using var transaction = connection.BeginTransaction();
            if (version < 1)
            {
                await ExecuteAsync(connection, transaction, """
                    CREATE TABLE environment_snapshots (
                        mode INTEGER PRIMARY KEY CHECK(mode IN (0,1)),
                        environment_id TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE snapshot_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mode INTEGER NOT NULL CHECK(mode IN (0,1)),
                        environment_id TEXT NOT NULL,
                        saved_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE INDEX idx_snapshot_history_mode_at ON snapshot_history(mode,saved_at);
                    CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
                    CREATE TABLE audit_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        at TEXT NOT NULL,
                        action TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        event_id TEXT NOT NULL
                    );
                    CREATE INDEX idx_audit_at ON audit_entries(at);
                    PRAGMA user_version=1;
                    """, cancellationToken).ConfigureAwait(false);
            }
            if (version < 2)
            {
                // Projections keep the graph navigable in SQLite without requiring a graph server.
                await ExecuteAsync(connection, transaction, """
                    CREATE TABLE evidence_nodes (
                        mode INTEGER NOT NULL,
                        node_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        label TEXT NOT NULL,
                        source TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY(mode,node_id),
                        FOREIGN KEY(mode) REFERENCES environment_snapshots(mode) ON DELETE CASCADE
                    );
                    CREATE TABLE evidence_edges (
                        mode INTEGER NOT NULL,
                        edge_id TEXT NOT NULL,
                        source_id TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        relationship TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY(mode,edge_id),
                        FOREIGN KEY(mode) REFERENCES environment_snapshots(mode) ON DELETE CASCADE
                    );
                    CREATE INDEX idx_evidence_edges_source ON evidence_edges(mode,source_id);
                    CREATE INDEX idx_evidence_edges_target ON evidence_edges(mode,target_id);
                    PRAGMA user_version=2;
                    """, cancellationToken).ConfigureAwait(false);
                // Backfill projections when upgrading an existing version-one database.
                var stored = new List<(EnvironmentMode Mode, string Json)>();
                await using (var command = connection.CreateCommand())
                {
                    command.Transaction = transaction;
                    command.CommandText = "SELECT mode,payload FROM environment_snapshots;";
                    await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                    while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                        stored.Add(((EnvironmentMode)reader.GetInt32(0), reader.GetString(1)));
                }
                foreach (var row in stored)
                {
                    var snapshot = DeserializeSnapshot(row.Json, row.Mode);
                    await SaveGraphAsync(connection, transaction, snapshot, cancellationToken).ConfigureAwait(false);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            if (!OperatingSystem.IsWindows())
                foreach (var file in new[] { _databasePath, _databasePath + "-wal", _databasePath + "-shm" })
                    if (File.Exists(file)) File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            _initialized = true;
        }
        finally { _initializeGate.Release(); }
    }

    public async Task<EnvironmentSnapshot?> LoadAsync(EnvironmentMode mode, CancellationToken cancellationToken = default)
    {
        ValidateMode(mode);
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM environment_snapshots WHERE mode=$mode;";
            command.Parameters.AddWithValue("$mode", (int)mode);
            var payload = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            return payload is null ? null : DeserializeSnapshot(payload, mode);
        }
        finally { _operationGate.Release(); }
    }

    public async Task SaveAsync(EnvironmentSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateSnapshot(snapshot);
        var payload = JsonSerializer.Serialize(snapshot, StorageJson.Options);
        // The caller may continue editing its view while this operation awaits I/O.
        snapshot = DeserializeSnapshot(payload, snapshot.Mode);
        cancellationToken.ThrowIfCancellationRequested();
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction();
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO environment_snapshots(mode,environment_id,updated_at,payload)
                    VALUES($mode,$id,$at,$payload)
                    ON CONFLICT(mode) DO UPDATE SET environment_id=excluded.environment_id,updated_at=excluded.updated_at,payload=excluded.payload;
                    INSERT INTO snapshot_history(mode,environment_id,saved_at,payload) VALUES($mode,$id,$saved,$payload);
                    """;
                command.Parameters.AddWithValue("$mode", (int)snapshot.Mode);
                command.Parameters.AddWithValue("$id", snapshot.Id);
                command.Parameters.AddWithValue("$at", Timestamp(snapshot.UpdatedAt));
                command.Parameters.AddWithValue("$saved", Timestamp(DateTimeOffset.UtcNow));
                command.Parameters.AddWithValue("$payload", payload);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await SaveGraphAsync(connection, transaction, snapshot, cancellationToken).ConfigureAwait(false);
            await InsertAuditAsync(connection, transaction, new AuditEntry(DateTimeOffset.UtcNow, "environment.saved", snapshot.Id,
                $"{snapshot.Mode}: {snapshot.Assets.Count} assets, {snapshot.Findings.Count} findings, {snapshot.Nodes.Count} evidence nodes.", Guid.NewGuid().ToString("N")), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally { _operationGate.Release(); }
    }

    public async Task<AppSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            var json = await ScalarAsync(connection, null, "SELECT payload FROM settings WHERE id=1;", cancellationToken).ConfigureAwait(false) as string;
            if (json is null) return new AppSettings();
            var settings = JsonSerializer.Deserialize<AppSettings>(json, StorageJson.Options)
                ?? throw new InvalidDataException("Saved SENTINEL settings are invalid.");
            ValidateSettings(settings);
            return settings;
        }
        finally { _operationGate.Release(); }
    }

    public async Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ValidateSettings(settings);
        var payload = JsonSerializer.Serialize(settings, StorageJson.Options);
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction();
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO settings(id,payload) VALUES(1,$payload) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload;";
            command.Parameters.AddWithValue("$payload", payload);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await InsertAuditAsync(connection, transaction, new AuditEntry(DateTimeOffset.UtcNow, "settings.saved", "settings", "Preferences updated. Credentials are held separately in the Windows secret store.", Guid.NewGuid().ToString("N")), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
        finally { _operationGate.Release(); }
    }

    public async Task AuditAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentException.ThrowIfNullOrWhiteSpace(entry.Action);
        ArgumentException.ThrowIfNullOrWhiteSpace(entry.EventId);
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await InsertAuditAsync(connection, null, entry, cancellationToken).ConfigureAwait(false);
        }
        finally { _operationGate.Release(); }
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadAuditAsync(int limit = 100, CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 10_000) throw new ArgumentOutOfRangeException(nameof(limit), "Choose an audit limit between 1 and 10,000.");
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT at,action,entity_id,detail,event_id FROM audit_entries ORDER BY at DESC,id DESC LIMIT $limit;";
            command.Parameters.AddWithValue("$limit", limit);
            var entries = new List<AuditEntry>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                entries.Add(new AuditEntry(DateTimeOffset.Parse(reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)));
            return entries;
        }
        finally { _operationGate.Release(); }
    }

    /// <summary>Remove expired history and events; retain current inventory and unresolved findings.</summary>
    public async Task ApplyRetentionAsync(int days, CancellationToken cancellationToken = default)
    {
        if (days is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(days), "Retention must be between 1 and 3,650 days.");
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            using var transaction = connection.BeginTransaction();
            var snapshots = new List<EnvironmentSnapshot>();
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "SELECT mode,payload FROM environment_snapshots;";
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    snapshots.Add(DeserializeSnapshot(reader.GetString(1), (EnvironmentMode)reader.GetInt32(0)));
            }
            foreach (var snapshot in snapshots)
            {
                snapshot.Changes.RemoveAll(x => x.At < cutoff);
                snapshot.Scans.RemoveAll(x => x.Status != ScanStatus.Running && (x.FinishedAt ?? x.StartedAt) < cutoff);
                snapshot.ScoreHistory.RemoveAll(x => x.At < cutoff);
                snapshot.Observations.RemoveAll(x => x.ObservedAt < cutoff);
                var incidentFindingIds = snapshot.Incidents.SelectMany(x => x.FindingIds).ToHashSet(StringComparer.Ordinal);
                snapshot.Findings.RemoveAll(x => x.Status == FindingStatus.Fixed && (x.FixedAt ?? x.LastSeen) < cutoff && !incidentFindingIds.Contains(x.Id));
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = "UPDATE environment_snapshots SET payload=$payload WHERE mode=$mode;";
                command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(snapshot, StorageJson.Options));
                command.Parameters.AddWithValue("$mode", (int)snapshot.Mode);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "DELETE FROM snapshot_history WHERE saved_at < $cutoff; DELETE FROM audit_entries WHERE at < $cutoff;";
                command.Parameters.AddWithValue("$cutoff", Timestamp(cutoff));
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await InsertAuditAsync(connection, transaction, new AuditEntry(DateTimeOffset.UtcNow, "retention.applied", "storage",
                $"Retained {days} days of scan, observation, score, change, resolved finding and audit history. Current assets and unresolved evidence retained.", Guid.NewGuid().ToString("N")), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            // Remove deleted bytes from free pages; WAL is truncated without rewriting active snapshots.
            await ExecuteAsync(connection, null, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken).ConfigureAwait(false);
        }
        finally { _operationGate.Release(); }
    }

    public async Task<IReadOnlyList<EnvironmentSnapshot>> ReadHistoryAsync(EnvironmentMode mode, int limit = 100, CancellationToken cancellationToken = default)
    {
        ValidateMode(mode);
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM snapshot_history WHERE mode=$mode ORDER BY id DESC LIMIT $limit;";
            command.Parameters.AddWithValue("$mode", (int)mode);
            command.Parameters.AddWithValue("$limit", limit);
            var snapshots = new List<EnvironmentSnapshot>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) snapshots.Add(DeserializeSnapshot(reader.GetString(0), mode));
            return snapshots;
        }
        finally { _operationGate.Release(); }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, null, "PRAGMA busy_timeout=15000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;", cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
    }

    private static async Task SaveGraphAsync(SqliteConnection connection, SqliteTransaction transaction, EnvironmentSnapshot snapshot, CancellationToken cancellationToken)
    {
        await using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM evidence_edges WHERE mode=$mode; DELETE FROM evidence_nodes WHERE mode=$mode;";
            clear.Parameters.AddWithValue("$mode", (int)snapshot.Mode);
            await clear.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        foreach (var node in snapshot.Nodes)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO evidence_nodes(mode,node_id,kind,label,source,observed_at,confidence,payload) VALUES($mode,$id,$kind,$label,$source,$at,$confidence,$payload);";
            command.Parameters.AddWithValue("$mode", (int)snapshot.Mode);
            command.Parameters.AddWithValue("$id", node.Id);
            command.Parameters.AddWithValue("$kind", node.Kind.ToString());
            command.Parameters.AddWithValue("$label", node.Label);
            command.Parameters.AddWithValue("$source", node.Source);
            command.Parameters.AddWithValue("$at", Timestamp(node.ObservedAt));
            command.Parameters.AddWithValue("$confidence", node.Confidence);
            command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(node, StorageJson.Options));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        foreach (var edge in snapshot.Edges)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO evidence_edges(mode,edge_id,source_id,target_id,relationship,payload) VALUES($mode,$id,$source,$target,$relationship,$payload);";
            command.Parameters.AddWithValue("$mode", (int)snapshot.Mode);
            command.Parameters.AddWithValue("$id", edge.Id);
            command.Parameters.AddWithValue("$source", edge.SourceId);
            command.Parameters.AddWithValue("$target", edge.TargetId);
            command.Parameters.AddWithValue("$relationship", edge.Relationship);
            command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(edge, StorageJson.Options));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task InsertAuditAsync(SqliteConnection connection, SqliteTransaction? transaction, AuditEntry entry, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO audit_entries(at,action,entity_id,detail,event_id) VALUES($at,$action,$entity,$detail,$event);";
        command.Parameters.AddWithValue("$at", Timestamp(entry.At));
        command.Parameters.AddWithValue("$action", entry.Action);
        command.Parameters.AddWithValue("$entity", entry.EntityId);
        command.Parameters.AddWithValue("$detail", entry.Detail);
        command.Parameters.AddWithValue("$event", entry.EventId);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static EnvironmentSnapshot DeserializeSnapshot(string json, EnvironmentMode expectedMode)
    {
        EnvironmentSnapshot snapshot;
        try
        {
            snapshot = JsonSerializer.Deserialize<EnvironmentSnapshot>(json, StorageJson.Options)
                ?? throw new InvalidDataException("The saved environment snapshot is invalid.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The saved environment snapshot is malformed and cannot be opened. Restore a verified backup or create a new environment.", exception);
        }
        ValidateSnapshot(snapshot);
        if (snapshot.Mode != expectedMode) throw new InvalidDataException("The environment mode does not match the stored snapshot.");
        return snapshot;
    }

    private static void ValidateSnapshot(EnvironmentSnapshot snapshot)
    {
        ValidateMode(snapshot.Mode);
        if (snapshot.SchemaVersion != 1) throw new InvalidDataException("The environment snapshot schema is not supported by this SENTINEL version.");
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshot.Id);
        if (snapshot.Assets is null || snapshot.Findings is null || snapshot.Nodes is null || snapshot.Edges is null || snapshot.Identities is null || snapshot.Observations is null || snapshot.Changes is null || snapshot.Scans is null || snapshot.Certificates is null || snapshot.ScoreHistory is null || snapshot.Incidents is null)
            throw new InvalidDataException("The environment snapshot contains missing collections.");
        if (snapshot.Assets.Any(x => x is null) || snapshot.Findings.Any(x => x is null) || snapshot.Nodes.Any(x => x is null)
            || snapshot.Edges.Any(x => x is null) || snapshot.Identities.Any(x => x is null) || snapshot.Observations.Any(x => x is null)
            || snapshot.Changes.Any(x => x is null) || snapshot.Scans.Any(x => x is null) || snapshot.Certificates.Any(x => x is null)
            || snapshot.ScoreHistory.Any(x => x is null) || snapshot.Incidents.Any(x => x is null))
            throw new InvalidDataException("The environment snapshot contains a missing record.");
        RequireUnique(snapshot.Assets.Select(x => x.Id), "asset");
        RequireUnique(snapshot.Findings.Select(x => x.Id), "finding");
        RequireUnique(snapshot.Nodes.Select(x => x.Id), "evidence node");
        RequireUnique(snapshot.Edges.Select(x => x.Id), "evidence edge");
        RequireUnique(snapshot.Incidents.Select(x => x.Id), "incident");
        var findingIds = snapshot.Findings.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var incident in snapshot.Incidents)
        {
            if (incident.FindingIds is null || incident.Notes is null || string.IsNullOrWhiteSpace(incident.Title) || string.IsNullOrWhiteSpace(incident.Owner))
                throw new InvalidDataException("Each incident requires a title, owner, finding references and notes collection.");
            if (incident.Status is not ("Open" or "Investigating" or "Contained" or "Resolved"))
                throw new InvalidDataException("An incident contains an unsupported workflow status.");
            if (incident.FindingIds.Count == 0 || incident.FindingIds.Any(id => !findingIds.Contains(id)))
                throw new InvalidDataException("An incident references a finding that is not present in this environment.");
            RequireUnique(incident.FindingIds, "incident finding reference");
            if (incident.Notes.Any(note => note is null || note.EntityId != incident.Id))
                throw new InvalidDataException("An incident note references a different incident.");
            RequireUnique(incident.Notes.Select(x => x.Id), "incident note");
        }
        var nodeIds = snapshot.Nodes.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        if (snapshot.Edges.Any(x => !nodeIds.Contains(x.SourceId) || !nodeIds.Contains(x.TargetId)))
            throw new InvalidDataException("An evidence relationship references an unknown node.");
        if (snapshot.Nodes.Any(x => !double.IsFinite(x.Confidence) || x.Confidence is < 0 or > 1)
            || snapshot.Edges.Any(x => !double.IsFinite(x.Confidence) || x.Confidence is < 0 or > 1))
            throw new InvalidDataException("Evidence confidence must be a finite value between zero and one.");
    }

    private static void RequireUnique(IEnumerable<string> ids, string name)
    {
        var known = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in ids)
            if (string.IsNullOrWhiteSpace(id) || !known.Add(id)) throw new InvalidDataException($"Each {name} requires a unique, nonempty identifier.");
    }

    private static void ValidateMode(EnvironmentMode mode)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
    }

    private static void ValidateSettings(AppSettings settings)
    {
        if (settings.Theme is not ("System" or "Dark" or "Light")) throw new ArgumentException("Theme must be System, Dark or Light.", nameof(settings));
        if (settings.RetentionDays is < 1 or > 3650) throw new ArgumentException("Retention must be between 1 and 3,650 days.", nameof(settings));
        if (settings.LastEnvironment.HasValue) ValidateMode(settings.LastEnvironment.Value);
        if (!string.IsNullOrWhiteSpace(settings.AiEndpoint))
        {
            if (!Uri.TryCreate(settings.AiEndpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query))
                throw new ArgumentException("AI endpoint must be an HTTPS URL without embedded credentials or query secrets.", nameof(settings));
        }
    }

    private static string Timestamp(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _initializeGate.Dispose();
        _operationGate.Dispose();
    }
}
