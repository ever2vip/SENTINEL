using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// This QA-only executable intentionally has no SENTINEL project references.
// Seed and inspect operations use the binaries installed by each real installer,
// so a current source build cannot accidentally stand in for the V1.0 baseline.
try
{
    if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        throw new PlatformNotSupportedException("Upgrade verification requires Windows x64.");
    var arguments = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < args.Length; index += 2)
    {
        if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException("Use --mode seed|inspect --desktop PATH --data PATH --result PATH.");
        arguments.Add(args[index][2..], args[index + 1]);
    }
    var mode = arguments["mode"];
    if (mode is not ("seed" or "inspect")) throw new ArgumentException("Mode must be seed or inspect.");
    var desktopDirectory = Path.GetFullPath(arguments["desktop"]);
    var dataDirectory = Path.GetFullPath(arguments["data"]);
    var resultPath = Path.GetFullPath(arguments["result"]);
    var database = Path.Combine(dataDirectory, "sentinel.db");
    if (mode == "seed" && File.Exists(database))
        throw new InvalidOperationException("Refusing to overwrite existing operator evidence; use a clean disposable VM.");
    if (mode == "inspect" && !File.Exists(database)) throw new FileNotFoundException("Operator evidence is missing.", database);
    var context = new InstalledApplicationContext(desktopDirectory);
    var infrastructure = context.LoadFromAssemblyPath(Path.Combine(desktopDirectory, "Sentinel.Infrastructure.dll"));
    var core = context.LoadFromAssemblyPath(Path.Combine(desktopDirectory, "Sentinel.Core.dll"));
    var repository = Activator.CreateInstance(infrastructure.GetType("Sentinel.Infrastructure.SQLiteEnvironmentRepository", true)!, database)!;
    var demoMode = Enum.Parse(core.GetType("Sentinel.Core.EnvironmentMode", true)!, "Demo");
    var secretStore = Activator.CreateInstance(infrastructure.GetType("Sentinel.Infrastructure.DpapiSecretStore", true)!, Path.Combine(dataDirectory, "secrets"))!;
    const string secretKey = "qa-upgrade-continuity";
    const string syntheticSecret = "SENTINEL synthetic upgrade fixture; not a connector credential";
    try
    {
        await InvokeAsync(repository, "InitializeAsync", CancellationToken.None);
        if (mode == "seed")
        {
            var lab = Activator.CreateInstance(core.GetType("Sentinel.Core.DemoLab", true)!)!;
            var snapshot = lab.GetType().GetMethod("Create")!.Invoke(lab, new object?[] { null })!;
            await InvokeAsync(repository, "SaveAsync", snapshot, CancellationToken.None);
            var preferences = Activator.CreateInstance(core.GetType("Sentinel.Core.AppSettings", true)!)!;
            preferences.GetType().GetProperty("Theme")!.SetValue(preferences, "Light");
            preferences.GetType().GetProperty("RetentionDays")!.SetValue(preferences, 180);
            preferences.GetType().GetProperty("LastEnvironment")!.SetValue(preferences, demoMode);
            await InvokeAsync(repository, "SaveSettingsAsync", preferences, CancellationToken.None);
            await InvokeAsync(secretStore, "SetAsync", secretKey, syntheticSecret, CancellationToken.None);
        }
        var persisted = await InvokeAsync(repository, "LoadAsync", demoMode, CancellationToken.None)
            ?? throw new InvalidDataException("The installed repository could not read Demo Organization.");
        var settings = (await InvokeAsync(repository, "GetSettingsAsync", CancellationToken.None))!;
        var history = (await InvokeAsync(repository, "ReadHistoryAsync", demoMode, 100, CancellationToken.None))!;
        var audit = (await InvokeAsync(repository, "ReadAuditAsync", 100, CancellationToken.None))!;
        var recoveredSecret = await InvokeAsync(secretStore, "GetAsync", secretKey, CancellationToken.None) as string;
        if (recoveredSecret != syntheticSecret) throw new InvalidDataException("The original user-bound DPAPI fixture could not be decrypted.");
        var assetCount = Count(persisted, "Assets");
        var findingCount = Count(persisted, "Findings");
        var nodeCount = Count(persisted, "Nodes");
        if (assetCount < 262 || findingCount == 0 || nodeCount == 0)
            throw new InvalidDataException("The installed repository did not return a complete Demo Organization.");
        string? workflowSha256 = null;
        var hasDesktopWorkflows = infrastructure.GetName().Version is { } installedVersion && installedVersion >= new Version(1, 1);
        if (hasDesktopWorkflows)
        {
            var desktop = context.LoadFromAssemblyPath(Path.Combine(desktopDirectory, "Sentinel.Desktop.dll"));
            var storeType = desktop.GetType("Sentinel.Desktop.DesktopWorkflowStore", true)!;
            var workflowStore = Activator.CreateInstance(storeType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null, args: [dataDirectory], culture: null)!;
            var environmentId = (string)persisted.GetType().GetProperty("Id")!.GetValue(persisted)!;
            await InvokeAsync(workflowStore, "LoadAsync", environmentId, CancellationToken.None);
            if (mode == "seed")
            {
                var remediation = Activator.CreateInstance(core.GetType("Sentinel.Core.RemediationEngine", true)!, new object?[] { null })!;
                var actions = (IEnumerable)remediation.GetType().GetMethod("Plan")!.Invoke(remediation, [persisted])!;
                var action = actions.Cast<object>().First();
                var planType = desktop.GetType("Sentinel.Desktop.RemediationPlan", true)!;
                var plan = planType.GetMethod("FromAction", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [action, persisted])!;
                planType.GetProperty("Status")!.SetValue(plan, "Planned");
                planType.GetProperty("Owner")!.SetValue(plan, "Windows upgrade verification");
                await InvokeAsync(workflowStore, "SavePlanAsync", plan, CancellationToken.None);
                await InvokeAsync(workflowStore, "SetUnderReviewAsync", "finding-log4j", true, "Synthetic upgrade review fixture", CancellationToken.None, environmentId);
            }
            var plans = storeType.GetProperty("Plans", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(workflowStore)!;
            var underReview = (bool)storeType.GetMethod("IsUnderReview", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(workflowStore, ["finding-log4j"])!;
            var workflowFiles = Directory.Exists(Path.Combine(dataDirectory, "Workflows"))
                ? Directory.GetFiles(Path.Combine(dataDirectory, "Workflows"), "*.json") : [];
            if (mode == "seed" && (!underReview || !((IEnumerable)plans).Cast<object>().Any()))
                throw new InvalidDataException("The installed V1.1 workflow fixture was not saved through the real planning store.");
            // V1.0 had no desktop workflows. Its upgrade must remain readable with
            // an empty store; V1.1 continuity is separately asserted by the gate.
            workflowSha256 = Fingerprint(new { plans, underReview });
            if (mode == "inspect" && workflowFiles.Length > 0 && (!underReview || !((IEnumerable)plans).Cast<object>().Any()))
                throw new InvalidDataException("The original V1.1 planning and review fixture is no longer readable.");
        }
        var result = new
        {
            schemaVersion = 1,
            mode,
            desktopDirectory,
            infrastructureVersion = infrastructure.GetName().Version?.ToString(),
            database,
            snapshotSha256 = Fingerprint(persisted),
            settingsSha256 = Fingerprint(settings),
            historySha256 = Fingerprint(history),
            auditSha256 = Fingerprint(audit),
            workflowSha256,
            assetCount,
            findingCount,
            nodeCount,
            dpapiContinuity = true,
            theme = settings.GetType().GetProperty("Theme")!.GetValue(settings),
            retentionDays = settings.GetType().GetProperty("RetentionDays")!.GetValue(settings)
        };
        Directory.CreateDirectory(Path.GetDirectoryName(resultPath)!);
        await File.WriteAllTextAsync(resultPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Installed {result.infrastructureVersion} {mode}: {assetCount} assets, {findingCount} findings, {nodeCount} nodes; DPAPI continuity passed.");
    }
    finally { ((IDisposable)repository).Dispose(); }
    return 0;
}
catch (Exception exception)
{
    var actual = exception is TargetInvocationException invocation ? invocation.InnerException ?? exception : exception;
    Console.Error.WriteLine("Installed application upgrade verification failed: " + actual.Message);
    return 1;
}

static int Count(object source, string property) => ((ICollection)source.GetType().GetProperty(property)!.GetValue(source)!).Count;
static string Fingerprint(object value)
{
    var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 128 };
    options.Converters.Add(new JsonStringEnumConverter());
    return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, value.GetType(), options)))).ToLowerInvariant();
}
static async Task<object?> InvokeAsync(object target, string method, params object?[] arguments)
{
    var task = (Task)target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.Invoke(target, arguments)!;
    await task.ConfigureAwait(false);
    return task.GetType().GetProperty("Result")?.GetValue(task);
}

sealed class InstalledApplicationContext(string directory) : AssemblyLoadContext
{
    protected override Assembly? Load(AssemblyName name)
    {
        // Use the QA process framework; resolve product and third-party libraries
        // strictly from the actual installed application directory.
        if (name.Name is null) return null;
        if (name.Name.StartsWith("System.", StringComparison.Ordinal) || name.Name is "System" or "mscorlib" or "netstandard")
        {
            try { return Default.LoadFromAssemblyName(name); }
            catch (FileNotFoundException) { /* Package-only System assemblies, such as DPAPI, belong to the installed payload. */ }
        }
        var path = Path.Combine(directory, name.Name + ".dll");
        return File.Exists(path) ? LoadFromAssemblyPath(path) : null;
    }
    protected override nint LoadUnmanagedDll(string name)
    {
        var path = Path.Combine(directory, name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? name : name + ".dll");
        return File.Exists(path) ? NativeLibrary.Load(path) : 0;
    }
}
