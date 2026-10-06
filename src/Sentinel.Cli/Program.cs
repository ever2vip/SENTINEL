using System.Text.Json;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Infrastructure;

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
if (args.Length == 0 || args[0] is "help" or "--help")
{
    Console.WriteLine("""
        SENTINEL Enterprise 1.0 — evidence-based defensive assessment
        demo   [--data DIRECTORY]                         Create or open the offline demo
        status [--environment live|demo] [--data DIRECTORY]
        report --kind Executive|Technical|Vulnerability|AssetInventory|Remediation|Compliance|SecurityProgress
               --format Pdf|Html|Json|Csv --out FILE [--environment live|demo]
        scan   --engine network|endpoint|web|email --operator NAME --confirm-authorized
               [--host EXACT_HOST ...] [--url EXACT_URL ...] [--ports 22,80,443,3389] [--local]
        import --file FILE --source azure|m365|aws|gcp|ad|vulnerability-intel --organization EXACT_ID
               --operator NAME --confirm-authorized
        Scan and import always use the live workspace. Ctrl+C cancels safely.
        No command connects to a network unless scan is explicitly requested with authorized scope.
        """);
    return 0;
}

try
{
    var options = Parse(args.Skip(1).ToArray());
    var dataRoot = One(options, "data") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");
    using var repository = new SQLiteEnvironmentRepository(Path.Combine(dataRoot, "sentinel.db"));
    IAssessmentEngine[] engines = [new NetworkPostureEngine(), new LocalEndpointEngine(), new WebPostureEngine(), new EmailPostureEngine()];
    var coordinator = new ApplicationCoordinator(repository, engines);
    await coordinator.InitializeAsync(cancellation.Token);
    var mode = args[0] is "scan" or "import" ? EnvironmentMode.Live : ParseMode(One(options, "environment") ?? "demo");
    await coordinator.OpenAsync(mode, cancellation.Token);
    switch (args[0])
    {
        case "demo":
            if (mode != EnvironmentMode.Demo) throw new ArgumentException("The demo command requires the demo environment.");
            PrintStatus(coordinator);
            break;
        case "status": PrintStatus(coordinator); break;
        case "report":
            var kind = Enum.Parse<ReportKind>(Required(options, "kind"), true);
            var format = Enum.Parse<ReportFormat>(Required(options, "format"), true);
            var artifact = await coordinator.ExportReportAsync(kind, format, Required(options, "out"), cancellation.Token);
            Console.WriteLine($"Created {artifact.Kind} {artifact.Format} report: {artifact.Path}");
            break;
        case "scan":
            var scope = new ScanScope
            {
                AuthorizationConfirmed = options.ContainsKey("confirm-authorized"),
                AuthorizedBy = Required(options, "operator"),
                AuthorizedAt = DateTimeOffset.UtcNow,
                Hosts = options.GetValueOrDefault("host") ?? [],
                WebUrls = options.GetValueOrDefault("url") ?? [],
                IncludeLocalEndpoint = options.ContainsKey("local"),
                Ports = (One(options, "ports") ?? "22,80,443,3389").Split(',').Select(int.Parse).ToList(),
                TimeoutSeconds = 5,
                MaxConcurrency = 8
            };
            ScopeGuard.Validate(scope);
            await coordinator.RunScanAsync(Required(options, "engine"), scope, new Progress<string>(Console.WriteLine), cancellation.Token);
            PrintStatus(coordinator);
            break;
        case "import":
            var authorization = new EvidenceImportAuthorization
            {
                AuthorizationConfirmed = options.ContainsKey("confirm-authorized"),
                AuthorizedBy = Required(options, "operator"),
                AuthorizedAt = DateTimeOffset.UtcNow,
                SourceId = Required(options, "source"),
                OrganizationId = Required(options, "organization")
            };
            await using (var stream = File.OpenRead(Required(options, "file")))
            {
                var imported = await new ExportedEvidenceImporter().ImportAsync(stream, authorization, cancellation.Token);
                await coordinator.ImportAsync(imported.Result, "import:" + imported.SourceId, imported.Identities, cancellation.Token);
                Console.WriteLine($"Validated export SHA-256: {imported.Sha256}");
            }
            PrintStatus(coordinator);
            break;
        default: throw new ArgumentException("Unknown command. Use --help for supported commands.");
    }
    return 0;
}
catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled safely. No partial scan evidence was committed."); return 130; }
catch (Exception exception)
{
    var error = ErrorTranslator.FromException(exception);
    Console.Error.WriteLine($"{error.Message} Event: {error.EventId}");
    Console.Error.WriteLine(error.TechnicalDetails);
    return 1;
}

static void PrintStatus(ApplicationCoordinator coordinator)
{
    var snapshot = coordinator.Current!;
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        product = "SENTINEL Enterprise", version = "1.0.0", environment = snapshot.Name,
        mode = snapshot.Mode.ToString(), synthetic = snapshot.Mode == EnvironmentMode.Demo,
        assets = snapshot.Assets.Count, identities = snapshot.Identities.Count,
        activeFindings = coordinator.Risk.RankedFindings.Count,
        globalScore = coordinator.Risk.CategoryScores.Count == 0 ? (double?)null : coordinator.Risk.GlobalScore,
        scoreMeaning = "Evidence-based heuristic; unassessed categories excluded. This is not a breach probability.",
        totalModeledRisk = coordinator.Risk.TotalRisk,
        defensivePaths = coordinator.AttackPaths.Count, remediationActions = coordinator.Remediations.Count,
        categories = coordinator.Risk.CategoryScores.ToDictionary(x => x.Key.ToString(), x => x.Value)
    }, new JsonSerializerOptions { WriteIndented = true }));
}
static EnvironmentMode ParseMode(string value) => value.ToLowerInvariant() switch { "demo" => EnvironmentMode.Demo, "live" => EnvironmentMode.Live, _ => throw new ArgumentException("Choose live or demo environment.") };
static string? One(Dictionary<string, List<string>> options, string name)
{
    if (!options.TryGetValue(name, out var values)) return null;
    if (values.Count != 1) throw new ArgumentException($"--{name} requires exactly one value.");
    return values[0];
}
static string Required(Dictionary<string, List<string>> options, string name) => One(options, name) ?? throw new ArgumentException($"--{name} is required.");
static Dictionary<string, List<string>> Parse(string[] arguments)
{
    var flags = new HashSet<string>(["confirm-authorized", "local"], StringComparer.Ordinal);
    var supported = new HashSet<string>(["data", "environment", "kind", "format", "out", "engine", "operator", "host", "url", "ports", "file", "source", "organization"], StringComparer.Ordinal);
    var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
    for (var i = 0; i < arguments.Length; i++)
    {
        var argument = arguments[i];
        if (!argument.StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Options must begin with --.");
        var name = argument[2..];
        if (flags.Contains(name)) { result.TryAdd(name, []); continue; }
        if (!supported.Contains(name)) throw new ArgumentException($"Unsupported option --{name}.");
        if (++i >= arguments.Length || arguments[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"--{name} requires a value.");
        if (!result.TryGetValue(name, out var values)) result[name] = values = [];
        values.Add(arguments[i]);
    }
    return result;
}
