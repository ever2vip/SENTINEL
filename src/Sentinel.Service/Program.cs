using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sentinel.Service;

var dataRootArgument = Array.IndexOf(args, "--data-root");
var dataRoot = dataRootArgument >= 0 && dataRootArgument + 1 < args.Length
    ? Path.GetFullPath(args[dataRootArgument + 1])
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

if (args.Contains("--health-once", StringComparer.Ordinal))
{
    var store = new MaintenanceStore(dataRoot);
    await store.WriteHealthAsync("healthy", "Maintenance self-check completed.", CancellationToken.None);
    await store.AppendAuditAsync("maintenance.self-check", "Maintenance self-check completed.", CancellationToken.None);
    return;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "SentinelMaintenance");
builder.Services.AddSingleton(new MaintenanceStore(dataRoot));
builder.Services.AddHostedService<MaintenanceWorker>();
await builder.Build().RunAsync();
