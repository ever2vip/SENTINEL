using Microsoft.Data.Sqlite;
using Sentinel.Core;

namespace Sentinel.Tests;

internal sealed class TestRunner
{
    private readonly List<string> _failures = [];
    private int _passed;
    private int _skipped;
    public async Task Check(string name, Func<Task> action)
    {
        try { await action(); _passed++; Console.WriteLine($"PASS {name}"); }
        catch (Exception exception) { _failures.Add($"{name}: {exception.GetType().Name}: {exception.Message}"); Console.WriteLine($"FAIL {_failures[^1]}"); }
    }
    public Task Check(string name, Action action) => Check(name, () => { action(); return Task.CompletedTask; });
    public void Skip(string name, string reason) { _skipped++; Console.WriteLine($"SKIP {name}: {reason}"); }
    public int Finish()
    {
        Console.WriteLine($"SENTINEL automated QA: {_passed} passed, {_failures.Count} failed, {_skipped} skipped.");
        foreach (var failure in _failures) Console.Error.WriteLine(failure);
        return _failures.Count == 0 ? 0 : 1;
    }
    public static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    public static void Equal<T>(T expected, T actual, string message) where T : notnull => Assert(EqualityComparer<T>.Default.Equals(expected, actual), $"{message}: expected {expected}, actual {actual}.");
    public static async Task Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    public static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    public static ScanScope AuthorizedScope() => new()
    {
        AuthorizationConfirmed = true, AuthorizedBy = "SENTINEL QA operator", AuthorizedAt = DateTimeOffset.UtcNow,
        TimeoutSeconds = 2, MaxConcurrency = 2
    };
}

internal sealed class TemporaryDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel-qa-" + Guid.NewGuid().ToString("N"));
    public TemporaryDirectory() => Directory.CreateDirectory(Path);
    public string File(string name) => System.IO.Path.Combine(Path, name);
    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
    }
}
