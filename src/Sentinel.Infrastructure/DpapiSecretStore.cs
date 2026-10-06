using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Infrastructure;

/// <summary>Windows current-user DPAPI secret storage. There is deliberately no plaintext or cross-platform fallback.</summary>
public sealed class DpapiSecretStore : ISecretStore
{
    private static readonly byte[] Magic = "SNTLSEC1"u8.ToArray();
    private readonly string _directory;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DpapiSecretStore(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = Path.GetFullPath(directory);
    }

    public async Task SetAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw UnsupportedPlatform();
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        if (Encoding.UTF8.GetByteCount(value) > 1024 * 1024)
            throw new ArgumentException("Secret values must be no larger than one megabyte.", nameof(value));
        cancellationToken.ThrowIfCancellationRequested();
        var plaintext = Encoding.UTF8.GetBytes(value);
        byte[] protectedBytes;
        try { protectedBytes = Protect(plaintext, Entropy(key)); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? temporaryPath = null;
        try
        {
            Directory.CreateDirectory(_directory);
            var path = SecretPath(key);
            temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(Magic, cancellationToken).ConfigureAwait(false);
                await stream.WriteAsync(protectedBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, path, overwrite: true);
            temporaryPath = null;
        }
        finally
        {
            if (temporaryPath is not null) TryDelete(temporaryPath);
            CryptographicOperations.ZeroMemory(protectedBytes);
            _gate.Release();
        }
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw UnsupportedPlatform();
        ValidateKey(key);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var path = SecretPath(key);
            if (!File.Exists(path)) return null;
            var fileInfo = new FileInfo(path);
            if (fileInfo.Length < Magic.Length || fileInfo.Length > 2 * 1024 * 1024)
                throw new InvalidDataException("The encrypted secret file is invalid. Configure this credential again.");
            var encrypted = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            try
            {
                if (!encrypted.AsSpan(0, Magic.Length).SequenceEqual(Magic))
                    throw new InvalidDataException("This secret format is not supported. Configure this credential again.");
                var plaintext = Unprotect(encrypted.AsSpan(Magic.Length).ToArray(), Entropy(key));
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return new UTF8Encoding(false, true).GetString(plaintext);
                }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }
            finally { CryptographicOperations.ZeroMemory(encrypted); }
        }
        finally { _gate.Release(); }
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw UnsupportedPlatform();
        ValidateKey(key);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { cancellationToken.ThrowIfCancellationRequested(); File.Delete(SecretPath(key)); }
        finally { _gate.Release(); }
    }

    private string SecretPath(string key) => Path.Combine(_directory, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".dpapi");
    private static byte[] Entropy(string key) => SHA256.HashData(Encoding.UTF8.GetBytes("SENTINEL Enterprise secret v1:" + key));
    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (key.Length > 512) throw new ArgumentException("Secret identifiers must be no longer than 512 characters.", nameof(key));
    }

    private static PlatformNotSupportedException UnsupportedPlatform() => new("SENTINEL credentials require Windows user-bound DPAPI encryption. Secrets cannot be stored on this operating system.");

    [SupportedOSPlatform("windows")]
    private static byte[] Protect(byte[] plaintext, byte[] entropy) => ProtectedData.Protect(plaintext, entropy, DataProtectionScope.CurrentUser);

    [SupportedOSPlatform("windows")]
    private static byte[] Unprotect(byte[] ciphertext, byte[] entropy) => ProtectedData.Unprotect(ciphertext, entropy, DataProtectionScope.CurrentUser);

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { /* A leftover file contains only DPAPI-protected bytes. */ }
        catch (UnauthorizedAccessException) { /* A leftover file contains only DPAPI-protected bytes. */ }
    }
}
