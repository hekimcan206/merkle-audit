using System.Security.Cryptography;
using MerkleAudit.Core.TreeHeads;
using Microsoft.Extensions.Options;

namespace MerkleAudit.Server.Log;

public sealed class SigningOptions
{
    public const string Section = "Signing";

    /// <summary>PKCS#8 PEM file with the active ECDSA P-256 signing key.</summary>
    public string KeyFile { get; set; } = "";

    /// <summary>Public keys of retired signing keys, listed by <c>GET /api/v1/keys</c> so old heads stay explainable.</summary>
    public string[] RetiredPublicKeyFiles { get; set; } = [];
}

public sealed record PublishedKey(string KeyId, string PublicKeyPem, string Status);

/// <summary>
/// The active signing key plus the public halves of retired ones. Rotation (docs/key-rotation.md) is: generate a new
/// key, distribute its public key to verifiers, point <c>Signing:KeyFile</c> at it, move the old public key to
/// <c>RetiredPublicKeyFiles</c>. Old heads keep verifying because each head names its key id.
/// </summary>
public sealed class SigningKeyRing : IDisposable
{
    public SigningKeyRing(IOptions<SigningOptions> options, IHostEnvironment environment)
    {
        var config = options.Value;
        // Relative paths are relative to the content root, not to wherever the process happened to be started.
        var keyFile = string.IsNullOrWhiteSpace(config.KeyFile) ? "" : Path.Combine(environment.ContentRootPath, config.KeyFile);
        if (keyFile.Length == 0 || !File.Exists(keyFile))
        {
            throw new InvalidOperationException(
                $"Signing:KeyFile '{config.KeyFile}' does not exist. Create one with `--ensure-key <dir>` (see docs/key-rotation.md).");
        }

        Active = TreeHeadSigner.FromPem(File.ReadAllText(keyFile));
        var keys = new List<PublishedKey> { new(Active.KeyId, Active.PublicKeyPem, "active") };
        foreach (var file in config.RetiredPublicKeyFiles)
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(Path.Combine(environment.ContentRootPath, file)));
            keys.Add(new(TreeHeadSigner.ComputeKeyId(key), key.ExportSubjectPublicKeyInfoPem(), "retired"));
        }

        Published = keys;
    }

    public TreeHeadSigner Active { get; }

    public IReadOnlyList<PublishedKey> Published { get; }

    /// <summary>
    /// Creates <c>sth-signing.pem</c> (private, mode 0600) and <c>trusted/&lt;key id&gt;.pub.pem</c> in
    /// <paramref name="directory"/> unless a key already exists. The public key can go to a separate directory, so
    /// verifiers can mount it without ever seeing the private key. Returns the key id.
    /// </summary>
    public static string EnsureKey(string directory, string? trustedDirectory = null)
    {
        Directory.CreateDirectory(directory);
        var privatePath = Path.Combine(directory, "sth-signing.pem");
        if (File.Exists(privatePath))
        {
            using var existing = TreeHeadSigner.FromPem(File.ReadAllText(privatePath));
            return existing.KeyId;
        }

        using var signer = TreeHeadSigner.Generate();
        WritePrivate(privatePath, signer.ExportPrivateKeyPem());
        var trusted = trustedDirectory ?? Path.Combine(directory, "trusted");
        Directory.CreateDirectory(trusted);
        File.WriteAllText(Path.Combine(trusted, $"{signer.KeyId}.pub.pem"), signer.PublicKeyPem);
        return signer.KeyId;
    }

    private static void WritePrivate(string path, string pem)
    {
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, pem);
            return;
        }

        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        using var writer = new StreamWriter(stream);
        writer.Write(pem);
    }

    public void Dispose() => Active.Dispose();
}
