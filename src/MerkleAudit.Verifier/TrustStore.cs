using System.Security.Cryptography;

namespace MerkleAudit.Verifier;

/// <summary>A public key the verifier trusts, optionally retired: heads it signed after <paramref name="NotAfterMs"/> are rejected.</summary>
public sealed record TrustedKey(string KeyId, ECDsa PublicKey, long? NotAfterMs);

/// <summary>
/// The keys an auditor accepts tree heads from. Keys are pinned out of band (a file shipped with the auditor), never
/// fetched from the log being audited: a log that can hand out its own trust anchors can sign anything.
/// Retired keys stay trusted for the heads they signed before retirement, so rotation never invalidates history.
/// </summary>
public sealed class TrustStore : IDisposable
{
    private readonly Dictionary<string, TrustedKey> _keys = new(StringComparer.Ordinal);

    public IReadOnlyCollection<TrustedKey> Keys => _keys.Values;

    public TrustedKey AddPem(string publicKeyPem, long? notAfterMs = null)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        if (key.KeySize != 256)
        {
            key.Dispose();
            throw new CryptographicException("Only ECDSA P-256 tree-head keys are supported.");
        }

        var id = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        var trusted = new TrustedKey(id, key, notAfterMs);
        _keys[id] = trusted;
        return trusted;
    }

    /// <summary>Returns null when the head verifies, otherwise the reason it does not.</summary>
    public string? Check(SignedHead head)
    {
        ArgumentNullException.ThrowIfNull(head);
        if (head.RootHash.Length != Rfc6962Hash.Size || head.TreeSize < 0 || head.TimestampMs < 0)
        {
            return "malformed tree head";
        }

        if (!_keys.TryGetValue(head.KeyId, out var key))
        {
            return $"signed by untrusted key {head.KeyId}";
        }

        if (key.NotAfterMs is { } notAfter && head.TimestampMs > notAfter)
        {
            return "signed by a retired key after its retirement";
        }

        return key.PublicKey.VerifyData(head.SignatureInput(), head.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
            ? null
            : "signature does not verify";
    }

    public void Dispose()
    {
        foreach (var key in _keys.Values)
        {
            key.PublicKey.Dispose();
        }
    }
}
