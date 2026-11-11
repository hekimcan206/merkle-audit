using System.Security.Cryptography;

namespace MerkleAudit.Core.TreeHeads;

/// <summary>
/// Signs tree heads with ECDSA P-256 / SHA-256, DER signatures (RFC 3279), the algorithm RFC 6962 logs use.
/// The key id is the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo, like a CT log id: it is derived from the
/// key, so a verifier cannot be told a wrong id for a key it trusts.
/// </summary>
public sealed class TreeHeadSigner : IDisposable
{
    private readonly ECDsa _key;

    public TreeHeadSigner(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeySize != 256)
        {
            throw new ArgumentException("Tree heads are signed with ECDSA P-256.", nameof(key));
        }

        _key = key;
        PublicKeyPem = key.ExportSubjectPublicKeyInfoPem();
        KeyId = ComputeKeyId(key);
    }

    public string KeyId { get; }

    public string PublicKeyPem { get; }

    public static TreeHeadSigner FromPem(string pkcs8Pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pkcs8Pem);
        return new TreeHeadSigner(key);
    }

    public static TreeHeadSigner Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    public static string ComputeKeyId(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
    }

    public string ExportPrivateKeyPem() => _key.ExportPkcs8PrivateKeyPem();

    public SignedTreeHead Sign(TreeHead head)
    {
        ArgumentNullException.ThrowIfNull(head);
        var signature = _key.SignData(head.ToSignatureInput(), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return new SignedTreeHead(head, KeyId, signature);
    }

    public void Dispose() => _key.Dispose();
}
