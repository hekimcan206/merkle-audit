using System.Security.Cryptography;

namespace MerkleAudit.Verifier;

/// <summary>
/// RFC 6962 hashing, written again here on purpose: the verifier shares no code with the log it checks, so a bug in
/// the server's tree code cannot also hide in the code that is supposed to catch it (see ADR 0003).
/// </summary>
public static class Rfc6962Hash
{
    public const int Size = 32;

    public static byte[] Leaf(ReadOnlySpan<byte> data)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData([0x00]);
        hash.AppendData(data);
        return hash.GetHashAndReset();
    }

    public static byte[] Node(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        Span<byte> buffer = stackalloc byte[65];
        buffer[0] = 0x01;
        left.CopyTo(buffer[1..33]);
        right.CopyTo(buffer[33..]);
        return SHA256.HashData(buffer);
    }

    public static byte[] Empty() => SHA256.HashData([]);
}
