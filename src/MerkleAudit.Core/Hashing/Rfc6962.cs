using System.Buffers;
using System.Security.Cryptography;

namespace MerkleAudit.Core.Hashing;

/// <summary>
/// RFC 6962 section 2.1 Merkle Tree Hash primitives over SHA-256.
/// The one-byte prefixes are domain separation: without them an interior node (64 bytes of child hashes) could be
/// presented as a leaf, and a second tree with the same root could be forged (a second-preimage attack).
/// </summary>
public static class Rfc6962
{
    /// <summary>Prefix of a leaf hash input: <c>SHA-256(0x00 || leaf)</c>.</summary>
    public const byte LeafPrefix = 0x00;

    /// <summary>Prefix of an interior node hash input: <c>SHA-256(0x01 || left || right)</c>.</summary>
    public const byte NodePrefix = 0x01;

    /// <summary>Length of every hash in bytes.</summary>
    public const int HashSize = SHA256.HashSizeInBytes;

    private static readonly byte[] EmptyRootBytes = SHA256.HashData(ReadOnlySpan<byte>.Empty);

    /// <summary>MTH({}) = SHA-256() — the hash of the empty tree.</summary>
    public static byte[] EmptyRoot() => (byte[])EmptyRootBytes.Clone();

    /// <summary>MTH({d}) = SHA-256(0x00 || d).</summary>
    public static byte[] HashLeaf(ReadOnlySpan<byte> leafInput)
    {
        var length = leafInput.Length + 1;
        byte[]? rented = null;
        var buffer = length <= 512 ? stackalloc byte[length] : (rented = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
        try
        {
            buffer[0] = LeafPrefix;
            leafInput.CopyTo(buffer[1..]);
            return SHA256.HashData(buffer);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>SHA-256(0x01 || left || right).</summary>
    public static byte[] HashChildren(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != HashSize || right.Length != HashSize)
        {
            throw new ArgumentException($"Child hashes must be {HashSize} bytes.");
        }

        Span<byte> buffer = stackalloc byte[1 + (2 * HashSize)];
        buffer[0] = NodePrefix;
        left.CopyTo(buffer[1..]);
        right.CopyTo(buffer[(1 + HashSize)..]);
        return SHA256.HashData(buffer);
    }
}
