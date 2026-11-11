using System.Buffers.Binary;
using MerkleAudit.Core.Hashing;

namespace MerkleAudit.Core.TreeHeads;

/// <summary>The log's commitment: "at <paramref name="TimestampMs"/> the tree had this many leaves and this root".</summary>
public sealed record TreeHead(long TreeSize, long TimestampMs, byte[] RootHash)
{
    /// <summary>
    /// The bytes that are signed: RFC 6962 section 3.5 <c>digitally-signed struct</c> for a tree head.
    /// <code>
    /// u8  version          = 0 (v1)
    /// u8  signature_type   = 1 (tree_hash)
    /// u64 timestamp        ms since epoch, big-endian
    /// u64 tree_size        big-endian
    /// u8[32] sha256_root_hash
    /// </code>
    /// </summary>
    public byte[] ToSignatureInput()
    {
        if (RootHash.Length != Rfc6962.HashSize)
        {
            throw new InvalidOperationException("Root hash must be 32 bytes.");
        }

        var buffer = new byte[2 + 8 + 8 + Rfc6962.HashSize];
        buffer[0] = 0;
        buffer[1] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(2), checked((ulong)TimestampMs));
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10), checked((ulong)TreeSize));
        RootHash.CopyTo(buffer, 18);
        return buffer;
    }
}

/// <summary>A tree head plus the id of the key that signed it and a DER-encoded ECDSA P-256 / SHA-256 signature.</summary>
public sealed record SignedTreeHead(TreeHead Head, string KeyId, byte[] Signature);
