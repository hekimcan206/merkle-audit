using System.Buffers.Binary;
using System.Text;

namespace MerkleAudit.Verifier;

/// <summary>An audit entry as the log serves it. <paramref name="OccurredAtMicros"/> is µs since the Unix epoch, UTC.</summary>
public sealed record EntryRecord(long Seq, long OccurredAtMicros, string Actor, string Action, string Resource, string Payload)
{
    /// <summary>
    /// Leaf input, format version 1 (docs/log-format.md), implemented independently of the server:
    /// <c>0x01 || i64 seq || i64 µs || (u32 len || utf8) × {actor, action, resource, payload}</c>, big-endian.
    /// </summary>
    public byte[] LeafInput(long? seqOverride = null)
    {
        using var stream = new MemoryStream();
        Span<byte> number = stackalloc byte[8];
        stream.WriteByte(1);
        BinaryPrimitives.WriteInt64BigEndian(number, seqOverride ?? Seq);
        stream.Write(number);
        BinaryPrimitives.WriteInt64BigEndian(number, OccurredAtMicros);
        stream.Write(number);
        foreach (var field in new[] { Actor, Action, Resource, Payload })
        {
            var bytes = Encoding.UTF8.GetBytes(field);
            BinaryPrimitives.WriteUInt32BigEndian(number, (uint)bytes.Length);
            stream.Write(number[..4]);
            stream.Write(bytes);
        }

        return stream.ToArray();
    }

    public byte[] LeafHash(long? seqOverride = null) => Rfc6962Hash.Leaf(LeafInput(seqOverride));
}

/// <summary>A signed tree head as published by the log.</summary>
public sealed record SignedHead(long TreeSize, long TimestampMs, byte[] RootHash, string KeyId, byte[] Signature)
{
    /// <summary>RFC 6962 section 3.5 tree-head signature input: version 0, type 1, u64 timestamp, u64 size, root.</summary>
    public byte[] SignatureInput()
    {
        var buffer = new byte[50];
        buffer[0] = 0;
        buffer[1] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(2), (ulong)TimestampMs);
        BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10), (ulong)TreeSize);
        RootHash.AsSpan(0, Math.Min(32, RootHash.Length)).CopyTo(buffer.AsSpan(18));
        return buffer;
    }

    public override string ToString() => $"STH(size={TreeSize}, root={Hex.Prefix(RootHash)}, key={KeyId[..Math.Min(8, KeyId.Length)]})";
}

public static class Hex
{
    public static string Of(byte[] value) => Convert.ToHexStringLower(value);

    public static string Prefix(byte[] value) => Convert.ToHexStringLower(value)[..Math.Min(12, value.Length * 2)];

    public static byte[] Parse(string value) => Convert.FromHexString(value);
}
