using System.Buffers.Binary;
using System.Text;

namespace MerkleAudit.Core.Entries;

/// <summary>
/// One audit record. <paramref name="Payload"/> is JSON text stored byte-for-byte (PostgreSQL <c>text</c>, not
/// <c>jsonb</c>), because jsonb re-orders keys and normalises whitespace, which would change the hash.
/// </summary>
public sealed record AuditEntry(long Seq, DateTimeOffset OccurredAt, string Actor, string Action, string Resource, string Payload)
{
    /// <summary>PostgreSQL <c>timestamptz</c> keeps microseconds; hashing anything finer would not survive a round trip.</summary>
    public static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value) =>
        new(value.UtcTicks - (value.UtcTicks % 10), TimeSpan.Zero);
}

/// <summary>
/// The canonical leaf encoding (format version 1), specified in docs/log-format.md:
/// <code>
/// u8  version = 1
/// i64 seq                       (big-endian)
/// i64 occurred_at, µs since Unix epoch, UTC (big-endian)
/// u32 len || UTF-8 actor
/// u32 len || UTF-8 action
/// u32 len || UTF-8 resource
/// u32 len || UTF-8 payload
/// </code>
/// Length prefixes make the encoding injective (no two entries encode to the same bytes), and the sequence number
/// binds each entry to its position, so moving a row is a change to the leaf, not just to the tree.
/// </summary>
public static class LeafCodec
{
    public const byte FormatVersion = 1;

    public static byte[] Encode(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var utf8 = Encoding.UTF8;
        var actor = utf8.GetByteCount(entry.Actor);
        var action = utf8.GetByteCount(entry.Action);
        var resource = utf8.GetByteCount(entry.Resource);
        var payload = utf8.GetByteCount(entry.Payload);
        var buffer = new byte[1 + 8 + 8 + 16 + actor + action + resource + payload];
        var span = buffer.AsSpan();
        span[0] = FormatVersion;
        BinaryPrimitives.WriteInt64BigEndian(span[1..], entry.Seq);
        BinaryPrimitives.WriteInt64BigEndian(span[9..], ToUnixMicroseconds(entry.OccurredAt));
        var offset = 17;
        offset = WriteString(span, offset, entry.Actor, actor);
        offset = WriteString(span, offset, entry.Action, action);
        offset = WriteString(span, offset, entry.Resource, resource);
        WriteString(span, offset, entry.Payload, payload);
        return buffer;
    }

    public static byte[] LeafHash(AuditEntry entry) => Hashing.Rfc6962.HashLeaf(Encode(entry));

    public static long ToUnixMicroseconds(DateTimeOffset value) => (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    private static int WriteString(Span<byte> span, int offset, string value, int byteCount)
    {
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)byteCount);
        Encoding.UTF8.GetBytes(value, span[(offset + 4)..]);
        return offset + 4 + byteCount;
    }
}
