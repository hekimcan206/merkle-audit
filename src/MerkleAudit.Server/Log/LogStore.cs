using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Tree;
using MerkleAudit.Core.TreeHeads;
using Npgsql;
using NpgsqlTypes;

namespace MerkleAudit.Server.Log;

public sealed record NewEntry(string Actor, string Action, string Resource, string Payload);

public sealed record AppendedEntry(long Seq, DateTimeOffset OccurredAt, byte[] LeafHash);

public sealed record TreeState(long TreeSize, byte[] RootHash);

/// <summary>
/// PostgreSQL persistence for the log. Appends are serialised by a row lock on <c>tree_state</c>: the tree is a
/// sequence, so exactly one writer may extend it at a time, across every server instance. Throughput comes from
/// putting many entries in each locked transaction (see <see cref="GroupCommitWriter"/>), not from parallel writers.
/// </summary>
public sealed class LogStore(NpgsqlDataSource dataSource, TimeProvider time, LogMetrics metrics) : INodeSource
{
    public async Task<IReadOnlyList<AppendedEntry>> AppendAsync(IReadOnlyList<NewEntry> batch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Count == 0)
        {
            return [];
        }

        var started = time.GetTimestamp();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken);

        long size;
        await using (var lockCmd = new NpgsqlCommand("SELECT tree_size FROM audit.tree_state WHERE id FOR UPDATE", connection, tx))
        {
            size = (long)(await lockCmd.ExecuteScalarAsync(cancellationToken))!;
        }

        // O(log n) hashes describe the whole existing tree; nothing else is read to append.
        var frontierIds = TreeMath.Frontier(size);
        var frontierHashes = await ReadNodesAsync(connection, tx, frontierIds, cancellationToken);
        var frontier = frontierIds.Select(id => new TreeNode(id, frontierHashes[id])).ToList();

        // Server time, truncated to what timestamptz keeps, so the hashed value is exactly the stored value.
        var now = AuditEntry.TruncateToMicroseconds(time.GetUtcNow());
        var entries = new AuditEntry[batch.Count];
        var leaves = new byte[batch.Count][];
        for (var i = 0; i < batch.Count; i++)
        {
            var e = batch[i];
            entries[i] = new AuditEntry(size + i, now, e.Actor, e.Action, e.Resource, e.Payload);
            leaves[i] = LeafCodec.LeafHash(entries[i]);
        }

        var result = TreeAppender.Append(size, frontier, leaves);

        await using (var insert = new NpgsqlCommand("""
            INSERT INTO audit.entries (seq, occurred_at, actor, action, resource, payload)
            SELECT * FROM unnest($1::bigint[], $2::timestamptz[], $3::text[], $4::text[], $5::text[], $6::text[])
            """, connection, tx))
        {
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Bigint, Value = entries.Select(e => e.Seq).ToArray() });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.TimestampTz, Value = entries.Select(e => e.OccurredAt.UtcDateTime).ToArray() });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = entries.Select(e => e.Actor).ToArray() });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = entries.Select(e => e.Action).ToArray() });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = entries.Select(e => e.Resource).ToArray() });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = entries.Select(e => e.Payload).ToArray() });
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var nodes = new NpgsqlCommand("""
            INSERT INTO audit.tree_nodes (level, idx, hash)
            SELECT * FROM unnest($1::smallint[], $2::bigint[], $3::bytea[])
            """, connection, tx))
        {
            nodes.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Smallint, Value = result.NewNodes.Select(n => (short)n.Id.Level).ToArray() });
            nodes.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Bigint, Value = result.NewNodes.Select(n => n.Id.Index).ToArray() });
            nodes.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Bytea, Value = result.NewNodes.Select(n => n.Hash).ToArray() });
            await nodes.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var state = new NpgsqlCommand("UPDATE audit.tree_state SET tree_size = $1, root_hash = $2, updated_at = now() WHERE id", connection, tx))
        {
            state.Parameters.Add(new NpgsqlParameter { Value = result.TreeSize });
            state.Parameters.Add(new NpgsqlParameter { Value = result.RootHash });
            await state.ExecuteNonQueryAsync(cancellationToken);
        }

        await tx.CommitAsync(cancellationToken);
        metrics.Appended(batch.Count, time.GetElapsedTime(started));
        return [.. entries.Select((e, i) => new AppendedEntry(e.Seq, e.OccurredAt, leaves[i]))];
    }

    public async Task<TreeState> GetTreeStateAsync(CancellationToken cancellationToken)
    {
        await using var cmd = dataSource.CreateCommand("SELECT tree_size, root_hash FROM audit.tree_state WHERE id");
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new TreeState(reader.GetInt64(0), (byte[])reader[1]);
    }

    public async Task<IReadOnlyList<AuditEntry>> GetEntriesAsync(long after, int limit, CancellationToken cancellationToken)
    {
        await using var cmd = dataSource.CreateCommand(
            "SELECT seq, occurred_at, actor, action, resource, payload FROM audit.entries WHERE seq > $1 ORDER BY seq LIMIT $2");
        cmd.Parameters.Add(new NpgsqlParameter { Value = after });
        cmd.Parameters.Add(new NpgsqlParameter { Value = limit });
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var result = new List<AuditEntry>(limit);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new AuditEntry(
                reader.GetInt64(0),
                new DateTimeOffset(reader.GetFieldValue<DateTime>(1), TimeSpan.Zero),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5)));
        }

        return result;
    }

    public async Task<IReadOnlyList<(long Index, byte[] Hash)>> GetLeafHashesAsync(long after, int limit, CancellationToken cancellationToken)
    {
        await using var cmd = dataSource.CreateCommand("SELECT idx, hash FROM audit.tree_nodes WHERE level = 0 AND idx > $1 ORDER BY idx LIMIT $2");
        cmd.Parameters.Add(new NpgsqlParameter { Value = after });
        cmd.Parameters.Add(new NpgsqlParameter { Value = limit });
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var result = new List<(long, byte[])>(limit);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add((reader.GetInt64(0), (byte[])reader[1]));
        }

        return result;
    }

    public async ValueTask<IReadOnlyDictionary<NodeId, byte[]>> GetNodesAsync(IReadOnlyCollection<NodeId> ids, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return await ReadNodesAsync(connection, null, ids, cancellationToken);
    }

    private static async Task<IReadOnlyDictionary<NodeId, byte[]>> ReadNodesAsync(
        NpgsqlConnection connection, NpgsqlTransaction? tx, IReadOnlyCollection<NodeId> ids, CancellationToken cancellationToken)
    {
        var result = new Dictionary<NodeId, byte[]>(ids.Count);
        if (ids.Count == 0)
        {
            return result;
        }

        // One round trip for the whole proof: a handful of primary-key lookups joined against two arrays.
        await using var cmd = new NpgsqlCommand("""
            SELECT n.level, n.idx, n.hash
            FROM unnest($1::smallint[], $2::bigint[]) AS want(level, idx)
            JOIN audit.tree_nodes n ON n.level = want.level AND n.idx = want.idx
            """, connection, tx);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Smallint, Value = ids.Select(i => (short)i.Level).ToArray() });
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Bigint, Value = ids.Select(i => i.Index).ToArray() });
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result[new NodeId(reader.GetInt16(0), reader.GetInt64(1))] = (byte[])reader[2];
        }

        if (result.Count != ids.Count)
        {
            throw new InvalidOperationException($"{ids.Count - result.Count} tree node(s) are missing from audit.tree_nodes.");
        }

        return result;
    }

    public async Task InsertTreeHeadAsync(SignedTreeHead sth, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sth);
        await using var cmd = dataSource.CreateCommand(
            "INSERT INTO audit.tree_heads (tree_size, timestamp_ms, root_hash, key_id, signature) VALUES ($1, $2, $3, $4, $5)");
        cmd.Parameters.Add(new NpgsqlParameter { Value = sth.Head.TreeSize });
        cmd.Parameters.Add(new NpgsqlParameter { Value = sth.Head.TimestampMs });
        cmd.Parameters.Add(new NpgsqlParameter { Value = sth.Head.RootHash });
        cmd.Parameters.Add(new NpgsqlParameter { Value = sth.KeyId });
        cmd.Parameters.Add(new NpgsqlParameter { Value = sth.Signature });
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Signed heads ordered by size then time. <paramref name="latestOnly"/> returns at most the newest one.</summary>
    public async Task<IReadOnlyList<SignedTreeHead>> GetTreeHeadsAsync(bool latestOnly, CancellationToken cancellationToken)
    {
        await using var cmd = dataSource.CreateCommand(latestOnly
            ? "SELECT tree_size, timestamp_ms, root_hash, key_id, signature FROM audit.tree_heads ORDER BY tree_size DESC, timestamp_ms DESC LIMIT 1"
            : "SELECT tree_size, timestamp_ms, root_hash, key_id, signature FROM audit.tree_heads ORDER BY tree_size, timestamp_ms");
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var result = new List<SignedTreeHead>();
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new SignedTreeHead(new TreeHead(reader.GetInt64(0), reader.GetInt64(1), (byte[])reader[2]), reader.GetString(3), (byte[])reader[4]));
        }

        return result;
    }
}
