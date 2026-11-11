using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Tree;
using Npgsql;

namespace MerkleAudit.Demo;

/// <summary>
/// Plays the rogue database administrator: connects as the PostgreSQL superuser, switches off the append-only
/// triggers for its session (<c>session_replication_role = replica</c>) and edits the log tables directly.
/// Every operation returns an undo action so a demo can show detection and recovery one scenario at a time.
/// </summary>
public sealed class Tamperer(NpgsqlDataSource superuser)
{
    public delegate Task Undo();

    private sealed record Row(long Seq, DateTime OccurredAt, string Actor, string Action, string Resource, string Payload);

    /// <summary>Changes the payload of one entry, e.g. to hide what was accessed.</summary>
    public async Task<Undo> AlterPayloadAsync(long seq, string payload)
    {
        var original = await ReadRowAsync(seq);
        await ExecuteAsync("UPDATE audit.entries SET payload = $2 WHERE seq = $1", seq, payload);
        return () => ExecuteAsync("UPDATE audit.entries SET payload = $2 WHERE seq = $1", seq, original.Payload);
    }

    /// <summary>Deletes one entry, e.g. an access that should not have happened.</summary>
    public async Task<Undo> DeleteAsync(long seq)
    {
        var original = await ReadRowAsync(seq);
        await ExecuteAsync("DELETE FROM audit.entries WHERE seq = $1", seq);
        return () => InsertRowAsync(original);
    }

    /// <summary>Swaps the content of two adjacent entries, e.g. to make a read appear after a consent change.</summary>
    public async Task<Undo> SwapAsync(long a, long b)
    {
        var rowA = await ReadRowAsync(a);
        var rowB = await ReadRowAsync(b);
        await ReplaceContentAsync(a, rowB);
        await ReplaceContentAsync(b, rowA);
        return async () =>
        {
            await ReplaceContentAsync(a, rowA);
            await ReplaceContentAsync(b, rowB);
        };
    }

    /// <summary>Inserts a forged, back-dated entry after the last one, e.g. a fake "consent given".</summary>
    public async Task<Undo> InsertForgedAsync(long seq, string actor, string action, string resource, string payload, DateTime occurredAt)
    {
        await InsertRowAsync(new Row(seq, occurredAt, actor, action, resource, payload));
        return () => ExecuteAsync("DELETE FROM audit.entries WHERE seq = $1", seq);
    }

    /// <summary>
    /// The thorough attacker: changes a row, then recomputes its leaf, every ancestor node and tree_state, so the
    /// database is internally consistent again. Only the signed tree heads published earlier can expose this.
    /// </summary>
    public async Task<Undo> RewriteRowAndTreeAsync(long seq, string actor)
    {
        var original = await ReadRowAsync(seq);
        await ExecuteAsync("UPDATE audit.entries SET actor = $2 WHERE seq = $1", seq, actor);

        var rows = await ReadAllRowsAsync();
        var rebuilt = new InMemoryMerkleTree();
        foreach (var row in rows)
        {
            rebuilt.AppendLeafHashes([LeafCodec.LeafHash(new AuditEntry(row.Seq, new DateTimeOffset(row.OccurredAt, TimeSpan.Zero), row.Actor, row.Action, row.Resource, row.Payload))]);
        }

        var stored = await ReadAllNodesAsync();
        var changed = stored.Where(n => !n.Value.AsSpan().SequenceEqual(rebuilt.Node(n.Key))).ToList();
        var (originalSize, originalRoot) = await ReadStateAsync();
        foreach (var (id, _) in changed)
        {
            await ExecuteAsync("UPDATE audit.tree_nodes SET hash = $3 WHERE level = $1 AND idx = $2", (short)id.Level, id.Index, rebuilt.Node(id));
        }

        await ExecuteAsync("UPDATE audit.tree_state SET root_hash = $1 WHERE id", rebuilt.Root);
        return async () =>
        {
            await ExecuteAsync("UPDATE audit.entries SET actor = $2 WHERE seq = $1", seq, original.Actor);
            foreach (var (id, hash) in changed)
            {
                await ExecuteAsync("UPDATE audit.tree_nodes SET hash = $3 WHERE level = $1 AND idx = $2", (short)id.Level, id.Index, hash);
            }

            await ExecuteAsync("UPDATE audit.tree_state SET tree_size = $1, root_hash = $2 WHERE id", originalSize, originalRoot);
        };
    }

    private async Task ReplaceContentAsync(long seq, Row content) =>
        await ExecuteAsync(
            "UPDATE audit.entries SET occurred_at = $2, actor = $3, action = $4, resource = $5, payload = $6 WHERE seq = $1",
            seq, content.OccurredAt, content.Actor, content.Action, content.Resource, content.Payload);

    private Task InsertRowAsync(Row row) =>
        ExecuteAsync(
            "INSERT INTO audit.entries (seq, occurred_at, actor, action, resource, payload) VALUES ($1, $2, $3, $4, $5, $6)",
            row.Seq, row.OccurredAt, row.Actor, row.Action, row.Resource, row.Payload);

    private async Task<Row> ReadRowAsync(long seq) =>
        (await ReadRowsAsync("WHERE seq = $1", seq)) is [var row] ? row : throw new InvalidOperationException($"No entry {seq}.");

    private Task<List<Row>> ReadAllRowsAsync() => ReadRowsAsync("");

    private async Task<List<Row>> ReadRowsAsync(string where, params object[] args)
    {
        await using var cmd = superuser.CreateCommand($"SELECT seq, occurred_at, actor, action, resource, payload FROM audit.entries {where} ORDER BY seq");
        foreach (var arg in args)
        {
            cmd.Parameters.Add(new NpgsqlParameter { Value = arg });
        }

        await using var reader = await cmd.ExecuteReaderAsync();
        var rows = new List<Row>();
        while (await reader.ReadAsync())
        {
            rows.Add(new Row(reader.GetInt64(0), reader.GetFieldValue<DateTime>(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)));
        }

        return rows;
    }

    private async Task<Dictionary<NodeId, byte[]>> ReadAllNodesAsync()
    {
        await using var cmd = superuser.CreateCommand("SELECT level, idx, hash FROM audit.tree_nodes");
        await using var reader = await cmd.ExecuteReaderAsync();
        var nodes = new Dictionary<NodeId, byte[]>();
        while (await reader.ReadAsync())
        {
            nodes[new NodeId(reader.GetInt16(0), reader.GetInt64(1))] = (byte[])reader[2];
        }

        return nodes;
    }

    private async Task<(long Size, byte[] Root)> ReadStateAsync()
    {
        await using var cmd = superuser.CreateCommand("SELECT tree_size, root_hash FROM audit.tree_state WHERE id");
        await using var reader = await cmd.ExecuteReaderAsync();
        await reader.ReadAsync();
        return (reader.GetInt64(0), (byte[])reader[1]);
    }

    private async Task ExecuteAsync(string sql, params object[] args)
    {
        // Each statement runs with triggers disabled for this session only; a superuser privilege by design.
        await using var connection = await superuser.OpenConnectionAsync();
        await using var tx = await connection.BeginTransactionAsync();
        await using (var replica = new NpgsqlCommand("SET LOCAL session_replication_role = replica", connection, tx))
        {
            await replica.ExecuteNonQueryAsync();
        }

        await using (var cmd = new NpgsqlCommand(sql, connection, tx))
        {
            foreach (var arg in args)
            {
                cmd.Parameters.Add(new NpgsqlParameter { Value = arg });
            }

            await cmd.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
    }
}
