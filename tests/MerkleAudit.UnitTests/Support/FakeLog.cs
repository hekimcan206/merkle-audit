using System.Runtime.CompilerServices;
using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Tree;
using MerkleAudit.Core.TreeHeads;
using MerkleAudit.Verifier;

namespace MerkleAudit.UnitTests.Support;

/// <summary>
/// An in-memory log with the same three layers as the PostgreSQL one (rows, stored nodes, signed heads), each of
/// which a test can tamper with directly, the way a database administrator could.
/// </summary>
internal sealed class FakeLog : ILogSource, INodeSource, IDisposable
{
    private readonly TreeHeadSigner _signer = TreeHeadSigner.Generate();
    private readonly InMemoryMerkleTree _tree = new();

    public SortedDictionary<long, EntryRecord> Rows { get; } = [];

    public Dictionary<NodeId, byte[]> Nodes { get; } = [];

    public List<SignedHead> Heads { get; } = [];

    public TreeHeadSigner Signer => _signer;

    public long Size => _tree.Size;

    public static FakeLog WithEntries(int count, int publishEvery)
    {
        var log = new FakeLog();
        for (var i = 0; i < count; i++)
        {
            log.Append($"user-{i % 7}", i % 3 == 0 ? "record.read" : "record.update", $"patient/{i % 11}", $$"""{"n":{{i}}}""");
            if ((i + 1) % publishEvery == 0)
            {
                log.Publish();
            }
        }

        return log;
    }

    public void Append(string actor, string action, string resource, string payload)
    {
        var seq = _tree.Size;
        var entry = new AuditEntry(seq, DateTimeOffset.UnixEpoch.AddSeconds(1_762_000_000 + seq), actor, action, resource, payload);
        _tree.AppendLeafHashes([LeafCodec.LeafHash(entry)]);
        Rows[seq] = new EntryRecord(seq, LeafCodec.ToUnixMicroseconds(entry.OccurredAt), actor, action, resource, payload);
        SyncNodes();
    }

    public SignedHead Publish(long? timestamp = null)
    {
        var sth = _signer.Sign(new TreeHead(_tree.Size, timestamp ?? (1_762_000_000_000 + Heads.Count), _tree.Root));
        var head = new SignedHead(sth.Head.TreeSize, sth.Head.TimestampMs, sth.Head.RootHash, sth.KeyId, sth.Signature);
        Heads.Add(head);
        return head;
    }

    /// <summary>Rebuilds every stored node from the current rows, as an attacker who knows the public algorithm would.</summary>
    public void RewriteTreeFromRows()
    {
        var rebuilt = new InMemoryMerkleTree();
        foreach (var row in Rows.Values)
        {
            rebuilt.AppendLeafHashes([row.LeafHash()]);
        }

        Nodes.Clear();
        CopyNodes(rebuilt);
    }

    private void SyncNodes() => CopyNodes(_tree);

    private void CopyNodes(InMemoryMerkleTree tree)
    {
        for (var level = 0; (1L << level) <= tree.Size; level++)
        {
            for (long index = 0; ((index + 1) << level) <= tree.Size; index++)
            {
                Nodes.TryAdd(new NodeId(level, index), tree.Node(new NodeId(level, index)));
            }
        }
    }

    public Task<IReadOnlyList<SignedHead>> GetTreeHeadsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SignedHead>>([.. Heads]);

    public async IAsyncEnumerable<EntryRecord> ReadEntriesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var row in Rows.Values.ToList())
        {
            await Task.Yield();
            yield return row;
        }
    }

    public async IAsyncEnumerable<(long Index, byte[] Hash)> ReadLeafHashesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var (id, hash) in Nodes.Where(n => n.Key.Level == 0).OrderBy(n => n.Key.Index).ToList())
        {
            await Task.Yield();
            yield return (id.Index, hash);
        }
    }

    public async Task<IReadOnlyList<byte[]>> GetInclusionProofAsync(long leafIndex, long treeSize, CancellationToken cancellationToken) =>
        await new ProofBuilder(this).InclusionProofAsync(leafIndex, treeSize, cancellationToken);

    public async Task<IReadOnlyList<byte[]>> GetConsistencyProofAsync(long firstSize, long secondSize, CancellationToken cancellationToken) =>
        await new ProofBuilder(this).ConsistencyProofAsync(firstSize, secondSize, cancellationToken);

    public ValueTask<IReadOnlyDictionary<NodeId, byte[]>> GetNodesAsync(IReadOnlyCollection<NodeId> ids, CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<NodeId, byte[]> result = ids.ToDictionary(id => id, id => Nodes[id]);
        return ValueTask.FromResult(result);
    }

    public TrustStore Trust()
    {
        var trust = new TrustStore();
        trust.AddPem(_signer.PublicKeyPem);
        return trust;
    }

    public void Dispose() => _signer.Dispose();
}
