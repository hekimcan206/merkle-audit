using MerkleAudit.Core.Hashing;

namespace MerkleAudit.Core.Tree;

/// <summary>
/// An append-only tree held in memory, storing exactly the nodes the PostgreSQL store stores. Used by tests, the
/// benchmarks and as the reference the database implementation is compared with.
/// </summary>
public sealed class InMemoryMerkleTree : INodeSource
{
    private readonly List<List<byte[]>> _levels = [];
    private List<TreeNode> _frontier = [];

    public long Size { get; private set; }

    public byte[] Root { get; private set; } = Rfc6962.EmptyRoot();

    public ProofBuilder Proofs => new(this);

    public long AppendData(ReadOnlySpan<byte> leafInput) => AppendLeafHashes([Rfc6962.HashLeaf(leafInput)]);

    /// <summary>Appends leaf hashes and returns the index of the first one.</summary>
    public long AppendLeafHashes(IReadOnlyList<byte[]> leafHashes)
    {
        var first = Size;
        var result = TreeAppender.Append(Size, _frontier, leafHashes);
        foreach (var node in result.NewNodes)
        {
            while (_levels.Count <= node.Id.Level)
            {
                _levels.Add([]);
            }

            // Nodes complete strictly left to right within a level, so the index is always the next slot.
            var level = _levels[node.Id.Level];
            if (level.Count != node.Id.Index)
            {
                throw new InvalidOperationException($"Node {node.Id} arrived out of order.");
            }

            level.Add(node.Hash);
        }

        Size = result.TreeSize;
        Root = result.RootHash;
        _frontier = [.. result.Frontier];
        return first;
    }

    public byte[] Node(NodeId id) =>
        id.Level < _levels.Count && id.Index < _levels[id.Level].Count
            ? _levels[id.Level][(int)id.Index]
            : throw new KeyNotFoundException($"Node {id} is not stored.");

    public byte[] LeafHash(long index) => Node(new NodeId(0, index));

    public byte[] RootAt(long treeSize) =>
        treeSize > Size ? throw new ArgumentOutOfRangeException(nameof(treeSize)) : TreeMath.RangeHash(new LeafRange(0, treeSize), Node);

    public ValueTask<IReadOnlyDictionary<NodeId, byte[]>> GetNodesAsync(IReadOnlyCollection<NodeId> ids, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ids);
        IReadOnlyDictionary<NodeId, byte[]> result = ids.ToDictionary(id => id, Node);
        return ValueTask.FromResult(result);
    }
}
