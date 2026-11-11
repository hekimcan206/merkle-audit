namespace MerkleAudit.Core.Tree;

/// <summary>Source of stored perfect-subtree hashes (in memory, PostgreSQL, ...).</summary>
public interface INodeSource
{
    /// <summary>Returns the hash of every requested node. Missing nodes are an error: the caller asked inside the tree.</summary>
    ValueTask<IReadOnlyDictionary<NodeId, byte[]>> GetNodesAsync(IReadOnlyCollection<NodeId> ids, CancellationToken cancellationToken);
}

/// <summary>
/// Builds RFC 6962 proofs in two steps: plan which perfect subtrees are needed (pure arithmetic), fetch them in one
/// round trip, then fold. A proof for any historic size m ≤ current size comes from the same stored nodes, because a
/// perfect subtree is immutable once complete.
/// </summary>
public sealed class ProofBuilder(INodeSource source)
{
    public async ValueTask<IReadOnlyList<byte[]>> InclusionProofAsync(long leafIndex, long treeSize, CancellationToken cancellationToken = default) =>
        await FoldAsync(TreeMath.InclusionPath(leafIndex, treeSize), cancellationToken);

    public async ValueTask<IReadOnlyList<byte[]>> ConsistencyProofAsync(long firstSize, long secondSize, CancellationToken cancellationToken = default) =>
        await FoldAsync(TreeMath.ConsistencyPath(firstSize, secondSize), cancellationToken);

    public async ValueTask<byte[]> RootAsync(long treeSize, CancellationToken cancellationToken = default)
    {
        var hashes = await FoldAsync(treeSize == 0 ? [] : [new LeafRange(0, treeSize)], cancellationToken);
        return hashes.Count == 0 ? Hashing.Rfc6962.EmptyRoot() : hashes[0];
    }

    private async ValueTask<IReadOnlyList<byte[]>> FoldAsync(IReadOnlyList<LeafRange> ranges, CancellationToken cancellationToken)
    {
        if (ranges.Count == 0)
        {
            return [];
        }

        var needed = new HashSet<NodeId>();
        foreach (var range in ranges)
        {
            needed.UnionWith(TreeMath.PerfectSubtrees(range));
        }

        var nodes = await source.GetNodesAsync(needed, cancellationToken);
        return [.. ranges.Select(r => TreeMath.RangeHash(r, id => nodes.TryGetValue(id, out var hash)
            ? hash
            : throw new InvalidOperationException($"Node {id} is missing from the store.")))];
    }
}
