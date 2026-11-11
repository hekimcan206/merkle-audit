namespace MerkleAudit.Core.Tree;

/// <summary>
/// A perfect, aligned subtree: level <paramref name="Level"/> node number <paramref name="Index"/> covers the leaves
/// <c>[Index · 2^Level, (Index + 1) · 2^Level)</c>. Level 0 nodes are leaf hashes.
/// Only these nodes are stored. They never change once the tree has grown past them, so storage is append-only.
/// </summary>
public readonly record struct NodeId(int Level, long Index)
{
    public long FirstLeaf => Index << Level;

    public long LeafCount => 1L << Level;

    public override string ToString() => $"({Level},{Index})";
}

/// <summary>The leaves <c>[Start, End)</c>; its hash is MTH(D[Start:End]) from RFC 6962.</summary>
public readonly record struct LeafRange(long Start, long End)
{
    public long Count => End - Start;

    public override string ToString() => $"[{Start},{End})";
}
