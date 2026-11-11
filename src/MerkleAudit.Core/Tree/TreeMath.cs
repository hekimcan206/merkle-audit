using System.Numerics;
using MerkleAudit.Core.Hashing;

namespace MerkleAudit.Core.Tree;

/// <summary>
/// The RFC 6962 section 2.1 recursion expressed as leaf ranges. Every proof element is MTH of some range, and every
/// range the recursion produces splits into a few perfect aligned subtrees (<see cref="NodeId"/>).
/// Keeping "which hashes" apart from "where hashes come from" lets one planner serve the in-memory tree, the
/// PostgreSQL store and the tests.
/// </summary>
public static class TreeMath
{
    /// <summary>The largest power of two strictly smaller than <paramref name="n"/> (the RFC's <c>k</c>), n ≥ 2.</summary>
    public static long SplitPoint(long n)
    {
        if (n < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(n), n, "A split needs at least two leaves.");
        }

        return 1L << (63 - BitOperations.LeadingZeroCount((ulong)(n - 1)));
    }

    public static bool IsPowerOfTwo(long n) => n > 0 && (n & (n - 1)) == 0;

    /// <summary>
    /// RFC 6962 PATH(m, D[n]) as ranges, from the leaf's sibling up to the root's child (the wire order).
    /// </summary>
    public static IReadOnlyList<LeafRange> InclusionPath(long leafIndex, long treeSize)
    {
        if (treeSize <= 0 || leafIndex < 0 || leafIndex >= treeSize)
        {
            throw new ArgumentOutOfRangeException(nameof(leafIndex), $"Leaf {leafIndex} is not in a tree of size {treeSize}.");
        }

        var path = new List<LeafRange>();
        Path(leafIndex, 0, treeSize, path);
        return path;
    }

    private static void Path(long m, long start, long end, List<LeafRange> output)
    {
        var n = end - start;
        if (n == 1)
        {
            return;
        }

        var k = SplitPoint(n);
        if (m < k)
        {
            Path(m, start, start + k, output);
            output.Add(new LeafRange(start + k, end));
        }
        else
        {
            Path(m - k, start + k, end, output);
            output.Add(new LeafRange(start, start + k));
        }
    }

    /// <summary>RFC 6962 PROOF(m, D[n]) = SUBPROOF(m, D[n], true) as ranges, in wire order.</summary>
    public static IReadOnlyList<LeafRange> ConsistencyPath(long firstSize, long secondSize)
    {
        if (firstSize < 0 || firstSize > secondSize)
        {
            throw new ArgumentOutOfRangeException(nameof(firstSize), $"Cannot prove {firstSize} is a prefix of {secondSize}.");
        }

        var proof = new List<LeafRange>();
        if (firstSize == 0 || firstSize == secondSize)
        {
            // The empty tree is a prefix of every tree, and a tree is a prefix of itself: both proofs are empty.
            return proof;
        }

        SubProof(firstSize, 0, secondSize, true, proof);
        return proof;
    }

    private static void SubProof(long m, long start, long end, bool startFromOldRoot, List<LeafRange> output)
    {
        var n = end - start;
        if (m == n)
        {
            if (!startFromOldRoot)
            {
                output.Add(new LeafRange(start, end));
            }

            return;
        }

        var k = SplitPoint(n);
        if (m <= k)
        {
            SubProof(m, start, start + k, startFromOldRoot, output);
            output.Add(new LeafRange(start + k, end));
        }
        else
        {
            SubProof(m - k, start + k, end, false, output);
            output.Add(new LeafRange(start, start + k));
        }
    }

    /// <summary>
    /// Splits a range produced by the RFC recursion into perfect aligned subtrees, left to right. The recursion only
    /// produces ranges whose start is aligned to their size class, which is why this split always exists.
    /// </summary>
    public static IReadOnlyList<NodeId> PerfectSubtrees(LeafRange range)
    {
        var nodes = new List<NodeId>();
        Decompose(range.Start, range.End, nodes);
        return nodes;
    }

    private static void Decompose(long start, long end, List<NodeId> output)
    {
        var n = end - start;
        if (n <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(end), "Empty ranges have no subtrees.");
        }

        if (IsPowerOfTwo(n))
        {
            var level = BitOperations.TrailingZeroCount((ulong)n);
            if ((start & (n - 1)) != 0)
            {
                throw new InvalidOperationException($"Range [{start},{end}) is not aligned to a perfect subtree.");
            }

            output.Add(new NodeId(level, start >> level));
            return;
        }

        var k = SplitPoint(n);
        Decompose(start, start + k, output);
        Decompose(start + k, end, output);
    }

    /// <summary>
    /// The perfect subtrees whose concatenation is the whole tree of <paramref name="treeSize"/> leaves (one per set
    /// bit, largest first). Their hashes are the frontier from which the root and the next appends are computed.
    /// </summary>
    public static IReadOnlyList<NodeId> Frontier(long treeSize)
    {
        var nodes = new List<NodeId>();
        long offset = 0;
        for (var level = 62; level >= 0; level--)
        {
            var size = 1L << level;
            if ((treeSize & size) != 0)
            {
                nodes.Add(new NodeId(level, offset >> level));
                offset += size;
            }
        }

        return nodes;
    }

    /// <summary>Hash of a range from perfect subtree hashes, following the RFC recursion exactly.</summary>
    public static byte[] RangeHash(LeafRange range, Func<NodeId, byte[]> node)
    {
        ArgumentNullException.ThrowIfNull(node);
        var n = range.Count;
        if (n == 0)
        {
            return Rfc6962.EmptyRoot();
        }

        if (IsPowerOfTwo(n))
        {
            var level = BitOperations.TrailingZeroCount((ulong)n);
            return node(new NodeId(level, range.Start >> level));
        }

        var k = SplitPoint(n);
        return Rfc6962.HashChildren(
            RangeHash(new LeafRange(range.Start, range.Start + k), node),
            RangeHash(new LeafRange(range.Start + k, range.End), node));
    }

    /// <summary>Root of a tree from its frontier hashes (largest subtree first): fold from the right.</summary>
    public static byte[] RootFromFrontier(IReadOnlyList<byte[]> frontier)
    {
        ArgumentNullException.ThrowIfNull(frontier);
        if (frontier.Count == 0)
        {
            return Rfc6962.EmptyRoot();
        }

        var root = frontier[^1];
        for (var i = frontier.Count - 2; i >= 0; i--)
        {
            root = Rfc6962.HashChildren(frontier[i], root);
        }

        return root;
    }
}
