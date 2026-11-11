using MerkleAudit.Core.Hashing;

namespace MerkleAudit.Core.Tree;

/// <summary>A stored perfect-subtree hash.</summary>
public readonly record struct TreeNode(NodeId Id, byte[] Hash);

/// <summary>The outcome of appending leaves: the nodes to store, the new size and root.</summary>
public sealed record AppendResult(long TreeSize, byte[] RootHash, IReadOnlyList<TreeNode> NewNodes, IReadOnlyList<TreeNode> Frontier);

/// <summary>
/// Appends leaf hashes to a tree described only by its frontier (O(log n) hashes). Every perfect subtree completed by
/// the append is emitted exactly once, so the store writes on average two node rows per leaf and never updates one.
/// </summary>
public static class TreeAppender
{
    public static AppendResult Append(long treeSize, IReadOnlyList<TreeNode> frontier, IReadOnlyList<byte[]> leafHashes)
    {
        ArgumentNullException.ThrowIfNull(frontier);
        ArgumentNullException.ThrowIfNull(leafHashes);

        var expected = TreeMath.Frontier(treeSize);
        if (expected.Count != frontier.Count || !expected.SequenceEqual(frontier.Select(f => f.Id)))
        {
            throw new ArgumentException($"The frontier does not describe a tree of size {treeSize}.", nameof(frontier));
        }

        // Stack of completed subtrees, largest (leftmost) at the bottom; equal levels at the top merge.
        var stack = new List<TreeNode>(frontier);
        var emitted = new List<TreeNode>(leafHashes.Count * 2);
        var size = treeSize;
        foreach (var leaf in leafHashes)
        {
            if (leaf.Length != Rfc6962.HashSize)
            {
                throw new ArgumentException("Leaf hashes must be SHA-256 sized.", nameof(leafHashes));
            }

            var node = new TreeNode(new NodeId(0, size), leaf);
            emitted.Add(node);
            stack.Add(node);
            while (stack.Count >= 2 && stack[^1].Id.Level == stack[^2].Id.Level)
            {
                var right = stack[^1];
                var left = stack[^2];
                stack.RemoveRange(stack.Count - 2, 2);
                var parent = new TreeNode(new NodeId(left.Id.Level + 1, left.Id.Index >> 1), Rfc6962.HashChildren(left.Hash, right.Hash));
                emitted.Add(parent);
                stack.Add(parent);
            }

            size++;
        }

        return new AppendResult(size, TreeMath.RootFromFrontier([.. stack.Select(s => s.Hash)]), emitted, stack);
    }
}
