namespace MerkleAudit.Verifier;

/// <summary>
/// Computes MTH of a growing list of leaf hashes in O(log n) memory, so an auditor can replay a million-entry log
/// while streaming it page by page and read off the root at any prefix size.
/// </summary>
public sealed class StreamingRoot
{
    // Completed perfect subtrees: (height, hash), largest first. Heights strictly decrease along the list.
    private readonly List<(int Height, byte[] Hash)> _stack = [];

    public long Count { get; private set; }

    public void Add(byte[] leafHash)
    {
        ArgumentNullException.ThrowIfNull(leafHash);
        var item = (Height: 0, Hash: leafHash);
        while (_stack.Count > 0 && _stack[^1].Height == item.Height)
        {
            var left = _stack[^1];
            _stack.RemoveAt(_stack.Count - 1);
            item = (item.Height + 1, Rfc6962Hash.Node(left.Hash, item.Hash));
        }

        _stack.Add(item);
        Count++;
    }

    /// <summary>MTH of the leaves added so far.</summary>
    public byte[] Root()
    {
        if (_stack.Count == 0)
        {
            return Rfc6962Hash.Empty();
        }

        var root = _stack[^1].Hash;
        for (var i = _stack.Count - 2; i >= 0; i--)
        {
            root = Rfc6962Hash.Node(_stack[i].Hash, root);
        }

        return root;
    }
}
