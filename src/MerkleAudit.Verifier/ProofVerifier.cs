namespace MerkleAudit.Verifier;

/// <summary>
/// Proof verification exactly as RFC 9162 sections 2.1.3.2 (inclusion) and 2.1.4.2 (consistency) specify it: an
/// iterative walk over the bits of the leaf index and the tree size. The server builds proofs with the recursive
/// RFC 6962 definitions instead, so the two sides are different algorithms that must agree (property-tested).
/// </summary>
public static class ProofVerifier
{
    /// <summary>Recomputes the root from a leaf hash and its audit path, or returns null if the path is malformed.</summary>
    public static byte[]? RootFromInclusionProof(long leafIndex, long treeSize, ReadOnlySpan<byte> leafHash, IReadOnlyList<byte[]> auditPath)
    {
        ArgumentNullException.ThrowIfNull(auditPath);
        if (leafIndex < 0 || leafIndex >= treeSize || leafHash.Length != Rfc6962Hash.Size)
        {
            return null;
        }

        var fn = leafIndex;
        var sn = treeSize - 1;
        var r = leafHash.ToArray();
        foreach (var p in auditPath)
        {
            if (sn == 0 || p is not { Length: Rfc6962Hash.Size })
            {
                return null;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                r = Rfc6962Hash.Node(p, r);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            }
            else
            {
                r = Rfc6962Hash.Node(r, p);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 ? r : null;
    }

    public static bool VerifyInclusion(long leafIndex, long treeSize, ReadOnlySpan<byte> leafHash, IReadOnlyList<byte[]> auditPath, ReadOnlySpan<byte> rootHash)
    {
        var computed = RootFromInclusionProof(leafIndex, treeSize, leafHash, auditPath);
        return computed is not null && computed.AsSpan().SequenceEqual(rootHash);
    }

    public static bool VerifyConsistency(long firstSize, long secondSize, IReadOnlyList<byte[]> proof, ReadOnlySpan<byte> firstRoot, ReadOnlySpan<byte> secondRoot)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (firstSize < 0 || firstSize > secondSize)
        {
            return false;
        }

        if (firstSize == secondSize)
        {
            return proof.Count == 0 && firstRoot.SequenceEqual(secondRoot);
        }

        if (firstSize == 0)
        {
            // The empty tree is a prefix of every tree; RFC 9162 only defines proofs for first > 0.
            return proof.Count == 0;
        }

        if (proof.Count == 0 || proof.Any(p => p is not { Length: Rfc6962Hash.Size }))
        {
            return false;
        }

        // Step 2: when the old tree is a perfect subtree, its root is the first proof element implicitly.
        var path = new List<byte[]>(proof.Count + 1);
        if ((firstSize & (firstSize - 1)) == 0)
        {
            path.Add(firstRoot.ToArray());
        }

        path.AddRange(proof);

        var fn = firstSize - 1;
        var sn = secondSize - 1;
        while ((fn & 1) == 1)
        {
            fn >>= 1;
            sn >>= 1;
        }

        var fr = path[0];
        var sr = path[0];
        for (var i = 1; i < path.Count; i++)
        {
            var c = path[i];
            if (sn == 0)
            {
                return false;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                fr = Rfc6962Hash.Node(c, fr);
                sr = Rfc6962Hash.Node(c, sr);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            }
            else
            {
                sr = Rfc6962Hash.Node(sr, c);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 && fr.AsSpan().SequenceEqual(firstRoot) && sr.AsSpan().SequenceEqual(secondRoot);
    }
}
