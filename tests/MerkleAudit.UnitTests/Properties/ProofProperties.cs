using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Tree;
using MerkleAudit.Verifier;

namespace MerkleAudit.UnitTests.Properties;

/// <summary>
/// The server builds proofs with the recursive RFC 6962 definitions; the verifier checks them with the iterative
/// RFC 9162 algorithm. These properties say the two always agree, for every leaf and every pair of sizes, including
/// proofs for historic sizes served from today's tree.
/// </summary>
public sealed class ProofProperties
{
    private const int MaxSize = 3000;

    // One tree, shared: proofs for any historic size come from the same stored nodes, which is itself a property
    // the server relies on (a perfect subtree never changes once complete).
    private static readonly InMemoryMerkleTree Tree = Build();
    private static readonly byte[][] Roots = [.. Enumerable.Range(0, MaxSize + 1).Select(s => Tree.RootAt(s))];

    private static InMemoryMerkleTree Build()
    {
        var tree = new InMemoryMerkleTree();
        for (var i = 0; i < MaxSize; i++)
        {
            tree.AppendData(BitConverter.GetBytes(i * 7919));
        }

        return tree;
    }

    private static Arbitrary<(int Index, int Size)> LeafInTree() =>
        (from size in Gen.Choose(1, MaxSize)
         from index in Gen.Choose(0, size - 1)
         select (index, size)).ToArbitrary();

    private static Arbitrary<(int First, int Second)> SizePair() =>
        (from second in Gen.Choose(0, MaxSize)
         from first in Gen.Choose(0, second)
         select (first, second)).ToArbitrary();

    [Property(MaxTest = 500)]
    public Property Every_inclusion_proof_verifies() =>
        Prop.ForAll(LeafInTree(), t =>
        {
            var proof = Tree.Proofs.InclusionProofAsync(t.Index, t.Size).AsTask().GetAwaiter().GetResult();
            return ProofVerifier.VerifyInclusion(t.Index, t.Size, Tree.LeafHash(t.Index), proof, Roots[t.Size]);
        });

    [Property(MaxTest = 500)]
    public Property Consistency_holds_between_any_two_sizes() =>
        Prop.ForAll(SizePair(), p =>
        {
            var proof = Tree.Proofs.ConsistencyProofAsync(p.First, p.Second).AsTask().GetAwaiter().GetResult();
            return ProofVerifier.VerifyConsistency(p.First, p.Second, proof, Roots[p.First], Roots[p.Second]);
        });

    [Property(MaxTest = 300)]
    public Property Inclusion_proof_does_not_verify_for_another_leaf() =>
        Prop.ForAll(LeafInTree(), t =>
        {
            var proof = Tree.Proofs.InclusionProofAsync(t.Index, t.Size).AsTask().GetAwaiter().GetResult();
            var other = (t.Index + 1) % t.Size;
            return other == t.Index || !ProofVerifier.VerifyInclusion(t.Index, t.Size, Tree.LeafHash(other), proof, Roots[t.Size]);
        });

    [Property(MaxTest = 300)]
    public Property Flipping_any_bit_of_an_inclusion_proof_breaks_it() =>
        Prop.ForAll(LeafInTree(), Gen.Choose(0, 255).ToArbitrary(), (t, bit) =>
        {
            var proof = Tree.Proofs.InclusionProofAsync(t.Index, t.Size).AsTask().GetAwaiter().GetResult().Select(p => (byte[])p.Clone()).ToList();
            if (proof.Count == 0)
            {
                return true;
            }

            var element = proof[bit % proof.Count];
            element[bit / 8] ^= (byte)(1 << (bit % 8));
            return !ProofVerifier.VerifyInclusion(t.Index, t.Size, Tree.LeafHash(t.Index), proof, Roots[t.Size]);
        });

    [Property(MaxTest = 300)]
    public Property Consistency_proof_does_not_verify_against_a_different_old_root() =>
        Prop.ForAll(SizePair(), p =>
        {
            if (p.First == 0 || p.First == p.Second)
            {
                return true;
            }

            var proof = Tree.Proofs.ConsistencyProofAsync(p.First, p.Second).AsTask().GetAwaiter().GetResult();
            var forgedOld = Roots[p.First - 1];
            return !ProofVerifier.VerifyConsistency(p.First, p.Second, proof, forgedOld, Roots[p.Second]);
        });

    [Property(MaxTest = 200)]
    public Property Proof_length_is_logarithmic() =>
        Prop.ForAll(LeafInTree(), t =>
        {
            var proof = Tree.Proofs.InclusionProofAsync(t.Index, t.Size).AsTask().GetAwaiter().GetResult();
            return proof.Count <= (int)Math.Ceiling(Math.Log2(t.Size));
        });

    [Property(MaxTest = 200)]
    public Property Batched_appends_produce_the_same_tree_as_single_appends(PositiveInt[] batchSizes)
    {
        var batched = new InMemoryMerkleTree();
        var single = new StreamingRoot();
        var i = 0;
        foreach (var size in batchSizes.Select(b => (b.Get % 40) + 1))
        {
            var leaves = Enumerable.Range(i, size).Select(n => Tree.LeafHash(n % MaxSize)).ToList();
            batched.AppendLeafHashes(leaves);
            leaves.ForEach(single.Add);
            i += size;
        }

        return batched.Root.AsSpan().SequenceEqual(single.Root()).ToProperty();
    }

    [Property(MaxTest = 300)]
    public Property Server_and_verifier_leaf_encodings_agree(long seq, NonNegativeInt micros, NonNull<string> actor, NonNull<string> action, NonNull<string> resource, NonNull<string> payload)
    {
        var at = DateTimeOffset.UnixEpoch.AddTicks((long)micros.Get * 10);
        var entry = new AuditEntry(seq, at, actor.Get, action.Get, resource.Get, payload.Get);
        var record = new EntryRecord(seq, micros.Get, actor.Get, action.Get, resource.Get, payload.Get);
        return LeafCodec.Encode(entry).AsSpan().SequenceEqual(record.LeafInput()).ToProperty();
    }

    [Property(MaxTest = 300)]
    public Property Leaf_encoding_is_injective_across_field_boundaries(NonNull<string> a, NonNull<string> b)
    {
        // "ab" + "" must not encode like "a" + "b": the length prefixes are what guarantee it.
        var at = DateTimeOffset.UnixEpoch;
        var joined = LeafCodec.Encode(new AuditEntry(1, at, a.Get + b.Get, "", "r", "{}"));
        var split = LeafCodec.Encode(new AuditEntry(1, at, a.Get, b.Get, "r", "{}"));
        return (b.Get.Length == 0 || !joined.AsSpan().SequenceEqual(split)).ToProperty();
    }
}
