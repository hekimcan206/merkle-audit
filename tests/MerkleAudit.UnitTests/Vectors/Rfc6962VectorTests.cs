using MerkleAudit.Core.Hashing;
using MerkleAudit.Core.Tree;
using MerkleAudit.Verifier;

namespace MerkleAudit.UnitTests.Vectors;

/// <summary>
/// Known-answer tests from the reference RFC 6962 implementation used by Certificate Transparency:
/// github.com/transparency-dev/merkle (Apache-2.0), files <c>testonly/constants.go</c> (leaf inputs, root hashes for
/// every size 0..8) and <c>proof/verify_test.go</c> (inclusion and consistency proof vectors). The same vectors go back
/// to the original C++ CT log's merkle_tree_test.cc. Values are copied verbatim; leaf indices there are 1-based.
/// </summary>
public sealed class Rfc6962VectorTests
{
    private static readonly string[] LeafInputs =
        ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];

    private static readonly string[] RootHashes =
    [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    // (1-based leaf, tree size, audit path) from proof/verify_test.go.
    public static TheoryData<int, int, string[]> InclusionVectors => new()
    {
        { 1, 1, [] },
        { 1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
        { 6, 8, ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
        { 3, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"] },
        { 2, 5, ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
    };

    // (size1, size2, proof) from proof/verify_test.go.
    public static TheoryData<int, int, string[]> ConsistencyVectors => new()
    {
        { 1, 1, [] },
        { 1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
        { 6, 8, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
        { 2, 5, ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
        { 6, 7, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
    };

    private static InMemoryMerkleTree BuildTree()
    {
        var tree = new InMemoryMerkleTree();
        foreach (var input in LeafInputs)
        {
            tree.AppendData(Convert.FromHexString(input));
        }

        return tree;
    }

    private static byte[] Root(int size) => Convert.FromHexString(RootHashes[size]);

    [Fact]
    public void Empty_tree_hash_is_sha256_of_nothing()
    {
        Convert.ToHexStringLower(Rfc6962.EmptyRoot()).Should().Be(RootHashes[0]);
        Convert.ToHexStringLower(Rfc6962Hash.Empty()).Should().Be(RootHashes[0]);
    }

    [Fact]
    public void Root_after_every_append_matches_the_reference_roots()
    {
        var tree = new InMemoryMerkleTree();
        var verifierRoot = new StreamingRoot();
        Convert.ToHexStringLower(tree.Root).Should().Be(RootHashes[0]);
        for (var i = 0; i < LeafInputs.Length; i++)
        {
            var input = Convert.FromHexString(LeafInputs[i]);
            tree.AppendData(input);
            verifierRoot.Add(Rfc6962Hash.Leaf(input));

            Convert.ToHexStringLower(tree.Root).Should().Be(RootHashes[i + 1], $"server root at size {i + 1}");
            Convert.ToHexStringLower(verifierRoot.Root()).Should().Be(RootHashes[i + 1], $"verifier root at size {i + 1}");
        }
    }

    [Fact]
    public void Historic_roots_are_recomputed_from_stored_nodes()
    {
        var tree = BuildTree();
        for (var size = 0; size <= 8; size++)
        {
            Convert.ToHexStringLower(tree.RootAt(size)).Should().Be(RootHashes[size]);
        }
    }

    [Fact]
    public void Leaf_and_node_hashes_use_domain_separation_prefixes()
    {
        // MTH of one empty leaf is SHA-256(0x00), not SHA-256(): the prefix is what the size-1 vector pins down.
        Convert.ToHexStringLower(Rfc6962.HashLeaf([])).Should().Be(RootHashes[1]);
        var left = Rfc6962.HashLeaf([]);
        var right = Rfc6962.HashLeaf([0x00]);
        Convert.ToHexStringLower(Rfc6962.HashChildren(left, right)).Should().Be(RootHashes[2]);
        Rfc6962Hash.Node(left, right).Should().Equal(Rfc6962.HashChildren(left, right));
    }

    [Theory]
    [MemberData(nameof(InclusionVectors))]
    public async Task Server_builds_the_reference_inclusion_proofs(int leaf, int size, string[] expected)
    {
        var proof = await BuildTree().Proofs.InclusionProofAsync(leaf - 1, size, TestContext.Current.CancellationToken);
        proof.Select(Convert.ToHexStringLower).Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(InclusionVectors))]
    public void Verifier_accepts_the_reference_inclusion_proofs(int leaf, int size, string[] path)
    {
        var leafHash = Rfc6962Hash.Leaf(Convert.FromHexString(LeafInputs[leaf - 1]));
        var proof = path.Select(Convert.FromHexString).ToList();
        ProofVerifier.VerifyInclusion(leaf - 1, size, leafHash, proof, Root(size)).Should().BeTrue();

        // And rejects it for any other leaf, size or root.
        ProofVerifier.VerifyInclusion(leaf - 1, size, Rfc6962Hash.Leaf([0xff]), proof, Root(size)).Should().BeFalse();
        ProofVerifier.VerifyInclusion(leaf - 1, size, leafHash, proof, Root(size - 1)).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(ConsistencyVectors))]
    public async Task Server_builds_the_reference_consistency_proofs(int first, int second, string[] expected)
    {
        var proof = await BuildTree().Proofs.ConsistencyProofAsync(first, second, TestContext.Current.CancellationToken);
        proof.Select(Convert.ToHexStringLower).Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(ConsistencyVectors))]
    public void Verifier_accepts_the_reference_consistency_proofs(int first, int second, string[] path)
    {
        var proof = path.Select(Convert.FromHexString).ToList();
        ProofVerifier.VerifyConsistency(first, second, proof, Root(first), Root(second)).Should().BeTrue();
        if (first != second)
        {
            ProofVerifier.VerifyConsistency(first, second, proof, Root(first), Root(first)).Should().BeFalse();
            ProofVerifier.VerifyConsistency(first, second, proof, Root(second), Root(second)).Should().BeFalse();
        }
    }

    [Fact]
    public void Verifier_rejects_malformed_inputs()
    {
        var leaf = Rfc6962Hash.Leaf([]);
        ProofVerifier.VerifyInclusion(0, 0, leaf, [], Root(0)).Should().BeFalse("no leaf is in the empty tree");
        ProofVerifier.VerifyInclusion(8, 8, leaf, [], Root(8)).Should().BeFalse("index past the end");
        ProofVerifier.VerifyInclusion(0, 8, leaf, [new byte[31]], Root(8)).Should().BeFalse("short hash");
        ProofVerifier.VerifyInclusion(0, 1, leaf, [leaf], Root(1)).Should().BeFalse("proof longer than the tree is deep");
        ProofVerifier.VerifyConsistency(5, 4, [], Root(5), Root(4)).Should().BeFalse("trees do not shrink");
        ProofVerifier.VerifyConsistency(3, 8, [], Root(3), Root(8)).Should().BeFalse("empty proof for different sizes");
        ProofVerifier.VerifyConsistency(0, 8, [], Root(0), Root(8)).Should().BeTrue("the empty tree is a prefix of every tree");
    }
}
