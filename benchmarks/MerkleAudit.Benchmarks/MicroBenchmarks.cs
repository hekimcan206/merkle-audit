using BenchmarkDotNet.Attributes;
using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Hashing;
using MerkleAudit.Core.Tree;
using MerkleAudit.Verifier;

namespace MerkleAudit.Benchmarks;

/// <summary>
/// Verification cost: what a client or monitor pays to check one proof, by tree size. Proofs are generated once from
/// an in-memory tree of 2^20 + 12345 leaves (just over one million), so every size up to that is a real historic size.
/// </summary>
[MemoryDiagnoser]
public class VerificationBenchmarks
{
    private const long TreeLeaves = (1L << 20) + 12_345;
    private static readonly InMemoryMerkleTree Tree = Build();

    private byte[] _leaf = [];
    private IReadOnlyList<byte[]> _inclusion = [];
    private IReadOnlyList<byte[]> _consistency = [];
    private byte[] _root = [];
    private byte[] _oldRoot = [];
    private long _index;
    private AuditEntry _entry = null!;

    [Params(1_000, 100_000, 1_000_000)]
    public long TreeSize { get; set; }

    private static InMemoryMerkleTree Build()
    {
        var tree = new InMemoryMerkleTree();
        var batch = new List<byte[]>(4096);
        for (long i = 0; i < TreeLeaves; i++)
        {
            batch.Add(Rfc6962.HashLeaf(BitConverter.GetBytes(i)));
            if (batch.Count == 4096)
            {
                tree.AppendLeafHashes(batch);
                batch.Clear();
            }
        }

        tree.AppendLeafHashes(batch);
        return tree;
    }

    [GlobalSetup]
    public void Setup()
    {
        _index = TreeSize / 3;
        _leaf = Tree.LeafHash(_index);
        _root = Tree.RootAt(TreeSize);
        _oldRoot = Tree.RootAt(TreeSize / 2 + 1);
        _inclusion = Tree.Proofs.InclusionProofAsync(_index, TreeSize).AsTask().GetAwaiter().GetResult();
        _consistency = Tree.Proofs.ConsistencyProofAsync(TreeSize / 2 + 1, TreeSize).AsTask().GetAwaiter().GetResult();
        _entry = new AuditEntry(_index, DateTimeOffset.UnixEpoch.AddDays(20_000), "dr.ayse.k", "record.read", "patient/P-000123",
            """{"ip":"10.20.3.246","reason":"treatment","n":115}""");
    }

    [Benchmark(Description = "verify inclusion proof")]
    public bool VerifyInclusion() => ProofVerifier.VerifyInclusion(_index, TreeSize, _leaf, _inclusion, _root);

    [Benchmark(Description = "verify consistency proof (n/2+1 -> n)")]
    public bool VerifyConsistency() => ProofVerifier.VerifyConsistency(TreeSize / 2 + 1, TreeSize, _consistency, _oldRoot, _root);

    [Benchmark(Description = "build inclusion proof (in-memory nodes)")]
    public int BuildInclusion() => Tree.Proofs.InclusionProofAsync(_index, TreeSize).AsTask().GetAwaiter().GetResult().Count;

    [Benchmark(Description = "encode + hash one audit entry")]
    public byte[] HashEntry() => LeafCodec.LeafHash(_entry);
}
