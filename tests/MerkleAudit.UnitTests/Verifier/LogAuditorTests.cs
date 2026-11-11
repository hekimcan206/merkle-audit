using MerkleAudit.Core.Tree;
using MerkleAudit.UnitTests.Support;
using MerkleAudit.Verifier;

namespace MerkleAudit.UnitTests.Verifier;

/// <summary>Each test tampers with one layer of an in-memory log and checks the auditor names exactly what changed.</summary>
public sealed class LogAuditorTests
{
    private static async Task<AuditReport> AuditAsync(FakeLog log, IReadOnlyList<SignedHead>? witnessed = null)
    {
        using var trust = log.Trust();
        return await new LogAuditor(log, trust).AuditAsync(witnessed, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Untouched_log_is_clean_and_proofs_verify()
    {
        using var log = FakeLog.WithEntries(200, publishEvery: 50);

        var report = await AuditAsync(log);

        report.Clean.Should().BeTrue(report.Render());
        report.StoredTreeAuthentic.Should().BeTrue();
        report.LatestHead!.TreeSize.Should().Be(200);
        report.ProofChecks.Should().NotBeEmpty().And.OnlyContain(p => p.Verified);
        report.ProofChecks.Count(p => p.Proof == "consistency").Should().Be(3, "200 entries published every 50 give 4 heads");
    }

    [Fact]
    public async Task Altered_row_is_pinpointed()
    {
        using var log = FakeLog.WithEntries(200, publishEvery: 50);
        log.Rows[117] = log.Rows[117] with { Payload = """{"n":117,"approved":true}""" };

        var report = await AuditAsync(log);

        report.Findings.Should().ContainSingle().Which.Should().Match<Finding>(f => f.Kind == FindingKind.RowAltered && f.Index == 117);
        report.StoredTreeAuthentic.Should().BeTrue("only the row changed; the tree still remembers the original leaf");
        report.ProofChecks.Should().Contain(p => p.Subject == "seq 117 in size 200" && !p.Verified);
    }

    [Fact]
    public async Task Deleted_row_is_pinpointed()
    {
        using var log = FakeLog.WithEntries(200, publishEvery: 50);
        log.Rows.Remove(42);

        var report = await AuditAsync(log);

        report.Findings.Should().ContainSingle().Which.Should().Match<Finding>(f => f.Kind == FindingKind.RowDeleted && f.Index == 42);
    }

    [Fact]
    public async Task Swapped_rows_are_reported_as_moved_both_ways()
    {
        using var log = FakeLog.WithEntries(200, publishEvery: 50);
        var (a, b) = (log.Rows[60], log.Rows[61]);
        log.Rows[60] = b with { Seq = 60 };
        log.Rows[61] = a with { Seq = 61 };

        var report = await AuditAsync(log);

        report.Findings.Select(f => (f.Kind, f.Index, f.Detail)).Should().Equal(
            (FindingKind.RowMoved, 60, "row holds the entry committed at seq 61"),
            (FindingKind.RowMoved, 61, "row holds the entry committed at seq 60"));
    }

    [Fact]
    public async Task Delete_and_renumber_is_reported_from_the_first_divergence()
    {
        using var log = FakeLog.WithEntries(100, publishEvery: 25);
        log.Rows.Remove(90);
        for (long seq = 91; seq < 100; seq++)
        {
            log.Rows[seq - 1] = log.Rows[seq] with { Seq = seq - 1 };
        }

        log.Rows.Remove(99);

        var report = await AuditAsync(log);

        report.Findings.Where(f => f.Kind == FindingKind.RowMoved).Select(f => f.Index).Should().Equal(Enumerable.Range(90, 9).Select(i => (long?)i));
        report.Findings.Should().ContainSingle(f => f.Kind == FindingKind.RowDeleted)
            .Which.Index.Should().Be(90, "entry 90 is the one that exists nowhere; entry 99 only moved to slot 98");
    }

    [Fact]
    public async Task Row_inserted_outside_the_tree_is_reported()
    {
        using var log = FakeLog.WithEntries(100, publishEvery: 50);
        log.Rows[100] = log.Rows[99] with { Seq = 100, Actor = "intruder" };

        var report = await AuditAsync(log);

        report.Findings.Should().ContainSingle().Which.Should().Match<Finding>(f => f.Kind == FindingKind.RowNotInTree && f.Index == 100);
    }

    [Fact]
    public async Task Rewriting_rows_and_the_whole_tree_is_localised_between_signed_heads()
    {
        using var log = FakeLog.WithEntries(200, publishEvery: 25);
        log.Rows[160] = log.Rows[160] with { Actor = "someone-else" };
        log.RewriteTreeFromRows();

        var report = await AuditAsync(log);

        report.StoredTreeAuthentic.Should().BeFalse();
        report.Findings.Should().Contain(f => f.Kind == FindingKind.StoredTreeRewritten && f.Detail.Contains("seq [150, 174]"));
        report.Findings.Should().Contain(f => f.Kind == FindingKind.RowsDivergeFromSignedHistory && f.Detail.Contains("seq [150, 174]"));
        report.Findings.Should().Contain(f => f.Kind == FindingKind.ConsistencyProofFailed);
        report.Findings.Should().NotContain(f => f.Kind == FindingKind.RowAltered, "rows and leaves agree with each other; only the signatures expose them");
    }

    [Fact]
    public async Task Tampered_interior_node_breaks_proofs_for_intact_rows()
    {
        using var log = FakeLog.WithEntries(256, publishEvery: 64);
        log.Nodes[new NodeId(6, 1)] = new byte[32]; // leaves 64..127: a sibling on leaf 0's path

        var report = await AuditAsync(log);

        report.Findings.Should().Contain(f => f.Kind == FindingKind.InclusionProofFailed && f.Index == 0);
    }

    [Fact]
    public async Task Forged_tree_head_is_rejected_and_reported()
    {
        using var log = FakeLog.WithEntries(100, publishEvery: 50);
        var last = log.Heads[^1];
        log.Heads[^1] = last with { TreeSize = 99 };

        var report = await AuditAsync(log);

        report.Findings.Should().Contain(f => f.Kind == FindingKind.InvalidTreeHead && f.Detail.Contains("signature does not verify"));
        report.ValidHeads.Should().Be(1);
    }

    [Fact]
    public async Task Witnessed_head_removed_from_history_is_reported()
    {
        using var log = FakeLog.WithEntries(100, publishEvery: 50);
        var witnessed = log.Heads.ToList();
        log.Heads.RemoveAt(0);

        var report = await AuditAsync(log, witnessed);

        report.Findings.Should().ContainSingle().Which.Kind.Should().Be(FindingKind.WitnessedHeadMissing);
    }

    [Fact]
    public async Task Truncated_log_is_reported()
    {
        using var log = FakeLog.WithEntries(100, publishEvery: 50);
        for (long seq = 80; seq < 100; seq++)
        {
            log.Rows.Remove(seq);
            log.Nodes.Remove(new NodeId(0, seq));
        }

        var report = await AuditAsync(log);

        report.Findings.Should().Contain(f => f.Kind == FindingKind.LogTruncated && f.Detail.Contains("covers 100 leaves but the stored tree has 80"));
    }

    [Fact]
    public async Task Entries_after_the_latest_head_are_an_unsigned_tail_not_a_finding()
    {
        using var log = FakeLog.WithEntries(110, publishEvery: 50);

        var report = await AuditAsync(log);

        report.Clean.Should().BeTrue(report.Render());
        report.UnsignedTail.Should().Be(10);
        report.Render().Should().Contain("unsigned tail:  10 entries");
    }

    [Fact]
    public async Task Two_signed_roots_for_one_size_are_a_fork()
    {
        using var log = FakeLog.WithEntries(50, publishEvery: 50);
        var sth = log.Signer.Sign(new Core.TreeHeads.TreeHead(50, 9, new byte[32]));
        log.Heads.Add(new SignedHead(50, 9, sth.Head.RootHash, sth.KeyId, sth.Signature));

        var report = await AuditAsync(log);

        report.Findings.Should().Contain(f => f.Kind == FindingKind.ConflictingTreeHeads);
    }
}
