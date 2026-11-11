using System.Globalization;

namespace MerkleAudit.Verifier;

/// <summary>
/// Full audit of a log: verifies every published tree head, replays every row, and explains each difference.
/// <para>
/// The trust argument, in order: (1) tree heads are trusted only if signed by a pinned key; (2) the stored leaf hashes
/// are trusted only if they reproduce the signed roots; (3) rows are trusted only if they hash to those leaves.
/// When (2) holds, every row-level difference is exact: the tree still remembers the original leaf, so the auditor can
/// say which row changed and how. When (2) fails, someone rewrote the tree too, and the auditor localises the change
/// to the interval between the last signed head that still matches and the first that does not.
/// </para>
/// </summary>
public sealed class LogAuditor(ILogSource source, TrustStore trust)
{
    private const int MaxClassified = 256;
    private const int MaxProofChecks = 16;
    private const int MaxConsistencyChecks = 64;
    private static readonly byte[] Absent = new byte[Rfc6962Hash.Size];

    public async Task<AuditReport> AuditAsync(IReadOnlyList<SignedHead>? witnessed = null, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        var proofChecks = new List<ProofCheck>();

        // 1. Signed heads: the only things trusted without recomputation, and only after the signature check.
        var published = await source.GetTreeHeadsAsync(cancellationToken);
        var valid = new List<SignedHead>();
        foreach (var head in published)
        {
            var problem = trust.Check(head);
            if (problem is null)
            {
                valid.Add(head);
            }
            else
            {
                findings.Add(new(FindingKind.InvalidTreeHead, null, $"tree head size {head.TreeSize}: {problem}"));
            }
        }

        foreach (var head in witnessed ?? [])
        {
            if (trust.Check(head) is not null)
            {
                continue;
            }

            if (!valid.Any(v => v.TreeSize == head.TreeSize && v.RootHash.AsSpan().SequenceEqual(head.RootHash)))
            {
                findings.Add(new(FindingKind.WitnessedHeadMissing, null, $"previously verified head size {head.TreeSize} root {Hex.Prefix(head.RootHash)} is no longer published"));
                valid.Add(head);
            }
        }

        var anchors = valid
            .GroupBy(h => h.TreeSize)
            .OrderBy(g => g.Key)
            .Select(g => (Size: g.Key, Roots: g.Select(h => h.RootHash).DistinctBy(Hex.Of).ToList()))
            .ToList();
        foreach (var anchor in anchors.Where(a => a.Roots.Count > 1))
        {
            findings.Add(new(FindingKind.ConflictingTreeHeads, null, $"{anchor.Roots.Count} different signed roots for size {anchor.Size}"));
        }

        // 2-3. Replay: stream stored leaves and rows in index order, keep two running roots, compare at every anchor.
        var storedRoot = new StreamingRoot();
        var rowRoot = new StreamingRoot();
        var storedOk = new Dictionary<long, bool>();
        var rowsOk = new Dictionary<long, bool>();
        var mismatched = new List<(long Index, EntryRecord Row, byte[] Stored)>();
        var deleted = new List<(long Index, byte[] Stored)>();
        var rowsWithoutLeaf = new List<EntryRecord>();
        // Rows needed for proof checks are captured during the single replay pass: the newest signed head is known
        // up front, so its sample positions are too; flagged rows are kept as they are found.
        var newest = valid.MaxBy(v => (v.TreeSize, v.TimestampMs));
        var samplePositions = newest is { TreeSize: > 0 } ? new HashSet<long> { 0, newest.TreeSize / 2, newest.TreeSize - 1 } : [];
        var capturedRows = new Dictionary<long, EntryRecord>();
        long rowsRead = 0;
        long storedLeaves = 0;
        var anchorPos = 0;
        CheckAnchors(0);

        await using var leaves = source.ReadLeafHashesAsync(cancellationToken).GetAsyncEnumerator(cancellationToken);
        await using var rows = source.ReadEntriesAsync(cancellationToken).GetAsyncEnumerator(cancellationToken);
        var hasLeaf = await leaves.MoveNextAsync();
        var hasRow = await rows.MoveNextAsync();
        long index = 0;
        while (hasLeaf || hasRow)
        {
            byte[]? stored = null;
            if (hasLeaf && leaves.Current.Index == index)
            {
                stored = leaves.Current.Hash;
                storedLeaves++;
                hasLeaf = await leaves.MoveNextAsync();
            }

            EntryRecord? row = null;
            while (hasRow && rows.Current.Seq < index)
            {
                // Only possible for a negative sequence number: a row inserted outside the log's own numbering.
                rowsRead++;
                rowsWithoutLeaf.Add(rows.Current);
                hasRow = await rows.MoveNextAsync();
            }

            if (hasRow && rows.Current.Seq == index)
            {
                row = rows.Current;
                rowsRead++;
                hasRow = await rows.MoveNextAsync();
            }

            var recomputed = row?.LeafHash();
            if (stored is not null)
            {
                storedRoot.Add(stored);
                rowRoot.Add(recomputed ?? Absent);
                if (row is null)
                {
                    deleted.Add((index, stored));
                }
                else if (!recomputed!.AsSpan().SequenceEqual(stored))
                {
                    mismatched.Add((index, row, stored));
                    capturedRows[index] = row;
                }

                if (row is not null && samplePositions.Contains(index))
                {
                    capturedRows[index] = row;
                }
            }
            else if (row is not null)
            {
                rowsWithoutLeaf.Add(row);
            }

            index++;
            if (stored is not null)
            {
                CheckAnchors(storedRoot.Count);
            }
        }

        // Anchors the replay never reached: a signed head promised more leaves than the log has now.
        foreach (var anchor in anchors.Skip(anchorPos))
        {
            storedOk[anchor.Size] = false;
            rowsOk[anchor.Size] = false;
            findings.Add(new(FindingKind.LogTruncated, null, $"signed head covers {anchor.Size} leaves but the stored tree has {storedRoot.Count}"));
        }

        var storedTreeAuthentic = anchors.All(a => storedOk.GetValueOrDefault(a.Size));
        var latest = newest is not null && newest.TreeSize <= storedRoot.Count
            ? newest
            : valid.Where(v => v.TreeSize <= storedRoot.Count).MaxBy(v => (v.TreeSize, v.TimestampMs));

        ClassifyRowFindings(findings, mismatched, deleted, rowsWithoutLeaf, storedRoot.Count, storedTreeAuthentic);

        if (!storedTreeAuthentic)
        {
            AddInterval(findings, anchors.Select(a => a.Size).ToList(), storedOk, FindingKind.StoredTreeRewritten, "stored leaf hashes stop reproducing the signed root");
            AddInterval(findings, anchors.Select(a => a.Size).ToList(), rowsOk, FindingKind.RowsDivergeFromSignedHistory, "rows stop reproducing the signed root");
        }

        // 4. Exercise the log's proof API the way a client would: inclusion of sampled and flagged entries, and
        //    consistency between consecutive signed heads. Proofs come from internal nodes, which the replay above
        //    never reads, so this also catches tampering with interior nodes alone.
        var flagged = findings.Where(f => f.Index is not null).Select(f => f.Index!.Value).ToHashSet();
        if (latest is not null && latest.TreeSize > 0 && latest.TreeSize <= storedRoot.Count)
        {
            var targets = new SortedSet<long>(samplePositions.Where(p => p < latest.TreeSize));
            foreach (var i in flagged.Where(i => i < latest.TreeSize).Order().Take(MaxProofChecks))
            {
                targets.Add(i);
            }

            foreach (var row in targets.Where(capturedRows.ContainsKey).Select(t => capturedRows[t]))
            {
                var ok = await TryAsync(async () =>
                {
                    var proof = await source.GetInclusionProofAsync(row.Seq, latest.TreeSize, cancellationToken);
                    return ProofVerifier.VerifyInclusion(row.Seq, latest.TreeSize, row.LeafHash(), proof, latest.RootHash);
                });
                proofChecks.Add(new("inclusion", $"seq {row.Seq} in size {latest.TreeSize}", ok));
                if (!ok && !flagged.Contains(row.Seq))
                {
                    findings.Add(new(FindingKind.InclusionProofFailed, row.Seq, $"intact row is not provable against the signed head of size {latest.TreeSize}"));
                }
            }

            var distinct = valid.Where(v => v.TreeSize <= storedRoot.Count).GroupBy(v => v.TreeSize).OrderBy(g => g.Key).Select(g => g.First()).ToList();
            foreach (var (first, second) in distinct.Zip(distinct.Skip(1)).TakeLast(MaxConsistencyChecks))
            {
                var ok = await TryAsync(async () =>
                {
                    var proof = await source.GetConsistencyProofAsync(first.TreeSize, second.TreeSize, cancellationToken);
                    return ProofVerifier.VerifyConsistency(first.TreeSize, second.TreeSize, proof, first.RootHash, second.RootHash);
                });
                proofChecks.Add(new("consistency", $"{first.TreeSize} -> {second.TreeSize}", ok));
                if (!ok)
                {
                    findings.Add(new(FindingKind.ConsistencyProofFailed, null, $"log cannot prove size {second.TreeSize} extends size {first.TreeSize}"));
                }
            }
        }

        var unsignedTail = latest is null ? storedRoot.Count : Math.Max(0, storedRoot.Count - latest.TreeSize);
        return new AuditReport(latest, rowsRead, storedLeaves, valid.Count, storedTreeAuthentic, findings, proofChecks, unsignedTail);

        void CheckAnchors(long size)
        {
            while (anchorPos < anchors.Count && anchors[anchorPos].Size <= size)
            {
                var anchor = anchors[anchorPos++];
                if (anchor.Size < size)
                {
                    continue;
                }

                var s = storedRoot.Root();
                var r = rowRoot.Root();
                storedOk[anchor.Size] = anchor.Roots.Count == 1 && anchor.Roots[0].AsSpan().SequenceEqual(s);
                rowsOk[anchor.Size] = anchor.Roots.Count == 1 && anchor.Roots[0].AsSpan().SequenceEqual(r);
            }
        }
    }

    private static void ClassifyRowFindings(
        List<Finding> findings,
        List<(long Index, EntryRecord Row, byte[] Stored)> mismatched,
        List<(long Index, byte[] Stored)> deleted,
        List<EntryRecord> rowsWithoutLeaf,
        long storedCount,
        bool storedTreeAuthentic)
    {
        var qualifier = storedTreeAuthentic ? "" : " (stored hashes unauthenticated)";
        var total = mismatched.Count + deleted.Count;
        if (total > MaxClassified)
        {
            var first = mismatched.Select(m => m.Index).Concat(deleted.Select(d => d.Index)).Min();
            findings.Add(new(FindingKind.TooManyDifferences, first, $"{total} rows differ from the committed leaves, starting here{qualifier}"));
        }
        else
        {
            // A moved row hashes to another index's committed leaf once its sequence number is put back.
            var committed = mismatched.Select(m => (m.Index, m.Stored)).Concat(deleted).ToList();
            var movedOrigins = new HashSet<long>();
            foreach (var (index, row, stored) in mismatched)
            {
                var origin = committed.FirstOrDefault(c => c.Index != index && row.LeafHash(c.Index).AsSpan().SequenceEqual(c.Stored));
                if (origin.Stored is not null)
                {
                    movedOrigins.Add(origin.Index);
                    findings.Add(new(FindingKind.RowMoved, index, $"row holds the entry committed at seq {origin.Index.ToString(CultureInfo.InvariantCulture)}{qualifier}"));
                }
                else
                {
                    findings.Add(new(FindingKind.RowAltered, index, $"leaf {Hex.Prefix(row.LeafHash())} != committed {Hex.Prefix(stored)}{qualifier}"));
                }
            }

            // A slot that now holds a moved row lost its own entry, unless that entry was itself moved elsewhere.
            foreach (var (index, _, stored) in mismatched)
            {
                if (!movedOrigins.Contains(index) && findings.Any(f => f.Kind == FindingKind.RowMoved && f.Index == index))
                {
                    findings.Add(new(FindingKind.RowDeleted, index, $"committed leaf {Hex.Prefix(stored)} appears in no row (this slot holds a moved row){qualifier}"));
                }
            }

            foreach (var (index, stored) in deleted)
            {
                // A deleted index whose entry reappears elsewhere was moved, not lost; the move finding covers it.
                if (!movedOrigins.Contains(index))
                {
                    findings.Add(new(FindingKind.RowDeleted, index, $"committed leaf {Hex.Prefix(stored)} has no row{qualifier}"));
                }
            }
        }

        foreach (var row in rowsWithoutLeaf)
        {
            findings.Add(row.Seq >= storedCount
                ? new(FindingKind.RowNotInTree, row.Seq, "row was never committed to the tree")
                : new(FindingKind.StoredLeafMissing, row.Seq, "stored tree has no leaf node for this row"));
        }

        // Stable order (head-level findings first, then by sequence number) keeps reports diffable.
        var ordered = findings.OrderBy(f => f.Index ?? -1).ToList();
        findings.Clear();
        findings.AddRange(ordered);
    }

    private static void AddInterval(List<Finding> findings, List<long> sizes, Dictionary<long, bool> ok, FindingKind kind, string what)
    {
        long lastGood = 0;
        foreach (var size in sizes)
        {
            if (ok.GetValueOrDefault(size))
            {
                lastGood = size;
                continue;
            }

            findings.Add(new(kind, null, $"{what} between size {lastGood} and size {size}: first divergence is in seq [{lastGood}, {size - 1}]"));
            return;
        }
    }

    private static async Task<bool> TryAsync(Func<Task<bool>> check)
    {
        try
        {
            return await check();
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
