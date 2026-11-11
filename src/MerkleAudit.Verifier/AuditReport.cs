using System.Globalization;
using System.Text;

namespace MerkleAudit.Verifier;

public enum FindingKind
{
    /// <summary>A published tree head fails signature, key or format checks.</summary>
    InvalidTreeHead,

    /// <summary>A head this auditor verified earlier is gone from the log's history.</summary>
    WitnessedHeadMissing,

    /// <summary>Two validly signed heads disagree (same size, different root): the log forked.</summary>
    ConflictingTreeHeads,

    /// <summary>A signed head covers more leaves than the log now has.</summary>
    LogTruncated,

    /// <summary>The tree commits to a leaf at this index but the row is gone.</summary>
    RowDeleted,

    /// <summary>The row's content no longer hashes to the committed leaf.</summary>
    RowAltered,

    /// <summary>The row at this index is the entry committed at another index.</summary>
    RowMoved,

    /// <summary>A row exists that the tree never committed to.</summary>
    RowNotInTree,

    /// <summary>The stored tree has no leaf node for an index that has a row.</summary>
    StoredLeafMissing,

    /// <summary>The stored leaf hashes no longer reproduce a signed root: the tree itself was rewritten.</summary>
    StoredTreeRewritten,

    /// <summary>Recomputing from the rows first disagrees with the signed history inside this range.</summary>
    RowsDivergeFromSignedHistory,

    /// <summary>A server-built inclusion proof does not verify for an entry that is otherwise intact.</summary>
    InclusionProofFailed,

    /// <summary>A server-built consistency proof between two signed heads does not verify.</summary>
    ConsistencyProofFailed,

    /// <summary>More differences than are worth listing individually.</summary>
    TooManyDifferences,
}

public sealed record Finding(FindingKind Kind, long? Index, string Detail)
{
    public override string ToString() =>
        Index is { } i ? $"{Kind,-28} seq {i.ToString(CultureInfo.InvariantCulture),-8} {Detail}" : $"{Kind,-28} {"",-12} {Detail}";
}

public sealed record ProofCheck(string Proof, string Subject, bool Verified);

public sealed record AuditReport(
    SignedHead? LatestHead,
    long RowsRead,
    long StoredLeaves,
    int ValidHeads,
    bool StoredTreeAuthentic,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<ProofCheck> ProofChecks,
    long UnsignedTail)
{
    public bool Clean => Findings.Count == 0;

    /// <summary>A stable, human-readable report (the golden test compares it byte for byte).</summary>
    public string Render()
    {
        var sb = new StringBuilder();
        var inv = CultureInfo.InvariantCulture;
        sb.AppendLine(inv, $"verdict:        {(Clean ? "CLEAN" : "TAMPERING DETECTED")}");
        sb.AppendLine(inv, $"latest head:    {(LatestHead is null ? "none" : $"size {LatestHead.TreeSize}, root {Hex.Of(LatestHead.RootHash)}")}");
        sb.AppendLine(inv, $"signed heads:   {ValidHeads} valid");
        sb.AppendLine(inv, $"rows read:      {RowsRead}");
        sb.AppendLine(inv, $"stored leaves:  {StoredLeaves}");
        sb.AppendLine(inv, $"stored tree:    {(StoredTreeAuthentic ? "matches every signed head (findings are exact)" : "does NOT match the signed heads (findings are localised to a range)")}");
        if (UnsignedTail > 0)
        {
            sb.AppendLine(inv, $"unsigned tail:  {UnsignedTail} entries after the latest signed head (checked against stored leaves only)");
        }

        sb.AppendLine(inv, $"proof checks:   {ProofChecks.Count(p => p.Verified)}/{ProofChecks.Count} verified");
        foreach (var failed in ProofChecks.Where(p => !p.Verified))
        {
            sb.AppendLine(inv, $"  failed: {failed.Proof} {failed.Subject}");
        }

        sb.AppendLine(inv, $"findings:       {Findings.Count}");
        foreach (var finding in Findings)
        {
            sb.AppendLine(inv, $"  {finding}");
        }

        return sb.ToString();
    }
}
