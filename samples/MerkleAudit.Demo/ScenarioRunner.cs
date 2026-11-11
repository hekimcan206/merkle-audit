using System.Text;
using MerkleAudit.Verifier;

namespace MerkleAudit.Demo;

public sealed record ScenarioResult(string Name, string Description, AuditReport Report, bool Detected, bool CleanAfterUndo);

/// <summary>
/// The tamper demo: for each attack, tamper in PostgreSQL directly, audit through the HTTP API with the independent
/// verifier, check the verdict names the right rows, undo, and check the log audits clean again.
/// Expects the seeded log of <see cref="DemoSeeder"/>: 200 entries with a signed head every 25.
/// </summary>
public sealed class ScenarioRunner(ILogSource source, TrustStore trust, Tamperer tamperer)
{
    public const int Entries = 200;
    public const int PublishEvery = 25;

    private sealed record Scenario(string Name, string Description, Func<Task<Tamperer.Undo?>> Tamper, Func<AuditReport, bool> Expected);

    public async Task<IReadOnlyList<ScenarioResult>> RunAsync(CancellationToken cancellationToken)
    {
        Scenario[] scenarios =
        [
            new("baseline", "untouched log", () => Task.FromResult<Tamperer.Undo?>(null),
                r => r.Clean),
            new("alter", "UPDATE payload of seq 115 to hide an emergency access", async () => await tamperer.AlterPayloadAsync(115, """{"ip":"10.20.3.246","reason":"treatment","n":115}"""),
                r => Only(r, FindingKind.RowAltered, 115) && r.StoredTreeAuthentic),
            new("delete", "DELETE seq 42", async () => await tamperer.DeleteAsync(42),
                r => Only(r, FindingKind.RowDeleted, 42) && r.StoredTreeAuthentic),
            new("reorder", "swap the content of seq 60 and 61", async () => await tamperer.SwapAsync(60, 61),
                r => r.Findings.Count == 2 && r.Findings.All(f => f.Kind == FindingKind.RowMoved) && r.Findings.Select(f => f.Index).SequenceEqual([60L, 61L])),
            new("insert", "INSERT a forged, back-dated consent as seq 200", async () => await tamperer.InsertForgedAsync(
                    200, "dr.ayse.k", "consent.update", "patient/P-000042", """{"consent":"granted"}""", new DateTime(2026, 1, 2, 9, 0, 0, DateTimeKind.Utc)),
                r => Only(r, FindingKind.RowNotInTree, 200)),
            new("rewrite", "change seq 160's actor AND recompute its leaf, ancestors and tree_state", async () => await tamperer.RewriteRowAndTreeAsync(160, "clerk.burak.a"),
                r => !r.StoredTreeAuthentic
                     && r.Findings.Any(f => f.Kind == FindingKind.StoredTreeRewritten && f.Detail.Contains("seq [150, 174]", StringComparison.Ordinal))
                     && r.Findings.Any(f => f.Kind == FindingKind.RowsDivergeFromSignedHistory && f.Detail.Contains("seq [150, 174]", StringComparison.Ordinal))),
        ];

        var results = new List<ScenarioResult>();
        var auditor = new LogAuditor(source, trust);
        foreach (var scenario in scenarios)
        {
            var undo = await scenario.Tamper();
            var report = await auditor.AuditAsync(null, cancellationToken);
            var cleanAfter = true;
            if (undo is not null)
            {
                await undo();
                cleanAfter = (await auditor.AuditAsync(null, cancellationToken)).Clean;
            }

            results.Add(new ScenarioResult(scenario.Name, scenario.Description, report, scenario.Expected(report), cleanAfter));
        }

        return results;
    }

    /// <summary>The report the demo prints and the golden file stores.</summary>
    public static string Render(IReadOnlyList<ScenarioResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var sb = new StringBuilder();
        foreach (var result in results)
        {
            sb.Append("=== scenario ").Append(result.Name).Append(": ").AppendLine(result.Description);
            sb.Append(result.Report.Render());
            sb.Append("expected verdict: ").AppendLine(result.Detected ? "yes" : "NO");
            sb.Append("clean after undo: ").AppendLine(result.CleanAfterUndo ? "yes" : "NO");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static bool Only(AuditReport report, FindingKind kind, long index) =>
        report.Findings is [var f] && f.Kind == kind && f.Index == index;
}
