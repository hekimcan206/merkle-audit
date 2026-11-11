using MerkleAudit.Demo;
using MerkleAudit.IntegrationTests.Infrastructure;

namespace MerkleAudit.IntegrationTests;

/// <summary>
/// The golden tamper demo, against real PostgreSQL: the same seeded log and the same attacks the compose demo runs.
/// With a deterministic clock, every leaf and root hash is reproducible, so the whole report is compared byte for
/// byte with <c>Golden/tamper-report.txt</c>. Set UPDATE_GOLDEN=1 to regenerate it, then review the diff like code.
/// </summary>
public sealed class TamperGoldenTests(LogEnvironment env)
{
    [Fact]
    public async Task Every_attack_is_detected_pinpointed_and_matches_the_golden_report()
    {
        await using var log = await env.CreateLogAsync(new SteppingTimeProvider());
        await DemoSeeder.SeedAsync(log.Http, LogEnvironment.ApiKey, ScenarioRunner.Entries, ScenarioRunner.PublishEvery,
            async _ => await log.PublishAsync(), CancellationToken.None);

        var results = await new ScenarioRunner(log.Source, log.Trust, new Tamperer(log.Superuser)).RunAsync(CancellationToken.None);
        var report = ScenarioRunner.Render(results);

        results.Should().OnlyContain(r => r.Detected && r.CleanAfterUndo, report);

        var golden = Path.Combine(GoldenDirectory(), "tamper-report.txt");
        if (Environment.GetEnvironmentVariable("UPDATE_GOLDEN") == "1")
        {
            await File.WriteAllTextAsync(golden, report);
        }

        (await File.ReadAllTextAsync(golden)).ReplaceLineEndings("\n").Should().Be(report.ReplaceLineEndings("\n"));
    }

    private static string GoldenDirectory()
    {
        // The source tree, not bin/: regenerating must update the committed file.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MerkleAudit.IntegrationTests.csproj")))
        {
            dir = dir.Parent;
        }

        return Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("Test project directory not found."), "Golden");
    }
}
