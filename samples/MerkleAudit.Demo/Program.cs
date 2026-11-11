using System.Text.Json;
using MerkleAudit.Demo;
using MerkleAudit.Verifier;
using Npgsql;

// The `docker compose up` tamper demo:
//   1. seed 200 synthetic entries through the API, one signed head per 25 (skipped if the log already has them);
//   2. run each attack directly in PostgreSQL as the superuser, audit with the independent verifier, undo;
//   3. print every report and a one-line JSON summary; exit 0 only if every attack was detected and undone cleanly.
var logUrl = Environment.GetEnvironmentVariable("LOG_URL") ?? "http://localhost:58780/";
var apiKey = Environment.GetEnvironmentVariable("APPEND_API_KEY") ?? "append-dev-only";
var superuser = Environment.GetEnvironmentVariable("PG_SUPERUSER") ?? throw new InvalidOperationException("PG_SUPERUSER is required (the rogue DBA's connection string).");
var keyDirectory = Environment.GetEnvironmentVariable("TRUSTED_KEYS_DIR") ?? "/keys/trusted";

using var http = new HttpClient { BaseAddress = new Uri(logUrl), Timeout = TimeSpan.FromSeconds(60) };
await WaitForServerAsync(http);

// Trust comes from the key volume (out of band), never from the log's own /keys endpoint.
using var trust = new TrustStore();
foreach (var file in Directory.GetFiles(keyDirectory, "*.pub.pem"))
{
    Console.WriteLine($"trusting tree-head key {trust.AddPem(await File.ReadAllTextAsync(file)).KeyId}");
}

var source = new HttpLogSource(http);
var existing = await source.GetLatestTreeHeadAsync(CancellationToken.None);
if (existing is null || existing.TreeSize < ScenarioRunner.Entries)
{
    Console.WriteLine($"seeding {ScenarioRunner.Entries} entries, a signed head every {ScenarioRunner.PublishEvery} ...");
    await DemoSeeder.SeedAsync(http, apiKey, ScenarioRunner.Entries, ScenarioRunner.PublishEvery,
        size => DemoSeeder.WaitForHeadAsync(http, size, CancellationToken.None), CancellationToken.None);
}

await using var dataSource = NpgsqlDataSource.Create(superuser);
var results = await new ScenarioRunner(source, trust, new Tamperer(dataSource)).RunAsync(CancellationToken.None);
Console.WriteLine();
Console.Write(ScenarioRunner.Render(results));

var failures = results.Where(r => !r.Detected || !r.CleanAfterUndo).Select(r => r.Name).ToList();
Console.WriteLine(JsonSerializer.Serialize(new
{
    scenarios = results.Count,
    detected = results.Count(r => r.Detected),
    cleanAfterUndo = results.Count(r => r.CleanAfterUndo),
    failures,
}));
return failures.Count == 0 ? 0 : 1;

static async Task WaitForServerAsync(HttpClient http)
{
    for (var attempt = 0; ; attempt++)
    {
        try
        {
            using var response = await http.GetAsync(new Uri("health/ready", UriKind.Relative));
            if (response.IsSuccessStatusCode)
            {
                return;
            }
        }
        catch (HttpRequestException) when (attempt < 60)
        {
        }

        if (attempt >= 60)
        {
            throw new TimeoutException("The log server did not become ready.");
        }

        await Task.Delay(1000);
    }
}
