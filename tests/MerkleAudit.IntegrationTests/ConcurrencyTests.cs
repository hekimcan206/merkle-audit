using System.Net.Http.Json;
using MerkleAudit.IntegrationTests.Infrastructure;
using MerkleAudit.Server.Api;
using MerkleAudit.Verifier;

namespace MerkleAudit.IntegrationTests;

/// <summary>
/// The tree is a sequence, so concurrency is about serialising writers without losing or duplicating a position:
/// many clients on one server (group commit), and two servers on one database (the tree_state row lock).
/// </summary>
public sealed class ConcurrencyTests(LogEnvironment env)
{
    private static object Entry(int client, int n) => new { actor = $"client-{client}", action = "record.read", resource = $"r/{n}", payload = n };

    [Fact]
    public async Task Concurrent_single_appends_are_group_committed_without_gaps_or_duplicates()
    {
        await using var log = await env.CreateLogAsync();
        const int clients = 32;
        const int perClient = 25;

        var seqs = await Task.WhenAll(Enumerable.Range(0, clients).Select(async c =>
        {
            var mine = new List<long>();
            for (var n = 0; n < perClient; n++)
            {
                var response = await log.AppendAsync(Entry(c, n));
                response.EnsureSuccessStatusCode();
                mine.Add((await response.Content.ReadFromJsonAsync<AppendResponse>())!.Seq);
            }

            return mine;
        }));

        seqs.SelectMany(s => s).Order().Should().Equal(Enumerable.Range(0, clients * perClient).Select(i => (long)i));
        seqs.Should().OnlyContain(s => s.SequenceEqual(s.Order()), "each client's own appends keep their order");

        await log.PublishAsync();
        var report = await new LogAuditor(log.Source, log.Trust).AuditAsync(null, CancellationToken.None);
        report.Clean.Should().BeTrue(report.Render());
    }

    [Fact]
    public async Task Two_server_instances_on_one_database_extend_the_same_tree()
    {
        await using var log = await env.CreateLogAsync();
        await using var second = log.Factory.WithWebHostBuilder(b => b.UseSetting("Log:MaxGroupCommit", "7"));
        using var secondHttp = second.CreateClient();

        async Task AppendManyAsync(HttpClient http, int client)
        {
            for (var n = 0; n < 60; n++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/entries") { Content = JsonContent.Create(Entry(client, n)) };
                request.Headers.Add("X-Api-Key", LogEnvironment.ApiKey);
                (await http.SendAsync(request)).EnsureSuccessStatusCode();
            }
        }

        await Task.WhenAll(
            Enumerable.Range(0, 4).Select(c => AppendManyAsync(log.Http, c))
                .Concat(Enumerable.Range(4, 4).Select(c => AppendManyAsync(secondHttp, c))));

        (await log.Store.GetTreeStateAsync(CancellationToken.None)).TreeSize.Should().Be(480);
        await log.PublishAsync();
        var report = await new LogAuditor(log.Source, log.Trust).AuditAsync(null, CancellationToken.None);
        report.Clean.Should().BeTrue(report.Render());
        report.RowsRead.Should().Be(480);
    }
}
