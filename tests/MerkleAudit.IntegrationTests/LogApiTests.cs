using System.Net;
using System.Net.Http.Json;
using MerkleAudit.Core.Tree;
using MerkleAudit.IntegrationTests.Infrastructure;
using MerkleAudit.Server.Api;
using MerkleAudit.Verifier;

namespace MerkleAudit.IntegrationTests;

public sealed class LogApiTests(LogEnvironment env)
{
    private static object Entry(int n, string payload = "{}") => new
    {
        actor = $"user-{n % 3}",
        action = "record.read",
        resource = $"patient/{n}",
        payload = System.Text.Json.JsonDocument.Parse(payload).RootElement,
    };

    [Fact]
    public async Task Appends_get_contiguous_sequence_numbers_and_leaf_hashes_the_verifier_reproduces()
    {
        await using var log = await env.CreateLogAsync();

        var first = await log.AppendAsync(Entry(0));
        first.StatusCode.Should().Be(HttpStatusCode.Created);
        var batch = await log.AppendBatchAsync([Entry(1), Entry(2), Entry(3)]);
        batch.StatusCode.Should().Be(HttpStatusCode.OK);

        var appended = (await batch.Content.ReadFromJsonAsync<List<AppendResponse>>())!;
        appended.Select(a => a.Seq).Should().Equal(1, 2, 3);

        var entries = await log.Source.ReadEntriesAsync(CancellationToken.None).ToListAsync();
        entries.Select(e => e.Seq).Should().Equal(0, 1, 2, 3);
        entries.Skip(1).Select(e => Hex.Of(e.LeafHash())).Should().Equal(appended.Select(a => a.LeafHash),
            "the verifier's independent leaf encoding must match the server's");
    }

    [Fact]
    public async Task Payload_is_stored_byte_for_byte()
    {
        await using var log = await env.CreateLogAsync();
        const string payload = """{ "b": 1,   "a": [true, null],  "ü": "çğış" }""";

        // Raw body: a JSON serializer on the client would normalise the payload before the server ever saw it.
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/entries")
        {
            Content = new StringContent($$"""{"actor":"a","action":"b","resource":"c","payload":{{payload}}}""", System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Api-Key", LogEnvironment.ApiKey);
        (await log.Http.SendAsync(request)).EnsureSuccessStatusCode();

        var stored = await log.Source.ReadEntriesAsync(CancellationToken.None).SingleAsync();
        stored.Payload.Should().Be(payload, "jsonb would re-order keys and drop whitespace, changing the hash");
    }

    [Fact]
    public async Task Appending_requires_a_valid_api_key_and_a_valid_entry()
    {
        await using var log = await env.CreateLogAsync();

        (await log.AppendAsync(Entry(0), apiKey: null)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await log.AppendAsync(Entry(0), apiKey: "wrong")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await log.AppendAsync(new { actor = "", action = "a", resource = "r", payload = 1 })).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await log.AppendAsync(new { actor = "a", action = "a", resource = "r" })).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await log.AppendBatchAsync([])).StatusCode.Should().Be(HttpStatusCode.BadRequest);

        (await log.Store.GetTreeStateAsync(CancellationToken.None)).TreeSize.Should().Be(0, "rejected requests consume no sequence number");
    }

    [Fact]
    public async Task Root_matches_an_independent_replay_and_every_proof_verifies()
    {
        await using var log = await env.CreateLogAsync();
        for (var start = 0; start < 137; start += 17)
        {
            (await log.AppendBatchAsync([.. Enumerable.Range(start, Math.Min(17, 137 - start)).Select(n => Entry(n))])).EnsureSuccessStatusCode();
        }

        var head = await log.PublishAsync();
        log.Trust.Check(head).Should().BeNull();

        var replay = new StreamingRoot();
        var entries = await log.Source.ReadEntriesAsync(CancellationToken.None).ToListAsync();
        entries.ForEach(e => replay.Add(e.LeafHash()));
        replay.Root().Should().Equal(head.RootHash);

        // Every leaf, at the current size and at a historic size served from the same stored nodes.
        var historicSize = 100;
        var historicRoot = await new ProofBuilder(log.Store).RootAsync(historicSize, CancellationToken.None);
        foreach (var e in entries)
        {
            var proof = await log.Source.GetInclusionProofAsync(e.Seq, 137, CancellationToken.None);
            ProofVerifier.VerifyInclusion(e.Seq, 137, e.LeafHash(), proof, head.RootHash).Should().BeTrue($"seq {e.Seq}");
            if (e.Seq < historicSize)
            {
                var old = await log.Source.GetInclusionProofAsync(e.Seq, historicSize, CancellationToken.None);
                ProofVerifier.VerifyInclusion(e.Seq, historicSize, e.LeafHash(), old, historicRoot).Should().BeTrue($"seq {e.Seq} @ {historicSize}");
            }
        }

        for (var first = 0; first <= 137; first += 7)
        {
            var proof = await log.Source.GetConsistencyProofAsync(first, 137, CancellationToken.None);
            var firstRoot = await new ProofBuilder(log.Store).RootAsync(first, CancellationToken.None);
            ProofVerifier.VerifyConsistency(first, 137, proof, firstRoot, head.RootHash).Should().BeTrue($"{first} -> 137");
        }
    }

    [Fact]
    public async Task Proof_requests_outside_the_tree_are_rejected()
    {
        await using var log = await env.CreateLogAsync();
        (await log.AppendBatchAsync([Entry(0), Entry(1)])).EnsureSuccessStatusCode();

        (await log.Http.GetAsync(new Uri("api/v1/proofs/inclusion?leafIndex=2&treeSize=2", UriKind.Relative))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await log.Http.GetAsync(new Uri("api/v1/proofs/inclusion?leafIndex=0&treeSize=3", UriKind.Relative))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await log.Http.GetAsync(new Uri("api/v1/proofs/consistency?first=2&second=1", UriKind.Relative))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await log.Http.GetAsync(new Uri("api/v1/proofs/consistency?first=1&second=3", UriKind.Relative))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Tree_heads_are_signed_monotonic_and_published_only_when_the_tree_grows()
    {
        await using var log = await env.CreateLogAsync();
        (await log.Http.GetAsync(new Uri("api/v1/sth", UriKind.Relative))).StatusCode.Should().Be(HttpStatusCode.NotFound);

        (await log.Publisher.PublishAsync(force: false, CancellationToken.None)).Should().NotBeNull("the first head covers the empty tree");
        (await log.Publisher.PublishAsync(force: false, CancellationToken.None)).Should().BeNull("nothing changed");
        (await log.AppendAsync(Entry(0))).EnsureSuccessStatusCode();
        (await log.Publisher.PublishAsync(force: false, CancellationToken.None))!.Head.TreeSize.Should().Be(1);

        var heads = await log.Source.GetTreeHeadsAsync(CancellationToken.None);
        heads.Select(h => h.TreeSize).Should().Equal(0, 1);
        heads.Should().OnlyContain(h => log.Trust.Check(h) == null);
        heads[0].RootHash.Should().Equal(Rfc6962Hash.Empty());
        heads[1].TimestampMs.Should().BeGreaterThan(heads[0].TimestampMs);

        var keys = await log.Http.GetFromJsonAsync<KeyListResponse>("api/v1/keys");
        keys!.Keys.Should().ContainSingle(k => k.Status == "active" && k.KeyId == heads[0].KeyId);
    }

    [Fact]
    public async Task Auditor_reads_a_large_log_across_many_pages()
    {
        await using var log = await env.CreateLogAsync();
        for (var start = 0; start < 2500; start += 1000)
        {
            (await log.AppendBatchAsync([.. Enumerable.Range(start, Math.Min(1000, 2500 - start)).Select(n => Entry(n))])).EnsureSuccessStatusCode();
            await log.PublishAsync();
        }

        var report = await new LogAuditor(log.Source, log.Trust).AuditAsync(null, CancellationToken.None);

        report.Clean.Should().BeTrue(report.Render());
        report.RowsRead.Should().Be(2500);
        report.StoredLeaves.Should().Be(2500);
    }
}
