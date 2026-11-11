using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using MerkleAudit.Core.Tree;
using MerkleAudit.Server.Log;
using MerkleAudit.Server.Persistence;
using MerkleAudit.Verifier;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Testcontainers.PostgreSql;

namespace MerkleAudit.Benchmarks;

/// <summary>
/// End-to-end measurements against a real PostgreSQL 17 (Testcontainers, default durability settings: fsync on,
/// synchronous_commit on). Uses the server's own LogStore and group-commit writer, so the numbers are for the code
/// path the API runs, minus HTTP. Results go to stdout and benchmark-results/*.json.
/// </summary>
internal sealed class PostgresHarness : IAsyncDisposable
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("merkleaudit")
        .WithEnvironment("MIGRATOR_PASSWORD", "migrator-bench")
        .WithEnvironment("APP_PASSWORD", "app-bench")
        .WithEnvironment("READER_PASSWORD", "reader-bench")
        .WithResourceMapping(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "postgres-init", "01-roles.sh")), "/docker-entrypoint-initdb.d/01-roles.sh")
        .Build();

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
    private int _databases;
    private readonly string _output;

    public PostgresHarness(string output) => _output = output;

    public async Task StartAsync()
    {
        await _postgres.StartAsync();
        await using (var ds = PersistenceExtensions.CreateDataSource(Cs("merkleaudit", "audit_migrator", "migrator-bench")))
        {
            await new MigrationRunner(ds, NullLogger<MigrationRunner>.Instance).MigrateAsync();
        }

        NpgsqlConnection.ClearAllPools();
    }

    // BENCH_WRITE_BUFFER=8192 reproduces Npgsql's default buffer for the before/after comparison; otherwise the
    // server's own data-source settings apply.
    private string Cs(string db, string user, string password) => CsCore(db, user, password) + (System.Environment.GetEnvironmentVariable("BENCH_WRITE_BUFFER") is { } wb ? $";Write Buffer Size={wb}" : "");

    private string CsCore(string db, string user, string password) => new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
    {
        Database = db,
        Username = user,
        Password = password,
        MaxPoolSize = 80,
        Timeout = 60,
        CommandTimeout = 600,
    }.ConnectionString;

    private async Task<(NpgsqlDataSource DataSource, LogStore Store)> FreshLogAsync()
    {
        var name = $"bench_{Interlocked.Increment(ref _databases)}";
        await using (var admin = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString()) { Database = "postgres" }.ConnectionString))
        await using (var cmd = admin.CreateCommand($"CREATE DATABASE {name} TEMPLATE merkleaudit"))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        var ds = PersistenceExtensions.CreateDataSource(Cs(name, "audit_app", "app-bench"));
        return (ds, new LogStore(ds, TimeProvider.System, new LogMetrics()));
    }

    private static NewEntry Entry(long n) => new(
        $"user-{n % 50}",
        n % 3 == 0 ? "record.read" : "record.update",
        $"patient/P-{n % 100_000:D6}",
        $$"""{"ip":"10.20.{{n % 7}}.{{n % 250}}","reason":"treatment","n":{{n}}}""");

    /// <summary>Append throughput: one transaction per entry, group commit under concurrency, explicit batches.</summary>
    public async Task<object> AppendThroughputAsync()
    {
        var results = new List<object>();

        // 1. One client, one entry per transaction: the latency floor of a durable commit.
        {
            var (ds, store) = await FreshLogAsync();
            await using var _ = ds;
            await WarmUpAsync(store);
            var latencies = new List<double>();
            const int count = 2000;
            var total = Stopwatch.StartNew();
            for (var i = 0; i < count; i++)
            {
                var sw = Stopwatch.StartNew();
                await store.AppendAsync([Entry(i)], CancellationToken.None);
                latencies.Add(sw.Elapsed.TotalMilliseconds);
            }

            results.Add(Row("single, 1 client, 1 entry/tx", count, total.Elapsed, latencies));
        }

        // 2. Many clients, single-entry requests, through the group-commit writer the API uses.
        foreach (var clients in new[] { 16, 64 })
        {
            var (ds, store) = await FreshLogAsync();
            await using var _ = ds;
            await WarmUpAsync(store);
            using var writer = new GroupCommitWriter(store, Options.Create(new LogOptions()), NullLogger<GroupCommitWriter>.Instance);
            await writer.StartAsync(CancellationToken.None);
            const int perClient = 250;
            var latencies = new System.Collections.Concurrent.ConcurrentBag<double>();
            var total = Stopwatch.StartNew();
            await Task.WhenAll(Enumerable.Range(0, clients).Select(async c =>
            {
                for (var i = 0; i < perClient; i++)
                {
                    var sw = Stopwatch.StartNew();
                    await writer.AppendAsync([Entry((c * perClient) + i)], CancellationToken.None);
                    latencies.Add(sw.Elapsed.TotalMilliseconds);
                }
            }));
            var elapsed = total.Elapsed;
            await writer.StopAsync(CancellationToken.None);
            results.Add(Row($"group commit, {clients} clients, 1 entry/request", clients * perClient, elapsed, [.. latencies]));
        }

        // 3. Explicit batches (POST /entries/batch): one transaction per batch.
        foreach (var batch in new[] { 10, 100, 1000 })
        {
            var (ds, store) = await FreshLogAsync();
            await using var _ = ds;
            await WarmUpAsync(store);
            var count = batch * Math.Max(20, 20_000 / batch);
            var latencies = new List<double>();
            var total = Stopwatch.StartNew();
            for (var i = 0; i < count; i += batch)
            {
                var sw = Stopwatch.StartNew();
                await store.AppendAsync([.. Enumerable.Range(i, batch).Select(n => Entry(n))], CancellationToken.None);
                latencies.Add(sw.Elapsed.TotalMilliseconds);
            }

            results.Add(Row($"batch of {batch}, 1 client", count, total.Elapsed, latencies));
        }

        return Save("append-throughput", results);

        static object Row(string mode, int entries, TimeSpan elapsed, IReadOnlyList<double> latencies) => new
        {
            mode,
            entries,
            seconds = Math.Round(elapsed.TotalSeconds, 2),
            entriesPerSecond = Math.Round(entries / elapsed.TotalSeconds),
            latencyMsP50 = Percentile(latencies, 0.50),
            latencyMsP95 = Percentile(latencies, 0.95),
            latencyMsP99 = Percentile(latencies, 0.99),
        };
    }

    /// <summary>
    /// Grows one log to <paramref name="target"/> leaves in batches of 1000 and, at each checkpoint, measures inclusion
    /// and consistency proof generation (plan + one SQL round trip + fold) while the tables really have that size.
    /// Then audits the whole log with the independent verifier straight from the store (no HTTP).
    /// </summary>
    public async Task<object> ProofLatencyAsync(long target)
    {
        var (ds, store) = await FreshLogAsync();
        await using var _ = ds;
        var checkpoints = new[] { 1_000L, 10_000, 100_000, 1_000_000, 2_000_000, 5_000_000 }.Where(c => c <= target).ToList();
        var proofs = new ProofBuilder(store);
        var rows = new List<object>();
        var load = Stopwatch.StartNew();
        var random = new Random(42);
        long size = 0;
        foreach (var checkpoint in checkpoints)
        {
            while (size < checkpoint)
            {
                var n = (int)Math.Min(1000, checkpoint - size);
                await store.AppendAsync([.. Enumerable.Range(0, n).Select(i => Entry(size + i))], CancellationToken.None);
                size += n;
            }

            Console.WriteLine($"  tree size {size:N0} reached after {load.Elapsed.TotalSeconds:F0} s");
            for (var i = 0; i < 50; i++)
            {
                await proofs.InclusionProofAsync(random.NextInt64(size), size);
            }

            var inclusion = new List<double>();
            for (var i = 0; i < 500; i++)
            {
                var sw = Stopwatch.StartNew();
                await proofs.InclusionProofAsync(random.NextInt64(size), size);
                inclusion.Add(sw.Elapsed.TotalMilliseconds);
            }

            var consistency = new List<double>();
            for (var i = 0; i < 300; i++)
            {
                var first = 1 + random.NextInt64(size - 1);
                var sw = Stopwatch.StartNew();
                await proofs.ConsistencyProofAsync(first, size);
                consistency.Add(sw.Elapsed.TotalMilliseconds);
            }

            var proofLength = (await proofs.InclusionProofAsync(size / 3, size)).Count;
            rows.Add(new
            {
                treeSize = size,
                inclusionMsP50 = Percentile(inclusion, 0.50),
                inclusionMsP95 = Percentile(inclusion, 0.95),
                inclusionMsP99 = Percentile(inclusion, 0.99),
                consistencyMsP50 = Percentile(consistency, 0.50),
                consistencyMsP95 = Percentile(consistency, 0.95),
                inclusionProofHashes = proofLength,
                loadSecondsSoFar = Math.Round(load.Elapsed.TotalSeconds, 1),
            });
        }

        var loadSeconds = load.Elapsed.TotalSeconds;
        string tableSize;
        await using (var cmd = ds.CreateCommand(
            "SELECT pg_size_pretty(pg_total_relation_size('audit.entries')) || ' entries, ' || pg_size_pretty(pg_total_relation_size('audit.tree_nodes')) || ' tree_nodes'"))
        {
            tableSize = (string)(await cmd.ExecuteScalarAsync())!;
        }

        // Full independent audit of the whole log: every row re-encoded and hashed, every root recomputed.
        var state = await store.GetTreeStateAsync(CancellationToken.None);
        var signer = Core.TreeHeads.TreeHeadSigner.Generate();
        var head = signer.Sign(new Core.TreeHeads.TreeHead(state.TreeSize, 1, state.RootHash));
        using var trust = new TrustStore();
        trust.AddPem(signer.PublicKeyPem);
        var source = new StoreSource(store, [new SignedHead(head.Head.TreeSize, 1, head.Head.RootHash, head.KeyId, head.Signature)]);
        var audit = Stopwatch.StartNew();
        var report = await new LogAuditor(source, trust).AuditAsync(null, CancellationToken.None);
        var auditSeconds = audit.Elapsed.TotalSeconds;
        signer.Dispose();

        return Save("proof-latency", new
        {
            checkpoints = rows,
            loadSeconds = Math.Round(loadSeconds, 1),
            loadEntriesPerSecondInclCheckpointMeasurements = Math.Round(size / loadSeconds),
            tableSize,
            fullAudit = new { rows = report.RowsRead, clean = report.Clean, seconds = Math.Round(auditSeconds, 1), rowsPerSecond = Math.Round(report.RowsRead / auditSeconds) },
        });
    }

    private static async Task WarmUpAsync(LogStore store)
    {
        for (var i = 0; i < 20; i++)
        {
            await store.AppendAsync([Entry(-1 - i)], CancellationToken.None);
        }
    }

    private static double Percentile(IReadOnlyList<double> values, double p)
    {
        var sorted = values.Order().ToArray();
        var rank = (int)Math.Ceiling(p * sorted.Length) - 1;
        return Math.Round(sorted[Math.Clamp(rank, 0, sorted.Length - 1)], 3);
    }

    private object Save(string name, object result)
    {
        Directory.CreateDirectory(_output);
        var json = JsonSerializer.Serialize(result, Indented);
        File.WriteAllText(Path.Combine(_output, name + (System.Environment.GetEnvironmentVariable("BENCH_TAG") is { } tag ? "-" + tag : "") + ".json"), json);
        Console.WriteLine(json);
        return result;
    }

    public async ValueTask DisposeAsync() => await _postgres.DisposeAsync();

    /// <summary>The auditor reading straight from the store: measures verification work, not HTTP.</summary>
    private sealed class StoreSource(LogStore store, IReadOnlyList<SignedHead> heads) : ILogSource
    {
        public Task<IReadOnlyList<SignedHead>> GetTreeHeadsAsync(CancellationToken cancellationToken) => Task.FromResult(heads);

        public async IAsyncEnumerable<EntryRecord> ReadEntriesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            long after = -1;
            while (true)
            {
                var page = await store.GetEntriesAsync(after, 5000, cancellationToken);
                foreach (var e in page)
                {
                    yield return new EntryRecord(e.Seq, Core.Entries.LeafCodec.ToUnixMicroseconds(e.OccurredAt), e.Actor, e.Action, e.Resource, e.Payload);
                    after = e.Seq;
                }

                if (page.Count < 5000)
                {
                    yield break;
                }
            }
        }

        public async IAsyncEnumerable<(long Index, byte[] Hash)> ReadLeafHashesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            long after = -1;
            while (true)
            {
                var page = await store.GetLeafHashesAsync(after, 5000, cancellationToken);
                foreach (var leaf in page)
                {
                    yield return leaf;
                    after = leaf.Index;
                }

                if (page.Count < 5000)
                {
                    yield break;
                }
            }
        }

        public async Task<IReadOnlyList<byte[]>> GetInclusionProofAsync(long leafIndex, long treeSize, CancellationToken cancellationToken) =>
            await new ProofBuilder(store).InclusionProofAsync(leafIndex, treeSize, cancellationToken);

        public async Task<IReadOnlyList<byte[]>> GetConsistencyProofAsync(long firstSize, long secondSize, CancellationToken cancellationToken) =>
            await new ProofBuilder(store).ConsistencyProofAsync(firstSize, secondSize, cancellationToken);
    }

    public static string Environment() => string.Create(CultureInfo.InvariantCulture,
        $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription}, {System.Environment.ProcessorCount} logical CPUs, .NET {System.Environment.Version}");
}
