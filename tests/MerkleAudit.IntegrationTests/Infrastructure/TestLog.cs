using System.Net.Http.Json;
using MerkleAudit.Server.Log;
using MerkleAudit.Verifier;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace MerkleAudit.IntegrationTests.Infrastructure;

/// <summary>One log under test: its server, its HTTP client, and direct database access as each role.</summary>
public sealed class TestLog : IAsyncDisposable
{
    internal TestLog(LogEnvironment.ServerFactory factory, NpgsqlDataSource superuser, NpgsqlDataSource app, NpgsqlDataSource migrator, string trustedKeyDirectory)
    {
        Factory = factory;
        Superuser = superuser;
        App = app;
        Migrator = migrator;
        Http = factory.CreateClient();
        Trust = new TrustStore();
        foreach (var file in Directory.GetFiles(trustedKeyDirectory, "*.pub.pem"))
        {
            Trust.AddPem(File.ReadAllText(file));
        }
    }

    internal LogEnvironment.ServerFactory Factory { get; }

    public HttpClient Http { get; }

    public NpgsqlDataSource Superuser { get; }

    public NpgsqlDataSource App { get; }

    public NpgsqlDataSource Migrator { get; }

    public TrustStore Trust { get; }

    public HttpLogSource Source => new(Http);

    public TreeHeadPublisher Publisher => Factory.Services.GetRequiredService<TreeHeadPublisher>();

    public LogStore Store => Factory.Services.GetRequiredService<LogStore>();

    public async Task<HttpResponseMessage> AppendAsync(object entry, string? apiKey = LogEnvironment.ApiKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/entries") { Content = JsonContent.Create(entry) };
        if (apiKey is not null)
        {
            request.Headers.Add("X-Api-Key", apiKey);
        }

        return await Http.SendAsync(request);
    }

    public async Task<HttpResponseMessage> AppendBatchAsync(object[] entries)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/entries/batch") { Content = JsonContent.Create(entries) };
        request.Headers.Add("X-Api-Key", LogEnvironment.ApiKey);
        return await Http.SendAsync(request);
    }

    public async Task<SignedHead> PublishAsync()
    {
        var sth = await Publisher.PublishAsync(force: true, CancellationToken.None)
            ?? throw new InvalidOperationException("Forced publication returned nothing.");
        return new SignedHead(sth.Head.TreeSize, sth.Head.TimestampMs, sth.Head.RootHash, sth.KeyId, sth.Signature);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        Trust.Dispose();
        await Factory.DisposeAsync();
        await Superuser.DisposeAsync();
        await App.DisposeAsync();
        await Migrator.DisposeAsync();
    }
}

/// <summary>Deterministic clock: every reading is 250 ms after the previous one, starting 2026-11-01 09:00 UTC.</summary>
public sealed class SteppingTimeProvider : TimeProvider
{
    private long _ticks = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero).UtcTicks;

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Add(ref _ticks, TimeSpan.TicksPerMillisecond * 250), TimeSpan.Zero);
}
