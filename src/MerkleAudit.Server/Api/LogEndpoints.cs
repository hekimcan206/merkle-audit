using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MerkleAudit.Core.Entries;
using MerkleAudit.Core.Tree;
using MerkleAudit.Core.TreeHeads;
using MerkleAudit.Server.Log;
using Microsoft.Extensions.Options;

namespace MerkleAudit.Server.Api;

/// <summary>Request body for one audit entry. <see cref="Payload"/> is any JSON value, stored exactly as sent.</summary>
public sealed record AppendRequest(string? Actor, string? Action, string? Resource, JsonElement Payload);

public sealed record AppendResponse(long Seq, string OccurredAt, string LeafHash);

public sealed record TreeHeadResponse(long TreeSize, long Timestamp, string RootHash, string KeyId, string Signature)
{
    public static TreeHeadResponse From(SignedTreeHead sth) => new(
        sth.Head.TreeSize, sth.Head.TimestampMs, Convert.ToHexStringLower(sth.Head.RootHash), sth.KeyId, Convert.ToBase64String(sth.Signature));
}

public sealed record TreeHeadListResponse(IReadOnlyList<TreeHeadResponse> Heads);

public sealed record TreeStateResponse(long TreeSize, string RootHash);

public sealed record EntryResponse(long Seq, string OccurredAt, long OccurredAtMicros, string Actor, string Action, string Resource, string Payload);

public sealed record EntryPageResponse(IReadOnlyList<EntryResponse> Entries);

public sealed record LeafResponse(long Index, string Hash);

public sealed record LeafPageResponse(IReadOnlyList<LeafResponse> Leaves);

public sealed record InclusionProofResponse(long LeafIndex, long TreeSize, IReadOnlyList<string> AuditPath);

public sealed record ConsistencyProofResponse(long First, long Second, IReadOnlyList<string> Consistency);

public sealed record KeyListResponse(IReadOnlyList<PublishedKey> Keys);

internal static class LogEndpoints
{
    private const int MaxPage = 1000;

    public static RouteGroupBuilder MapLogEndpoints(this RouteGroupBuilder api)
    {
        var entries = api.MapGroup("/entries").WithTags("Entries");
        entries.MapPost("/", AppendOneAsync)
            .WithSummary("Append one audit entry (group-committed with concurrent appends).")
            .AddEndpointFilter<ApiKeyFilter>();
        entries.MapPost("/batch", AppendBatchAsync)
            .WithSummary("Append up to Log:MaxBatch entries in one transaction.")
            .AddEndpointFilter<ApiKeyFilter>();
        entries.MapGet("/", ListEntriesAsync).WithSummary("Entries with seq > after, in order.");

        var tree = api.MapGroup("/tree").WithTags("Tree");
        tree.MapGet("/", async (LogStore store, CancellationToken ct) =>
        {
            var state = await store.GetTreeStateAsync(ct);
            return new TreeStateResponse(state.TreeSize, Convert.ToHexStringLower(state.RootHash));
        }).WithSummary("Current (unsigned) tree size and root.");
        tree.MapGet("/leaves", ListLeavesAsync).WithSummary("Stored leaf hashes with index > after, in order.");

        var sth = api.MapGroup("/sth").WithTags("Signed tree heads");
        sth.MapGet("/", async Task<IResult> (LogStore store, CancellationToken ct) =>
            (await store.GetTreeHeadsAsync(latestOnly: true, ct)) is [var latest]
                ? TypedResults.Ok(TreeHeadResponse.From(latest))
                : TypedResults.Problem("No tree head has been published yet.", statusCode: StatusCodes.Status404NotFound))
            .WithSummary("Latest signed tree head (RFC 6962 get-sth).");
        sth.MapGet("/history", async (LogStore store, CancellationToken ct) =>
            new TreeHeadListResponse([.. (await store.GetTreeHeadsAsync(latestOnly: false, ct)).Select(TreeHeadResponse.From)]))
            .WithSummary("Every signed tree head, by size then time.");

        var proofs = api.MapGroup("/proofs").WithTags("Proofs");
        proofs.MapGet("/inclusion", InclusionAsync).WithSummary("Audit path for leafIndex in the tree of treeSize (RFC 6962 get-proof-by-hash, by index).");
        proofs.MapGet("/consistency", ConsistencyAsync).WithSummary("Consistency proof between two tree sizes (RFC 6962 get-sth-consistency).");

        api.MapGet("/keys", (SigningKeyRing keys) => new KeyListResponse(keys.Published))
            .WithTags("Signed tree heads")
            .WithSummary("Tree-head public keys. Informational: verifiers must pin keys out of band.");
        return api;
    }

    private static async Task<IResult> AppendOneAsync(AppendRequest request, GroupCommitWriter writer, CancellationToken ct)
    {
        if (Validate(request) is { } error)
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> { ["entry"] = [error] });
        }

        var appended = (await writer.AppendAsync([ToNewEntry(request)], ct))[0];
        return TypedResults.Created($"/api/v1/entries?after={appended.Seq - 1}&limit=1", ToResponse(appended));
    }

    private static async Task<IResult> AppendBatchAsync(AppendRequest[] requests, GroupCommitWriter writer, IOptions<LogOptions> options, CancellationToken ct)
    {
        if (requests.Length == 0 || requests.Length > options.Value.MaxBatch)
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> { ["batch"] = [$"A batch holds 1..{options.Value.MaxBatch} entries."] });
        }

        for (var i = 0; i < requests.Length; i++)
        {
            if (Validate(requests[i]) is { } error)
            {
                return TypedResults.ValidationProblem(new Dictionary<string, string[]> { [$"[{i}]"] = [error] });
            }
        }

        var appended = await writer.AppendAsync([.. requests.Select(ToNewEntry)], ct);
        return TypedResults.Ok(appended.Select(ToResponse).ToList());
    }

    private static async Task<EntryPageResponse> ListEntriesAsync(LogStore store, CancellationToken ct, long after = -1, int limit = 100)
    {
        var page = await store.GetEntriesAsync(after, Math.Clamp(limit, 1, MaxPage), ct);
        return new EntryPageResponse([.. page.Select(e => new EntryResponse(
            e.Seq, e.OccurredAt.ToString("O", CultureInfo.InvariantCulture), LeafCodec.ToUnixMicroseconds(e.OccurredAt), e.Actor, e.Action, e.Resource, e.Payload))]);
    }

    private static async Task<LeafPageResponse> ListLeavesAsync(LogStore store, CancellationToken ct, long after = -1, int limit = 100)
    {
        var page = await store.GetLeafHashesAsync(after, Math.Clamp(limit, 1, MaxPage), ct);
        return new LeafPageResponse([.. page.Select(l => new LeafResponse(l.Index, Convert.ToHexStringLower(l.Hash)))]);
    }

    private static async Task<IResult> InclusionAsync(long leafIndex, long treeSize, LogStore store, LogMetrics metrics, TimeProvider time, CancellationToken ct)
    {
        var state = await store.GetTreeStateAsync(ct);
        if (treeSize < 1 || treeSize > state.TreeSize || leafIndex < 0 || leafIndex >= treeSize)
        {
            return TypedResults.Problem($"Need 0 <= leafIndex < treeSize <= {state.TreeSize}.", statusCode: StatusCodes.Status400BadRequest);
        }

        var started = time.GetTimestamp();
        var path = await new ProofBuilder(store).InclusionProofAsync(leafIndex, treeSize, ct);
        metrics.ProofBuilt("inclusion", time.GetElapsedTime(started));
        return TypedResults.Ok(new InclusionProofResponse(leafIndex, treeSize, [.. path.Select(Convert.ToHexStringLower)]));
    }

    private static async Task<IResult> ConsistencyAsync(long first, long second, LogStore store, LogMetrics metrics, TimeProvider time, CancellationToken ct)
    {
        var state = await store.GetTreeStateAsync(ct);
        if (first < 0 || first > second || second > state.TreeSize)
        {
            return TypedResults.Problem($"Need 0 <= first <= second <= {state.TreeSize}.", statusCode: StatusCodes.Status400BadRequest);
        }

        var started = time.GetTimestamp();
        var proof = await new ProofBuilder(store).ConsistencyProofAsync(first, second, ct);
        metrics.ProofBuilt("consistency", time.GetElapsedTime(started));
        return TypedResults.Ok(new ConsistencyProofResponse(first, second, [.. proof.Select(Convert.ToHexStringLower)]));
    }

    internal static string? Validate(AppendRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Actor) || request.Actor.Length > 200)
        {
            return "actor is required (1-200 characters).";
        }

        if (string.IsNullOrWhiteSpace(request.Action) || request.Action.Length > 200)
        {
            return "action is required (1-200 characters).";
        }

        if (string.IsNullOrWhiteSpace(request.Resource) || request.Resource.Length > 500)
        {
            return "resource is required (1-500 characters).";
        }

        if (request.Payload.ValueKind == JsonValueKind.Undefined)
        {
            return "payload is required (any JSON value).";
        }

        return request.Payload.GetRawText().Length > 65536 ? "payload is limited to 64 KiB." : null;
    }

    private static NewEntry ToNewEntry(AppendRequest r) => new(r.Actor!, r.Action!, r.Resource!, r.Payload.GetRawText());

    private static AppendResponse ToResponse(AppendedEntry e) =>
        new(e.Seq, e.OccurredAt.ToString("O", CultureInfo.InvariantCulture), Convert.ToHexStringLower(e.LeafHash));
}

/// <summary>Appends need an API key (X-Api-Key), compared in constant time. Reads are public by design.</summary>
internal sealed class ApiKeyFilter(IOptions<LogOptions> options) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var presented = context.HttpContext.Request.Headers["X-Api-Key"].ToString();
        var presentedHash = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        var allowed = presented.Length > 0 && options.Value.AppendApiKeys
            .Any(k => k.Length > 0 && CryptographicOperations.FixedTimeEquals(presentedHash, SHA256.HashData(Encoding.UTF8.GetBytes(k))));
        return allowed ? await next(context) : TypedResults.Problem("A valid X-Api-Key is required to append.", statusCode: StatusCodes.Status401Unauthorized);
    }
}
