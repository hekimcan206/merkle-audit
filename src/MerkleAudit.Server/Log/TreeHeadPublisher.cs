using MerkleAudit.Core.Tree;
using MerkleAudit.Core.TreeHeads;
using Microsoft.Extensions.Options;

namespace MerkleAudit.Server.Log;

/// <summary>
/// Periodically signs the current tree state and appends the signed head to <c>audit.tree_heads</c>. A signed head is
/// the log's only durable, attributable commitment: once a monitor has a copy, the log cannot rewrite anything
/// before that size without the signature exposing it.
/// </summary>
public sealed partial class TreeHeadPublisher(
    LogStore store,
    SigningKeyRing keys,
    TimeProvider time,
    IOptions<LogOptions> options,
    LogMetrics metrics,
    ILogger<TreeHeadPublisher> logger) : BackgroundService
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Signs and stores a head if the tree grew (or <paramref name="force"/>, or the last head is too old).</summary>
    public async Task<SignedTreeHead?> PublishAsync(bool force, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var state = await store.GetTreeStateAsync(cancellationToken);
            var heads = await store.GetTreeHeadsAsync(latestOnly: true, cancellationToken);
            var latest = heads.Count > 0 ? heads[0] : null;
            var now = time.GetUtcNow().ToUnixTimeMilliseconds();
            var stale = latest is null || now - latest.Head.TimestampMs >= options.Value.MaxHeadAge.TotalMilliseconds;
            if (!force && !stale && latest!.Head.TreeSize == state.TreeSize)
            {
                return null;
            }

            // Never sign a fork. Before signing, the stored nodes must still reproduce the last signed root, and the
            // current root must be what those same nodes give: then the new head provably extends the old one. Without
            // this check, someone who rewrote the tree between two publications would get the forgery signed.
            if (await IntegrityProblemAsync(state, latest, cancellationToken) is { } problem)
            {
                metrics.HeadRefused();
                LogRefused(state.TreeSize, problem);
                return null;
            }

            // Timestamps must not go backwards, even if the wall clock does: monitors order heads by time.
            var timestamp = latest is null ? now : Math.Max(now, latest.Head.TimestampMs + 1);
            var sth = keys.Active.Sign(new TreeHead(state.TreeSize, timestamp, state.RootHash));
            await store.InsertTreeHeadAsync(sth, cancellationToken);
            metrics.HeadPublished();
            if (logger.IsEnabled(LogLevel.Information))
            {
                var rootHex = Convert.ToHexStringLower(sth.Head.RootHash);
                LogPublished(sth.Head.TreeSize, rootHex, sth.KeyId);
            }
            return sth;
        }
        finally
        {
            _gate.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // A zero interval turns the schedule off (tests and external schedulers call PublishAsync themselves).
        if (options.Value.PublishInterval <= TimeSpan.Zero)
        {
            return;
        }

        using var timer = new PeriodicTimer(options.Value.PublishInterval, time);
        do
        {
            try
            {
                await PublishAsync(force: false, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // A missed publication is retried on the next tick; the tree itself is unaffected.
                LogPublishFailed(ex);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task<string?> IntegrityProblemAsync(TreeState state, SignedTreeHead? latest, CancellationToken cancellationToken)
    {
        var nodes = new ProofBuilder(store);
        if (latest is not null)
        {
            if (state.TreeSize < latest.Head.TreeSize)
            {
                return $"tree shrank from signed size {latest.Head.TreeSize} to {state.TreeSize}";
            }

            var signedRoot = await nodes.RootAsync(latest.Head.TreeSize, cancellationToken);
            if (!signedRoot.AsSpan().SequenceEqual(latest.Head.RootHash))
            {
                return $"stored nodes no longer reproduce the signed root of size {latest.Head.TreeSize}";
            }
        }

        var currentRoot = await nodes.RootAsync(state.TreeSize, cancellationToken);
        return currentRoot.AsSpan().SequenceEqual(state.RootHash) ? null : "tree_state root does not match the stored nodes";
    }

    public override void Dispose()
    {
        _gate.Dispose();
        base.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Signed tree head size {TreeSize} root {RootHash} key {KeyId}")]
    private partial void LogPublished(long treeSize, string rootHash, string keyId);

    [LoggerMessage(Level = LogLevel.Critical, Message = "Refusing to sign tree head of size {TreeSize}: {Problem}. The log may have been tampered with")]
    private partial void LogRefused(long treeSize, string problem);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Tree head publication failed")]
    private partial void LogPublishFailed(Exception exception);
}
