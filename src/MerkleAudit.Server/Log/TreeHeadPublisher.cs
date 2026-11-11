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

    public override void Dispose()
    {
        _gate.Dispose();
        base.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Signed tree head size {TreeSize} root {RootHash} key {KeyId}")]
    private partial void LogPublished(long treeSize, string rootHash, string keyId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Tree head publication failed")]
    private partial void LogPublishFailed(Exception exception);
}
