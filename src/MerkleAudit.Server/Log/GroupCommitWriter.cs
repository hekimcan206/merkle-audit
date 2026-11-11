using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace MerkleAudit.Server.Log;

/// <summary>
/// Group commit. Every append, single or batch, joins one in-process queue; a single writer drains whatever is waiting
/// (up to <see cref="LogOptions.MaxGroupCommit"/> entries) into one locked transaction. Concurrent single appends then
/// cost one commit per group instead of one per entry, while each caller still gets its own sequence numbers back
/// only after the commit is durable.
/// </summary>
public sealed partial class GroupCommitWriter(LogStore store, IOptions<LogOptions> options, ILogger<GroupCommitWriter> logger) : BackgroundService
{
    private sealed record Pending(IReadOnlyList<NewEntry> Entries, TaskCompletionSource<IReadOnlyList<AppendedEntry>> Done);

    private readonly Channel<Pending> _channel = Channel.CreateBounded<Pending>(new BoundedChannelOptions(options.Value.QueueCapacity)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait,
    });

    public async Task<IReadOnlyList<AppendedEntry>> AppendAsync(IReadOnlyList<NewEntry> entries, CancellationToken cancellationToken)
    {
        var pending = new Pending(entries, new TaskCompletionSource<IReadOnlyList<AppendedEntry>>(TaskCreationOptions.RunContinuationsAsynchronously));
        await _channel.Writer.WriteAsync(pending, cancellationToken);

        // The caller may stop waiting, but the entry is not withdrawn: once queued it is committed or failed as a whole.
        return await pending.Done.Task.WaitAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var max = options.Value.MaxGroupCommit;
        var group = new List<Pending>();
        while (await _channel.Reader.WaitToReadAsync(stoppingToken))
        {
            group.Clear();
            var count = 0;
            while (count < max && _channel.Reader.TryPeek(out var next) && (count == 0 || count + next.Entries.Count <= max) && _channel.Reader.TryRead(out next))
            {
                group.Add(next);
                count += next.Entries.Count;
            }

            try
            {
                var appended = await store.AppendAsync([.. group.SelectMany(p => p.Entries)], stoppingToken);
                var offset = 0;
                foreach (var pending in group)
                {
                    pending.Done.TrySetResult(appended.Skip(offset).Take(pending.Entries.Count).ToList());
                    offset += pending.Entries.Count;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
            {
                // The whole group rolled back: every caller in it gets the error and may retry.
                LogGroupFailed(ex, group.Count, count);
                foreach (var pending in group)
                {
                    pending.Done.TrySetException(ex);
                }
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _channel.Writer.TryComplete();
        await base.StopAsync(cancellationToken);
        while (_channel.Reader.TryRead(out var pending))
        {
            pending.Done.TrySetCanceled(cancellationToken);
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Group commit of {Requests} requests / {Entries} entries failed")]
    private partial void LogGroupFailed(Exception exception, int requests, int entries);
}

public sealed class LogOptions
{
    public const string Section = "Log";

    /// <summary>Largest number of entries committed in one transaction.</summary>
    public int MaxGroupCommit { get; set; } = 1000;

    /// <summary>Requests waiting for the writer before callers are slowed down (back-pressure).</summary>
    public int QueueCapacity { get; set; } = 10_000;

    /// <summary>Largest explicit batch accepted by <c>POST /entries/batch</c>.</summary>
    public int MaxBatch { get; set; } = 1000;

    /// <summary>How often a new tree head is considered for signing.</summary>
    public TimeSpan PublishInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>A head is re-signed at least this often even when the tree has not grown, so monitors see liveness.</summary>
    public TimeSpan MaxHeadAge { get; set; } = TimeSpan.FromHours(1);

    /// <summary>API keys allowed to append (X-Api-Key). Reading is public: transparency is the point.</summary>
    public string[] AppendApiKeys { get; set; } = [];
}
