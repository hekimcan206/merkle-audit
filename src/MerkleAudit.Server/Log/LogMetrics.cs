using System.Diagnostics.Metrics;

namespace MerkleAudit.Server.Log;

/// <summary>OpenTelemetry metrics for the log: append volume and latency, group size, heads, proof latency.</summary>
public sealed class LogMetrics : IDisposable
{
    public const string MeterName = "MerkleAudit.Log";

    private readonly Meter _meter = new(MeterName);
    private readonly Counter<long> _entries;
    private readonly Histogram<int> _groupSize;
    private readonly Histogram<double> _appendMs;
    private readonly Counter<long> _heads;
    private readonly Histogram<double> _proofMs;

    public LogMetrics()
    {
        _entries = _meter.CreateCounter<long>("merkle_audit.entries.appended", "{entry}", "Entries committed to the log");
        _groupSize = _meter.CreateHistogram<int>("merkle_audit.append.group_size", "{entry}", "Entries per append transaction");
        _appendMs = _meter.CreateHistogram<double>("merkle_audit.append.duration", "ms", "Append transaction duration");
        _heads = _meter.CreateCounter<long>("merkle_audit.tree_heads.published", "{head}", "Signed tree heads published");
        _proofMs = _meter.CreateHistogram<double>("merkle_audit.proof.duration", "ms", "Proof generation duration");
    }

    public void Appended(int entries, TimeSpan duration)
    {
        _entries.Add(entries);
        _groupSize.Record(entries);
        _appendMs.Record(duration.TotalMilliseconds);
    }

    public void HeadPublished() => _heads.Add(1);

    public void ProofBuilt(string kind, TimeSpan duration) =>
        _proofMs.Record(duration.TotalMilliseconds, new KeyValuePair<string, object?>("kind", kind));

    public void Dispose() => _meter.Dispose();
}
