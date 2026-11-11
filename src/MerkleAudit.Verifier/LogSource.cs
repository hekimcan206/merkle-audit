using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MerkleAudit.Verifier;

/// <summary>What an auditor reads from a log. Everything it returns is untrusted until checked against signed heads.</summary>
public interface ILogSource
{
    Task<IReadOnlyList<SignedHead>> GetTreeHeadsAsync(CancellationToken cancellationToken);

    /// <summary>All entries ordered by sequence number.</summary>
    IAsyncEnumerable<EntryRecord> ReadEntriesAsync(CancellationToken cancellationToken);

    /// <summary>The leaf hashes stored in the tree (level 0 nodes) ordered by index.</summary>
    IAsyncEnumerable<(long Index, byte[] Hash)> ReadLeafHashesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<byte[]>> GetInclusionProofAsync(long leafIndex, long treeSize, CancellationToken cancellationToken);

    Task<IReadOnlyList<byte[]>> GetConsistencyProofAsync(long firstSize, long secondSize, CancellationToken cancellationToken);
}

/// <summary>Reads a log through its public HTTP API (<c>/api/v1</c>).</summary>
public sealed class HttpLogSource(HttpClient http, int pageSize = 1000) : ILogSource
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<SignedHead>> GetTreeHeadsAsync(CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<TreeHeadListDto>("api/v1/sth/history", Json, cancellationToken)
            ?? throw new InvalidOperationException("Empty tree head history.");
        return [.. response.Heads.Select(h => h.ToModel())];
    }

    public async Task<SignedHead?> GetLatestTreeHeadAsync(CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync("api/v1/sth", cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var dto = await response.Content.ReadFromJsonAsync<TreeHeadDto>(Json, cancellationToken);
        return dto?.ToModel();
    }

    public async Task<EntryRecord?> GetEntryAsync(long seq, CancellationToken cancellationToken)
    {
        var page = await http.GetFromJsonAsync<EntryPageDto>($"api/v1/entries?after={seq - 1}&limit=1", Json, cancellationToken);
        return page?.Entries is [var e] && e.Seq == seq ? new EntryRecord(e.Seq, e.OccurredAtMicros, e.Actor, e.Action, e.Resource, e.Payload) : null;
    }

    public async IAsyncEnumerable<EntryRecord> ReadEntriesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        long after = -1;
        while (true)
        {
            var page = await http.GetFromJsonAsync<EntryPageDto>($"api/v1/entries?after={after}&limit={pageSize}", Json, cancellationToken)
                ?? throw new InvalidOperationException("Empty entry page.");
            foreach (var e in page.Entries)
            {
                yield return new EntryRecord(e.Seq, e.OccurredAtMicros, e.Actor, e.Action, e.Resource, e.Payload);
                after = e.Seq;
            }

            if (page.Entries.Count < pageSize)
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
            var page = await http.GetFromJsonAsync<LeafPageDto>($"api/v1/tree/leaves?after={after}&limit={pageSize}", Json, cancellationToken)
                ?? throw new InvalidOperationException("Empty leaf page.");
            foreach (var leaf in page.Leaves)
            {
                yield return (leaf.Index, Hex.Parse(leaf.Hash));
                after = leaf.Index;
            }

            if (page.Leaves.Count < pageSize)
            {
                yield break;
            }
        }
    }

    public async Task<IReadOnlyList<byte[]>> GetInclusionProofAsync(long leafIndex, long treeSize, CancellationToken cancellationToken)
    {
        var dto = await http.GetFromJsonAsync<InclusionProofDto>($"api/v1/proofs/inclusion?leafIndex={leafIndex}&treeSize={treeSize}", Json, cancellationToken)
            ?? throw new InvalidOperationException("Empty proof.");
        return [.. dto.AuditPath.Select(Hex.Parse)];
    }

    public async Task<IReadOnlyList<byte[]>> GetConsistencyProofAsync(long firstSize, long secondSize, CancellationToken cancellationToken)
    {
        var dto = await http.GetFromJsonAsync<ConsistencyProofDto>($"api/v1/proofs/consistency?first={firstSize}&second={secondSize}", Json, cancellationToken)
            ?? throw new InvalidOperationException("Empty proof.");
        return [.. dto.Consistency.Select(Hex.Parse)];
    }
}

/// <summary>Wire format of a signed tree head: hashes in lowercase hex, signature in base64 (DER).</summary>
public sealed record TreeHeadDto(long TreeSize, long Timestamp, string RootHash, string KeyId, string Signature)
{
    public SignedHead ToModel() => new(TreeSize, Timestamp, Hex.Parse(RootHash), KeyId, Convert.FromBase64String(Signature));

    public static TreeHeadDto From(SignedHead head)
    {
        ArgumentNullException.ThrowIfNull(head);
        return new(head.TreeSize, head.TimestampMs, Hex.Of(head.RootHash), head.KeyId, Convert.ToBase64String(head.Signature));
    }
}

public sealed record TreeHeadListDto(IReadOnlyList<TreeHeadDto> Heads);

public sealed record EntryDto(long Seq, string OccurredAt, long OccurredAtMicros, string Actor, string Action, string Resource, string Payload);

public sealed record EntryPageDto(IReadOnlyList<EntryDto> Entries);

public sealed record LeafDto(long Index, string Hash);

public sealed record LeafPageDto(IReadOnlyList<LeafDto> Leaves);

public sealed record InclusionProofDto(long LeafIndex, long TreeSize, IReadOnlyList<string> AuditPath);

public sealed record ConsistencyProofDto(long First, long Second, IReadOnlyList<string> Consistency);

/// <summary>The auditor's memory between runs: every tree head it has already verified.</summary>
public sealed record WitnessState(IReadOnlyList<TreeHeadDto> Heads)
{
    [JsonIgnore]
    public IReadOnlyList<SignedHead> SignedHeads => [.. Heads.Select(h => h.ToModel())];

    public static async Task<WitnessState> LoadAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return new WitnessState([]);
        }

        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<WitnessState>(stream, HttpLogSource.Json, cancellationToken) ?? new WitnessState([]);
    }

    public async Task SaveAsync(string path, CancellationToken cancellationToken)
    {
        var temp = path + ".tmp";
        await using (var stream = File.Create(temp))
        {
            await JsonSerializer.SerializeAsync(stream, this, HttpLogSource.Json, cancellationToken);
        }

        File.Move(temp, path, overwrite: true);
    }
}
