using System.Globalization;
using System.Text.Json;
using MerkleAudit.Verifier;

// merkle-verify: checks a merkle-audit log from the outside. It trusts only the public keys it is given.
//   audit        replay the whole log, verify every signed head, pinpoint tampered rows   (exit 2 on tampering)
//   inclusion    prove one entry is in the latest signed head                             (exit 2 if not)
//   consistency  prove the latest signed head extends the one in the witness file         (exit 2 if not)
// Exit 1 means the check could not run (bad arguments, log unreachable).

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("""
        usage: merkle-verify <audit|inclusion|consistency> --log <url> --key <public.pem>[,notAfter=<ISO-8601>] [...]
          --key        trusted tree-head public key (repeatable; a retired key takes notAfter)
          --witness    JSON file of tree heads verified on earlier runs (read, then updated on success)
          --seq        entry sequence number (inclusion)
          --report     also write the audit report to this file
        """);
    return 1;
}

var command = args[0];
var options = ParseOptions(args.AsSpan(1));
try
{
    using var trust = new TrustStore();
    foreach (var spec in options.GetValueOrDefault("key") ?? [])
    {
        var parts = spec.Split(",notAfter=", 2);
        long? notAfter = parts.Length == 2 ? DateTimeOffset.Parse(parts[1], CultureInfo.InvariantCulture).ToUnixTimeMilliseconds() : null;
        var key = trust.AddPem(await File.ReadAllTextAsync(parts[0]), notAfter);
        Console.Error.WriteLine($"trusted key {key.KeyId}{(notAfter is null ? "" : " (retired)")}");
    }

    if (trust.Keys.Count == 0)
    {
        throw new ArgumentException("At least one --key is required: a verifier without pinned keys verifies nothing.");
    }

    var logUrl = Single(options, "log");
    using var http = new HttpClient { BaseAddress = new Uri(logUrl.EndsWith('/') ? logUrl : logUrl + "/"), Timeout = TimeSpan.FromSeconds(60) };
    var source = new HttpLogSource(http);
    var witnessPath = options.TryGetValue("witness", out var w) ? w[0] : null;
    var witness = witnessPath is null ? new WitnessState([]) : await WitnessState.LoadAsync(witnessPath, CancellationToken.None);

    return command switch
    {
        "audit" => await AuditAsync(),
        "inclusion" => await InclusionAsync(),
        "consistency" => await ConsistencyAsync(),
        _ => throw new ArgumentException($"Unknown command '{command}'."),
    };

    async Task<int> AuditAsync()
    {
        var report = await new LogAuditor(source, trust).AuditAsync(witness.SignedHeads);
        var text = report.Render();
        Console.Write(text);
        if (options.TryGetValue("report", out var reportPath))
        {
            await File.WriteAllTextAsync(reportPath[0], text);
        }

        // Only a clean audit extends the witness: a tampered log must not become the new baseline.
        if (report.Clean && witnessPath is not null && report.LatestHead is { } latest)
        {
            await new WitnessState([.. witness.Heads, TreeHeadDto.From(latest)]).SaveAsync(witnessPath, CancellationToken.None);
        }

        return report.Clean ? 0 : 2;
    }

    async Task<int> InclusionAsync()
    {
        var seq = long.Parse(Single(options, "seq"), CultureInfo.InvariantCulture);
        var head = await LatestVerifiedHeadAsync();
        if (seq >= head.TreeSize)
        {
            Console.WriteLine($"seq {seq} is not covered yet: latest signed head has size {head.TreeSize}");
            return 2;
        }

        var entry = await source.GetEntryAsync(seq, CancellationToken.None);
        if (entry is null)
        {
            Console.WriteLine($"seq {seq}: row missing from the log");
            return 2;
        }

        var leaf = entry.LeafHash();
        var proof = await source.GetInclusionProofAsync(seq, head.TreeSize, CancellationToken.None);
        var ok = ProofVerifier.VerifyInclusion(seq, head.TreeSize, leaf, proof, head.RootHash);
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            seq,
            leafHash = Hex.Of(leaf),
            treeSize = head.TreeSize,
            rootHash = Hex.Of(head.RootHash),
            proofLength = proof.Count,
            verified = ok,
        }));
        return ok ? 0 : 2;
    }

    async Task<int> ConsistencyAsync()
    {
        var head = await LatestVerifiedHeadAsync();
        var previous = witness.SignedHeads.Where(h => trust.Check(h) is null).MaxBy(h => h.TreeSize);
        if (previous is null)
        {
            Console.WriteLine($"no witnessed head yet; trusting {head} as the first one");
        }
        else
        {
            var proof = await source.GetConsistencyProofAsync(previous.TreeSize, head.TreeSize, CancellationToken.None);
            var ok = ProofVerifier.VerifyConsistency(previous.TreeSize, head.TreeSize, proof, previous.RootHash, head.RootHash);
            Console.WriteLine(JsonSerializer.Serialize(new { first = previous.TreeSize, second = head.TreeSize, proofLength = proof.Count, verified = ok }));
            if (!ok)
            {
                return 2;
            }
        }

        if (witnessPath is not null)
        {
            await new WitnessState([.. witness.Heads, TreeHeadDto.From(head)]).SaveAsync(witnessPath, CancellationToken.None);
        }

        return 0;
    }

    async Task<SignedHead> LatestVerifiedHeadAsync()
    {
        var head = await source.GetLatestTreeHeadAsync(CancellationToken.None)
            ?? throw new InvalidOperationException("The log has not published a tree head yet.");
        var problem = trust.Check(head);
        return problem is null ? head : throw new VerificationException($"latest tree head rejected: {problem}");
    }
}
catch (VerificationException ex)
{
    Console.WriteLine(ex.Message);
    return 2;
}
catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException or IOException or FormatException or System.Security.Cryptography.CryptographicException)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

static Dictionary<string, List<string>> ParseOptions(ReadOnlySpan<string> args)
{
    var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
        {
            throw new ArgumentException($"Expected '--name value', got '{args[i]}'.");
        }

        var name = args[i][2..];
        if (!result.TryGetValue(name, out var values))
        {
            result[name] = values = [];
        }

        values.Add(args[++i]);
    }

    return result;
}

static string Single(Dictionary<string, List<string>> options, string name) =>
    options.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : throw new ArgumentException($"--{name} is required once.");

internal sealed class VerificationException(string message) : Exception(message);
