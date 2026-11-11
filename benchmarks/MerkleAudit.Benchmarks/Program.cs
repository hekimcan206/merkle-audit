using BenchmarkDotNet.Running;
using MerkleAudit.Benchmarks;

// dotnet run -c Release --project benchmarks/MerkleAudit.Benchmarks -- <mode>
//   micro               BenchmarkDotNet: proof verification, proof building, leaf hashing   (no Docker)
//   append              PostgreSQL append throughput: single, group commit, batches          (Docker)
//   proofs [leaves]     grow a log to [leaves] (default 1,000,000), proof latency at checkpoints,
//                       then a full independent audit of the whole log                        (Docker)
var mode = args.Length > 0 ? args[0] : "micro";
var output = Path.GetFullPath(Path.Combine("benchmark-results"));
Console.WriteLine($"environment: {PostgresHarness.Environment()}");

switch (mode)
{
    case "micro":
        BenchmarkRunner.Run<VerificationBenchmarks>(args: args[1..]);
        break;
    case "append":
    case "proofs":
        await using (var harness = new PostgresHarness(output))
        {
            await harness.StartAsync();
            if (mode == "append")
            {
                await harness.AppendThroughputAsync();
            }
            else
            {
                await harness.ProofLatencyAsync(args.Length > 1 ? long.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 1_000_000);
            }
        }

        break;
    default:
        Console.Error.WriteLine($"unknown mode '{mode}'");
        return 1;
}

return 0;
