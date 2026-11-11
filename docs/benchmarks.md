# Benchmarks

Every number here was measured on the machine below. Raw results are in [`benchmark-results/`](../benchmark-results)
(one JSON file per run, `summary.json` holds the medians). Nothing is estimated.

## Environment

| | |
|---|---|
| CPU | 13th Gen Intel Core i7-13620H, 10 cores / 16 threads, laptop |
| RAM | 15.7 GB host; Docker Desktop VM 7.6 GB |
| OS | Windows 11 25H2 (10.0.26200), Docker Desktop 29.9.1 on WSL2 (kernel 6.18) |
| .NET | SDK 10.0.401, runtime 10.0.12, Release build |
| PostgreSQL | `postgres:17-alpine` in Docker via Testcontainers, **default durability** (`fsync=on`, `synchronous_commit=on`), data on the WSL2 virtual disk |
| Client | the benchmark process on Windows, talking to PostgreSQL through Docker Desktop's port forwarding |
| Host load | shared developer machine: about 40 % CPU in use by other work before the runs, another project's containers active in the same Docker VM. Expect noise; that is why every PostgreSQL scenario ran 3 times and the **median** is reported, with all runs listed |

## How to reproduce

```bash
dotnet build -c Release
dotnet run -c Release --project benchmarks/MerkleAudit.Benchmarks -- append            # ~1.5 min
dotnet run -c Release --project benchmarks/MerkleAudit.Benchmarks -- proofs 1000000    # ~1 min
dotnet run -c Release --project benchmarks/MerkleAudit.Benchmarks -- micro --job short # BenchmarkDotNet
# repeat with BENCH_TAG=run1..3 (and BENCH_WRITE_BUFFER=8192 BENCH_TAG=npgsql-8k-runN for the baseline), then:
node benchmarks/summarize.mjs
```

The harness uses the server's own `LogStore` and `GroupCommitWriter` (the code path behind the HTTP API, without
HTTP), on a fresh database cloned from a migrated template for each scenario, connecting as `audit_app`.

## 1. PostgreSQL append throughput

Entries are ~150-byte synthetic audit records. Each append transaction locks `tree_state`, reads the frontier,
inserts entries and tree nodes (`unnest`), updates `tree_state` and commits. Latency is per request (per transaction
for batches). Median of 3 runs.

| Mode | Entries/s (median) | All runs | p50 ms | p95 ms | p99 ms |
|---|---:|---|---:|---:|---:|
| Single append, 1 client, 1 entry per transaction | **201** | 203 / 163 / 201 | 3.6 | 11.9 | 23.3 |
| Group commit, 16 clients, 1 entry per request | 1,482 | 2,968 / 1,482 / 1,230 | 8.0 | 24.5 | 45.8 |
| Group commit, 64 clients, 1 entry per request | **6,765** | 12,894 / 6,765 / 5,949 | 7.8 | 17.3 | 28.6 |
| Batch of 10, 1 client | 2,071 | 3,515 / 2,071 / 2,025 | 3.6 | 10.8 | 19.5 |
| Batch of 100, 1 client | 14,589 | 25,486 / 14,464 / 14,589 | 4.8 | 14.3 | 21.4 |
| Batch of 1,000, 1 client | **33,543** | 39,993 / 27,284 / 33,543 | 14.4 | 60.1 | 96.4 |

Reading it:

- A single durable commit costs ~3.6 ms here (WSL2 virtual disk fsync plus the Docker port proxy), so one client
  appending one entry per transaction tops out around 200/s. That is the number to compare everything else with.
- Group commit turns concurrency into larger transactions: 64 clients each sending single entries reach 6,765/s
  (34× single) at a p50 of 7.8 ms per request. No client batches anything; the server does.
- Explicit batches amortise the commit: 1,000 entries per transaction reach 33,543 entries/s.

### The 8 KiB write-buffer stall (found by this benchmark)

The first run showed batch-of-100 appends *slower* than batch-of-10 (1,042 vs 1,908 entries/s) with a flat ~92 ms
per transaction. Large Bind messages were leaving Npgsql's default 8 KiB write buffer in many socket writes, and
every append bigger than the buffer stalled about 90 ms on this host. The server now defaults to a 256 KiB write
buffer (`PersistenceExtensions.CreateDataSource`). Same harness, `Write Buffer Size=8192` forced, median of 3 runs:

| Mode | Npgsql default 8 KiB buffer | Server default 256 KiB | Change |
|---|---:|---:|---:|
| Batch of 100 | 1,042 /s, p50 92.4 ms | 14,589 /s, p50 4.8 ms | 14.0× |
| Batch of 1,000 | 9,601 /s, p50 100.9 ms | 33,543 /s, p50 14.4 ms | 3.5× |
| Group commit, 64 clients | 4,991 /s, p50 9.4 ms | 6,765 /s, p50 7.8 ms | 1.4× |
| Single, 1 client | 183 /s | 201 /s | within noise |

The ~90 ms constant looks like a Nagle / delayed-ACK interaction in the Windows-to-WSL2 port forwarding; that cause
is a hypothesis, not measured. It was not reproduced on Linux, where the stall may be smaller or absent. The larger
buffer costs 256 KiB per pooled connection.

## 2. Proof generation latency vs tree size (up to 1,000,000 leaves)

One log grows to 1,000,000 leaves in batches of 1,000. At each checkpoint, while the tables really have that many
rows, 500 inclusion proofs for random leaves and 300 consistency proofs from a random earlier size are generated
through `ProofBuilder` over PostgreSQL: plan, **one** SQL round trip (`unnest` join on the primary key), fold.
Median over 3 runs of the per-run percentiles.

| Tree size | Proof length (hashes) | Inclusion p50 | Inclusion p95 | Inclusion p99 | Consistency p50 | Consistency p95 |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 10 | 0.87 ms | 1.90 ms | 2.70 ms | 0.95 ms | 1.87 ms |
| 10,000 | 14 | 0.97 ms | 3.67 ms | 8.92 ms | 0.87 ms | 2.15 ms |
| 100,000 | 17 | 0.97 ms | 3.22 ms | 6.53 ms | 0.89 ms | 2.09 ms |
| 1,000,000 | 20 | **0.94 ms** | 3.12 ms | 5.22 ms | **0.84 ms** | 2.40 ms |

Proof latency is flat from 1 K to 1 M leaves: the work is O(log n) primary-key lookups in one round trip, and the
round trip dominates. Loading 1,000,000 entries took 33.7 s (median, batches of 1,000, including the checkpoint
measurements). Table sizes at 1 M: **156 MB `entries`, 222 MB `tree_nodes`** (≈ 2 node rows per entry, with indexes).

Not measured: proof latency through HTTP (adds Kestrel and JSON serialisation), and trees beyond 1 M leaves (the
harness supports `proofs 5000000`; disk space on this machine was the constraint).

## 3. Verification cost

BenchmarkDotNet 0.15.8, ShortRun (3 iterations, so treat ±10 % as noise), **median** column. Proofs come from an
in-memory tree of 1,060,921 leaves; every size is a real historic size of that tree. Full table:
[`benchmark-results/micro.md`](../benchmark-results/micro.md).

| Operation | 1,000 leaves | 100,000 leaves | 1,000,000 leaves | Allocated (1 M) |
|---|---:|---:|---:|---:|
| Verify inclusion proof (RFC 9162 algorithm) | 3.0 µs | 4.3 µs | **4.2 µs** | 1,216 B |
| Verify consistency proof (n/2+1 → n) | 4.7 µs | 5.4 µs | **8.0 µs** | 1,784 B |
| Build inclusion proof from in-memory nodes | 5.1 µs | 2.9 µs | 4.8 µs | 9,248 B |
| Encode + hash one audit entry | 0.51 µs | 0.25 µs | 0.35 µs | 200 B |

(The 1,000-leaf "build" row had one 300 ms outlier iteration, visible in the mean; the median is used.)

### Full independent audit of 1,000,000 entries

`LogAuditor` reading straight from the store (no HTTP): re-encode and hash every row, stream every stored leaf,
recompute both roots, compare with the signed head, spot-check proofs.

| Rows | Time (median of 3) | Rows/s | Result |
|---:|---:|---:|---|
| 1,000,000 | 22.1 s | 45,300 | clean |

Through the HTTP API (pages of 1,000) the audit additionally pays JSON serialisation; the integration test audits
2,500 entries that way, the compose demo 200 entries six times. A 1 M-row audit over HTTP was not timed.
