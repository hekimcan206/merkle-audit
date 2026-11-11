# 0004: One writer at a time via a row lock, throughput via group commit

- Status: accepted
- Date: 2026-11-11

## Context

A Merkle log is a sequence: entry n's position, its leaf and every ancestor node depend on all entries before it.
Two concurrent appends must never get the same sequence number, never leave a gap, and never compute ancestors from
different frontiers. At the same time an audit log sits on the hot path of the system it audits, so append
throughput matters, and the system may run more than one API instance.

## Options considered

1. **SERIALIZABLE transactions, retry on conflict.** Correct, but every concurrent append conflicts on the same
   frontier rows, so under load most transactions abort and retry.
2. **`pg_advisory_xact_lock`.** Works, but the lock is invisible in the schema and easy to forget in a second code
   path.
3. **`SELECT ... FOR UPDATE` on the one-row `tree_state` (chosen).** The row that holds the size and root is the
   lock. Every writer, in any instance, must take it before reading the frontier, so the serialisation point is the
   data itself.
4. **Sequencer/integrator split** (Trillian): assign sequence numbers quickly, build the tree asynchronously. Higher
   ingest rates, but entries are not in the tree (and not provable) when the append returns, and the design needs a
   background integrator with its own failure modes.

## Decision

- `LogStore.AppendAsync` takes the `tree_state` row lock, reads the frontier, inserts entries and completed nodes
  with `INSERT ... SELECT * FROM unnest(...)` (one statement each, whatever the batch size), updates `tree_state`
  and commits. When it returns, the entries are durable and provable.
- `GroupCommitWriter` funnels every append in the process (single and batch requests) through one queue. A single
  writer drains what is waiting, up to `Log:MaxGroupCommit` (1,000) entries, into one transaction, then hands each
  caller its own sequence numbers. Concurrency becomes larger transactions instead of lock contention.
- Back-pressure: the queue is bounded (`Log:QueueCapacity`); a caller that gives up waiting does not withdraw its
  entry (it is committed or failed with its group, never half).
- `lock_timeout = 5 s` bounds how long a second instance waits; a timeout becomes a retryable 503.

## Consequences

- Measured (see [benchmarks](../benchmarks.md)): one entry per transaction is bounded by commit latency; group
  commit with many clients and explicit batches are an order of magnitude faster. The numbers are in the README.
- Two server instances on one database produce one contiguous tree (integration test
  `Two_server_instances_on_one_database_extend_the_same_tree`).
- Ingest is ultimately bounded by a single writer per log. Sharding into several logs (per tenant or per day) is the
  scaling path; it is a limitation, not a hidden assumption.
