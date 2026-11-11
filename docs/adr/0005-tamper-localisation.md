# 0005: Detect every change, pinpoint it exactly when the tree still remembers, localise it when not

- Status: accepted
- Date: 2026-11-11

## Context

"Tamper-evident" is often demonstrated as "the root changed". That tells an investigator nothing. The question after
an incident is *which* records were changed, deleted, inserted or reordered. The realistic attacker here is a
database administrator (or anyone with the superuser password), who can bypass privileges and triggers and edit any
table, including the tree.

## Options considered

1. **Compare the recomputed root with the latest signed root.** Detects, cannot locate.
2. **A monitor that mirrors every leaf hash it has seen.** Exact, but it is a second copy of the log to operate and
   protect, and the Merkle tree adds little on top.
3. **Three layers of trust, checked in order (chosen)**: signed heads, stored leaf hashes, rows.

## Decision

The auditor (`LogAuditor`) trusts nothing it has not checked:

1. **Signed heads** are trusted only after the signature check with a pinned key. Heads from a witness file (heads
   the auditor verified on earlier runs) are added as anchors, and a witnessed head missing from the log's history is
   itself a finding.
2. **Stored leaf hashes** (`tree_nodes` level 0) are trusted only if, folded together, they reproduce **every**
   signed root. They live apart from the rows on purpose ([ADR 0001](0001-rfc6962-merkle-tree-with-stored-perfect-subtrees.md)).
3. **Rows** are trusted only if they hash to those leaves.

When layer 2 holds, every row-level difference is exact, because the tree still remembers the original leaf:

| What the attacker did | Finding |
|---|---|
| `UPDATE` a row | `RowAltered` at that seq (recomputed leaf != committed leaf) |
| `DELETE` a row | `RowDeleted` at that seq (committed leaf has no row) |
| swap two rows' content | `RowMoved` both ways: the row at 60 hashes to the leaf committed at 61 once its seq is put back |
| delete and renumber the rest | `RowMoved` chain plus one `RowDeleted` for the entry that exists nowhere |
| `INSERT` a forged row | `RowNotInTree` |

When layer 2 fails, the attacker also rewrote the tree. The auditor then replays two running roots (stored leaves
and recomputed rows) and compares them with each signed head in size order: the change is in the interval between
the last head that still matches and the first that does not (`StoredTreeRewritten`,
`RowsDivergeFromSignedHistory`). With a head every 25 entries in the demo, that interval is 25 entries.

Finally the auditor uses the log's proof API like a client would: inclusion proofs for sampled and flagged entries,
and consistency proofs between consecutive signed heads. Proofs are built from interior nodes, which the replay never
reads, so this catches tampering with interior nodes alone (`InclusionProofFailed`, `ConsistencyProofFailed`).

## Consequences

- The golden test and the compose demo show each case against real PostgreSQL; the report format is stable and
  compared byte for byte.
- Localisation granularity after a full rewrite equals the publication interval. Publishing more often (or a
  monitor that stores heads more often) narrows it; per-entry signed receipts (like CT's SCTs) would make it exact
  and are listed as a next step.
- Classification of moves is O(k²) in the number of differing rows, capped at 256 (beyond that the auditor reports
  `TooManyDifferences` from the first divergent seq). Detection itself is O(n) and uncapped.
- Entries appended after the latest signed head are an "unsigned tail": checked against stored leaves only, because
  nothing outside the database commits to them yet.
