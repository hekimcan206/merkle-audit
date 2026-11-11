# 0001: RFC 6962 Merkle tree, stored as immutable perfect subtrees in PostgreSQL

- Status: accepted
- Date: 2026-11-11

## Context

An audit log is only useful if someone who does not trust the operator can check two things cheaply:

1. **Inclusion**: "my entry is in the log the operator committed to".
2. **Append-only**: "today's log extends yesterday's log; nothing before was changed or removed".

A hash chain (each row stores `H(prev || row)`) gives the second property only to someone who replays the whole
chain, and gives no short proof of the first. Certificate Transparency solved both with a Merkle tree over the log
([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), updated by [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)):
an inclusion proof and a consistency proof are both O(log n) hashes. The same construction was proposed for
tamper-evident logging in general by Crosby and Wallach ("Efficient Data Structures for Tamper-Evident Logging",
USENIX Security 2009).

The tree also has to live somewhere. Proofs must be served for any historic tree size (a monitor asks "prove size
150 is a prefix of size 200"), with predictable latency at a million leaves and beyond, and writes must stay cheap.

## Options considered

**Tree shape and hashing**

1. **Own binary tree, no domain separation.** Simple, but `H(left || right)` for an interior node and `H(data)` for
   a leaf are indistinguishable, which allows a second-preimage attack: a 64-byte "leaf" equal to two child hashes
   produces the same root as a different tree. Rejected.
2. **RFC 6962 (chosen).** `MTH({d}) = SHA-256(0x00 || d)`, `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`
   with `k` the largest power of two below `n`. The 0x00/0x01 prefixes are the domain separation. It is a standard,
   so third-party verifiers exist and published test vectors can pin the implementation down.

**Storage**

1. **Store only leaf hashes, compute everything else per request.** No write amplification, but a proof for
   size 1 M needs ~1 M hashes. Rejected.
2. **Store every node of the current tree, including the right edge.** Right-edge nodes change on every append, so
   the table needs UPDATEs (which the append-only design forbids) and proofs for historic sizes need old versions.
3. **Tiles** (Trillian/Tessera, Sigsum): fixed-height subtrees grouped into immutable objects, ideal for static
   file serving and CDN caching. More moving parts than a single-database service needs.
4. **Every perfect, aligned subtree, as one row each (chosen).** A node `(level, idx)` covers leaves
   `[idx·2^level, (idx+1)·2^level)` and is written once, when its last leaf arrives; it never changes. Level 0 holds
   the leaf hashes. On average two rows per leaf.

## Decision

- Hashing follows RFC 6962 exactly (`Rfc6962`), checked against the Certificate Transparency reference vectors from
  [transparency-dev/merkle](https://github.com/transparency-dev/merkle) (`testonly/constants.go`,
  `proof/verify_test.go`): roots for sizes 0 to 8 and published inclusion and consistency proofs.
- `audit.tree_nodes(level, idx, hash)` stores perfect subtrees. An append reads only the frontier (one node per set
  bit of the size, at most 63) inside the locked transaction, folds new leaves in (`TreeAppender`) and inserts the
  completed nodes. Nothing is updated except the one-row `tree_state` (size and root).
- Proofs are planned as RFC 6962 `PATH`/`SUBPROOF` leaf ranges (`TreeMath`), each range is split into perfect
  subtrees, all needed nodes are fetched in **one** query (`unnest` join on the primary key), then folded. Because
  perfect subtrees are immutable, the same rows serve proofs for every historic size.
- The leaf hashes are stored in `tree_nodes`, not as a column of `entries`. Deleting or editing a row therefore does
  not erase the tree's memory of it, which is what makes exact tamper pinpointing possible ([ADR 0005](0005-tamper-localisation.md)).

## Consequences

- Write cost is ~2 node rows per entry; the 1 M-leaf benchmark puts `tree_nodes` at roughly the size of `entries`
  for small entries (see [benchmarks](../benchmarks.md)).
- Proof generation is O(log n) primary-key lookups in one round trip; its latency is measured as a function of tree
  size up to 1 M leaves.
- A missing node is an error, never silently recomputed: the store is the source of truth, and a gap means
  tampering or corruption.
- Serving proofs needs the database. A static, cacheable tile layout (option 3) is the natural next step if read
  traffic ever dominates; it is listed in the README's limitations.
