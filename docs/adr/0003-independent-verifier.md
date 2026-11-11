# 0003: An independent verifier that shares no code with the log

- Status: accepted
- Date: 2026-11-11

## Context

A tamper-evident log is checked by someone who does not trust the log's operator, and often does not run its code.
If the verifier reused the server's tree code, one bug (an off-by-one in the split point, a wrong prefix) would be
present on both sides and every proof would "verify". The verifier also has to be usable on its own: as a library
in another service, and as a CLI an auditor runs against a URL.

## Options considered

1. **One shared library for building and checking.** Least code. A shared bug is invisible, and the "independent"
   check is not independent.
2. **Use a third-party verifier** (for example transparency-dev/merkle in Go). Truly independent, but the audit
   also needs this log's leaf encoding and tamper classification, and a second runtime in CI.
3. **A separate .NET assembly written from the RFC text, with no project reference to the server or Core
   (chosen).** Different algorithms on purpose, cross-checked by property tests and published vectors.

## Decision

- `MerkleAudit.Verifier` references nothing from this repository. It has its own RFC 6962 hashing, its own leaf
  encoding written from [docs/log-format.md](../log-format.md), its own tree-head serialisation and its own streaming
  root computation.
- Proof checking uses the **iterative** algorithms of RFC 9162 sections 2.1.3.2 and 2.1.4.2 (walk the bits of the
  leaf index and tree size). The server generates proofs with the **recursive** RFC 6962 `PATH` / `SUBPROOF`
  definitions. Two algorithms, two code bases, one specification.
- They are tied together by: the CT reference vectors (both sides must produce/accept them exactly); FsCheck
  properties that every server-built inclusion proof verifies for any leaf and size up to 3,000, that consistency
  holds between any two sizes, that flipping any bit breaks a proof, and that both leaf encodings agree byte for
  byte on arbitrary strings; and integration tests that verify every leaf of a real PostgreSQL-backed log.
- `merkle-verify` (CLI, packable as a dotnet tool) has three commands: `audit` (full replay, exit 2 on tampering),
  `inclusion --seq N` and `consistency` against a witness file of previously verified heads. It only trusts keys
  given on the command line.

## Consequences

- About 400 lines exist twice (hashing, encoding, root folding). That is the price of the independence and is
  deliberate; the property tests keep the copies honest.
- The encoding is specified in a document, not in code, so a verifier in another language can be written from it.
- The demo, the golden test and the CI compose job all detect tampering through this verifier, over HTTP, never
  through the server's own view of itself.
