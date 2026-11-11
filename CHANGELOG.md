# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-11

### Added

- RFC 6962 Merkle tree over audit entries: domain-separated leaf (0x00) and node (0x01) hashing, frontier-based
  appends, perfect subtrees stored once as immutable rows in PostgreSQL (`audit.tree_nodes`, level 0 included).
- Proof API: inclusion and consistency proofs for any historic tree size, built from one SQL round trip.
- Signed tree heads: ECDSA P-256 / SHA-256 over the RFC 6962 tree-head structure, published on a schedule and on
  growth, key id derived from the public key, documented key rotation with `notAfter` for retired keys.
- The publisher refuses to sign a tree that no longer reproduces its last signed root.
- Independent verifier library (`MerkleAudit.Verifier`, no code shared with the server): RFC 9162 iterative proof
  verification, tree-head signature checks against pinned keys, and a full tamper audit that pinpoints altered,
  deleted, moved and uncommitted rows and localises full tree rewrites between signed heads.
- `merkle-verify` CLI (`audit`, `inclusion`, `consistency`, witness file), packable as a dotnet tool.
- Group-commit writer: concurrent appends share one locked transaction; explicit batch endpoint.
- Least-privilege PostgreSQL roles (`audit_migrator`, `audit_app`, `audit_reader`) and append-only triggers.
- `docker compose up` tamper demo: synthetic seeding, five rogue-DBA attacks as the PostgreSQL superuser, each detected
  over HTTP by the independent verifier and undone.
- Tests: CT reference vectors (transparency-dev/merkle), FsCheck properties (every inclusion proof verifies,
  consistency between any two sizes, encodings agree), Testcontainers integration tests and a byte-for-byte golden
  tamper report.
- Benchmarks: PostgreSQL append throughput (single, group commit, batches), proof latency up to 1,000,000 leaves,
  verification cost, full-audit throughput.
- ADRs, threat model, log format specification, key-rotation runbook, CI with vulnerability audit, CodeQL, container
  and compose-demo jobs.

### Fixed

- Large appends were stalling ~90 ms each on the benchmark host because Npgsql's default 8 KiB write buffer split
  every multi-kilobyte Bind message into many socket writes; the server now defaults to a 256 KiB write buffer
  (batch of 100: 1,042 → 14,589 entries/s, batch of 1,000: 9,601 → 33,543 entries/s, medians of 3 runs).

[Unreleased]: https://github.com/hekimcan206/merkle-audit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hekimcan206/merkle-audit/releases/tag/v1.0.0
