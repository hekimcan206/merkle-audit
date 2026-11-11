# 0006: A length-prefixed binary leaf encoding that includes the sequence number

- Status: accepted
- Date: 2026-11-11

## Context

The leaf hash covers "the entry". Which bytes that means must be defined so precisely that an independent verifier,
possibly in another language, reproduces it from the rows the database returns. PostgreSQL round-trips are the trap:
`jsonb` re-orders keys and drops whitespace, `timestamptz` keeps microseconds while .NET has 100 ns ticks.

## Options considered

1. **Hash the JSON of the entry as the API received it.** The stored form differs from the received form as soon as
   any column type normalises.
2. **JSON Canonicalization Scheme** ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) over the whole entry.
   Well-defined, but number formatting and Unicode rules make independent implementations subtle, and the payload
   would have to be re-canonicalised on every read.
3. **A small binary format with explicit lengths (chosen)**, plus storing the payload byte-for-byte as `text`.

## Decision

Format version 1 ([log-format.md](../log-format.md)):
`u8 version=1 || i64 seq || i64 occurred_at_µs || (u32 len || UTF-8) × {actor, action, resource, payload}`,
all big-endian.

- **Length prefixes** make the encoding injective: `("ab", "")` and `("a", "b")` encode differently
  (FsCheck property `Leaf_encoding_is_injective_across_field_boundaries`).
- **The sequence number is inside the leaf.** A row moved to another position fails even if someone also moves its
  leaf, and the auditor can recognise a moved row by re-encoding it with the other seq.
- **Payload is stored as `text`**, exactly as sent, with a size check; JSON validity is checked by the API on input.
- **Time is truncated to microseconds** before hashing, so the hashed value is exactly what `timestamptz` returns.
- The server stamps `occurred_at` (server time); clients cannot back-date entries through the API.
- The version byte lets a future format coexist: a verifier dispatches on it.

## Consequences

- Both encoders (server `LeafCodec`, verifier `EntryRecord.LeafInput`) are tested to agree byte for byte on
  arbitrary strings, and the server's leaf hashes returned by the append API are reproduced by the verifier in the
  integration tests.
- Payload JSON is opaque to the hash: two semantically equal payloads with different whitespace are different
  entries. That is the right behaviour for evidence.
