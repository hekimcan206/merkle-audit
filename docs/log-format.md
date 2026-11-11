# Log format (version 1)

This document is the contract between the log and any verifier. The server (`MerkleAudit.Core`) and the
independent verifier (`MerkleAudit.Verifier`) are both implemented from it, separately.

## Leaf input

Each audit entry becomes one leaf. All integers are big-endian.

| Field | Type | Notes |
|---|---|---|
| version | `u8` | `1` |
| seq | `i64` | 0-based position in the log; equals the leaf index |
| occurred_at | `i64` | microseconds since 1970-01-01T00:00:00Z, stamped by the server |
| actor | `u32` length + UTF-8 bytes | 1 to 200 characters |
| action | `u32` length + UTF-8 bytes | 1 to 200 characters |
| resource | `u32` length + UTF-8 bytes | 1 to 500 characters |
| payload | `u32` length + UTF-8 bytes | JSON text exactly as received, at most 64 KiB |

Leaf hash: `SHA-256(0x00 || leaf_input)` (RFC 6962 section 2.1).

## Tree

RFC 6962 section 2.1 Merkle Tree Hash over the leaf inputs in `seq` order:

- `MTH({}) = SHA-256()` (`e3b0c442...b855`)
- `MTH({d}) = SHA-256(0x00 || d)`
- `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`, `k` = largest power of two `< n`

Inclusion and consistency proofs are RFC 6962 section 2.1.1 / 2.1.2, in the same order; they verify with the RFC 9162
section 2.1.3.2 / 2.1.4.2 algorithms.

## Signed tree head

Signature input (RFC 6962 section 3.5), 50 bytes:

| Field | Type | Value |
|---|---|---|
| version | `u8` | `0` |
| signature_type | `u8` | `1` (tree_hash) |
| timestamp | `u64` | milliseconds since the epoch |
| tree_size | `u64` | |
| sha256_root_hash | `u8[32]` | |

Signature: ECDSA P-256 with SHA-256, DER encoded. Key id: lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.

## HTTP API (v1)

| Method and path | Returns |
|---|---|
| `POST /api/v1/entries` (X-Api-Key) | `{seq, occurredAt, leafHash}` |
| `POST /api/v1/entries/batch` (X-Api-Key) | array of the above, one transaction |
| `GET /api/v1/entries?after=&limit=` | `{entries: [{seq, occurredAt, occurredAtMicros, actor, action, resource, payload}]}` |
| `GET /api/v1/tree` | `{treeSize, rootHash}` (current, unsigned) |
| `GET /api/v1/tree/leaves?after=&limit=` | `{leaves: [{index, hash}]}` (stored leaf hashes) |
| `GET /api/v1/sth` | `{treeSize, timestamp, rootHash, keyId, signature}` (latest signed head) |
| `GET /api/v1/sth/history` | `{heads: [...]}` (every signed head) |
| `GET /api/v1/proofs/inclusion?leafIndex=&treeSize=` | `{leafIndex, treeSize, auditPath: [hex]}` |
| `GET /api/v1/proofs/consistency?first=&second=` | `{first, second, consistency: [hex]}` |
| `GET /api/v1/keys` | public keys (informational; pin keys out of band) |

Hashes are lowercase hex; signatures are base64. Page `limit` is capped at 1,000.
