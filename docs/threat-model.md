# Threat model

merkle-audit makes an audit trail **tamper-evident**, not tamper-proof. Someone with enough access can always change
bytes in a database. The goal is that no change to history goes unnoticed by an auditor holding a pinned public key,
and that the auditor can say what changed.

## Assets

| Asset | Why it matters |
|---|---|
| Audit entries (`audit.entries`) | The evidence: who did what to which record, when |
| Tree nodes (`audit.tree_nodes`) | The log's memory of every entry; makes exact pinpointing possible |
| Signed tree heads (`audit.tree_heads`, and copies held by auditors) | The only commitments that bind the operator |
| Tree-head signing key | Whoever holds it can sign any history |
| Pinned public keys at verifiers | Whoever can replace them can make a forged log verify |

## Actors

| Actor | Capability assumed |
|---|---|
| Application user / client with an API key | Can append entries. Cannot read the database directly |
| Anonymous reader | Can read the whole log over HTTP (transparency is a feature) |
| Application (role `audit_app`) | SELECT/INSERT on log tables, UPDATE on `tree_state` only |
| Schema owner (`audit_migrator`) | DDL; blocked by the append-only triggers like everyone else who respects them |
| **Rogue DBA / superuser / attacker with database credentials** | Anything inside PostgreSQL: bypass triggers (`session_replication_role = replica`), edit any row, rewrite the tree, delete tree heads |
| Attacker with the signing key | Can sign new heads |
| Auditor / monitor | Runs `merkle-verify` with pinned keys, keeps a witness file of verified heads |

## Threats and mitigations (STRIDE)

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | **Tampering**: DBA edits, deletes, reorders or inserts rows | Rows must hash to leaves stored separately; leaves must reproduce signed roots. Each case is pinpointed (`RowAltered`, `RowDeleted`, `RowMoved`, `RowNotInTree`). Demonstrated by the compose demo and the golden test | Detection happens at the next audit, not at the moment of the change |
| T2 | **Tampering**: DBA also rewrites leaves, ancestors and `tree_state` consistently | Signed heads published earlier no longer match; the change is localised to the interval between two heads. Consistency proofs between heads fail. The publisher refuses to sign a tree that does not extend its last head (`tree_heads.refused`) | Granularity = publish interval (1 s demo, 10 s default). An attacker who rewrites history **before** the first head covering it was ever copied off the database is undetectable: see T5 |
| T3 | **Tampering**: interior nodes changed (to make forged proofs) | Proofs are verified against signed roots by the client/auditor; the auditor spot-checks inclusion and checks consistency between consecutive heads | Spot checks are sampled; a full proof sweep is O(n log n) and optional |
| T4 | **Repudiation / truncation**: heads deleted from `tree_heads`, log truncated | Auditor's witness file: a previously verified head missing from history is `WitnessedHeadMissing`; a head larger than the log is `LogTruncated` | Requires auditors to keep witness state somewhere the DBA cannot write |
| T5 | **Split view / fork**: operator shows different logs to different auditors | Two signed roots for one size are `ConflictingTreeHeads` if one auditor sees both. Gossip between auditors, or publishing heads to an external witness (transparency-log witnesses, a ticketing system, email), closes it | No built-in external witness network; listed as next step |
| T6 | **Spoofing**: forged tree heads | ECDSA P-256 signatures; key id derived from the pinned key; untrusted keys rejected | Depends on key secrecy (T7) |
| T7 | **Signing key compromise** | Key file mode 0600 in its own volume, never mounted into verifier containers; rotation with `notAfter` so a retired key cannot extend the log ([key-rotation.md](key-rotation.md)) | A compromised *active* key lets the attacker sign a rewritten history from the point of compromise onward; heads copied out before the compromise still expose earlier changes. Production should use a KMS/HSM |
| T8 | **Spoofing**: verifier's trust anchors replaced | Keys are pinned out of band; the CLI never fetches keys from the log (`/keys` is informational) | Operational: protect the auditor's key files like the witness file |
| T9 | **Tampering at write time**: client sends false content or a back-dated entry | Server stamps `occurred_at`; API key required to append; input validation and size limits | The log proves what was recorded, not that it was true |
| T10 | **Information disclosure**: the log is publicly readable | Designed for synthetic or non-sensitive audit metadata. Store references (`patient/P-000123`), not personal data; put readers behind a gateway if the content is sensitive | Entries cannot be deleted for erasure requests without breaking the tree: personal data must not go into payloads (see README privacy note) |
| T11 | **Denial of service**: append flooding, huge payloads, huge proof requests | Request body limit 4 MiB, payload 64 KiB, batch 1,000, bounded group-commit queue (back-pressure), page size cap 1,000, proofs O(log n) | No rate limiting in the service; put it behind an API gateway |
| T12 | **Elevation of privilege** via the app role | `audit_app` has no UPDATE/DELETE on log tables, cannot create objects, cannot read migration history (integration-tested) | A SQL injection would still allow INSERT; all SQL is parameterised |

## Out of scope

- Proving that an event happened (only that it was logged and not changed afterwards).
- Confidentiality of entries at rest (use disk/column encryption; see field-level encryption elsewhere).
- Availability guarantees of the log itself (backups, replication).
