# 0002: Signed tree heads with ECDSA P-256, key ids derived from the key, rotation by "not after"

- Status: accepted
- Date: 2026-11-11

## Context

The Merkle root alone proves nothing to an outsider: whoever controls the database can recompute a new root after
changing a row. A root becomes a commitment only when it is **signed** and **copied somewhere the operator cannot
reach** (a monitor, an auditor's witness file, a ticket, an email). RFC 6962 calls this a Signed Tree Head (STH):
`(tree_size, timestamp, root)` signed by the log's key.

Requirements: a standard signature input that other tools can verify, an algorithm available in .NET 10 without
extra native dependencies, key rotation that never invalidates history, and protection against a compromised
*retired* key being used to sign new heads.

## Options considered

1. **HMAC over the root.** Symmetric: everyone who can verify can also forge. Useless for third-party audit.
2. **Ed25519.** Small keys, deterministic signatures, the choice of Sigsum and many newer logs. .NET 10's
   `System.Security.Cryptography` does not include Ed25519 (it added ML-DSA/ML-KEM/SLH-DSA instead), so it would
   need BouncyCastle or a libsodium binding: one more cryptographic dependency to pin and audit.
3. **ECDSA P-256 with SHA-256 (chosen).** One of the two algorithms RFC 6962 allows for logs, built into .NET on
   every platform, hardware-backed in most KMS/HSM products. Signatures are randomised, which is fine for STHs.
4. **RSA.** Allowed by RFC 6962, but larger keys and signatures for no benefit here.

## Decision

- The signed bytes are the RFC 6962 section 3.5 tree-head structure: `version(0) || signature_type(1) ||
  u64 timestamp_ms || u64 tree_size || root[32]`, big-endian, 50 bytes (`TreeHead.ToSignatureInput`). Signatures
  are DER (RFC 3279), as in CT.
- The **key id** is the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo, like a CT log id. It is computed by
  the verifier from the key it trusts, so a head cannot claim to be signed by a trusted key it was not signed with.
- **Verifiers pin keys out of band** (`--key`/`--key-dir`, or the demo's `trusted-keys` volume). `GET /api/v1/keys`
  exists only for humans; a log that hands out its own trust anchors can sign anything.
- **Rotation** ([key-rotation.md](../key-rotation.md)): distribute the new public key first, switch
  `Signing:KeyFile`, keep the old public key trusted with `notAfter` = rotation time. Heads signed by the old key
  before `notAfter` stay valid forever; heads it signs after are rejected ("signed by a retired key after its
  retirement"), so a leaked old key cannot extend the log.
- The publisher signs on a schedule (`Log:PublishInterval`, 1 s in the demo, 10 s by default) when the tree grew,
  and at least every `Log:MaxHeadAge` (1 h) even when it did not, so monitors can tell a quiet log from a stalled
  one. Timestamps never go backwards.
- **The signer never signs a fork.** Before signing, it checks that the stored nodes still reproduce the last signed
  root and that `tree_state` matches them; otherwise it refuses, logs at Critical and counts
  `merkle_audit.tree_heads.refused`. This was added after the tamper demo showed that a tree rewritten between two
  publications would otherwise be signed on the next tick.

## Consequences

- Any CT-style tool can verify a head with the public key and the 50-byte structure.
- The private key is a file (PKCS#8 PEM, mode 0600, separate Docker volume from the verifier's public keys). A
  production deployment would keep it in a KMS/HSM and sign remotely; the signer is one class (`TreeHeadSigner`)
  to swap. Listed under limitations.
- Signature freshness is bounded by the publish interval: entries newer than the latest head are reported by the
  verifier as an "unsigned tail", checked only against the stored leaves.
