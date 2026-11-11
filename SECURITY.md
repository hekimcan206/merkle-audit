# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository. You can expect an acknowledgement within 5 working days. If
the report is confirmed, a fix or mitigation plan follows within 30 days.

Please include the affected version or commit, steps to reproduce and the impact you observed. Reports about the
verifier accepting a proof or tree head it should reject are especially welcome.

## Security-relevant design

See [docs/threat-model.md](docs/threat-model.md) for assets, actors, threats and mitigations. In short:

| Area | Default |
|---|---|
| Tamper evidence | RFC 6962 Merkle tree; rows, stored leaves and signed heads are checked against each other by an independent verifier |
| Tree heads | ECDSA P-256 / SHA-256 over the RFC 6962 tree-head structure; the signer refuses to sign a tree that does not extend its last head |
| Trust anchors | Verifiers pin public keys out of band; retired keys are trusted only up to their `notAfter` |
| Signing key | PKCS#8 PEM file, mode 0600, in its own volume; never mounted into verifier containers |
| Database access | Server runs as `audit_app` (SELECT/INSERT only on log tables); migrations as `audit_migrator`; append-only triggers on entries, nodes and heads |
| Write access | `X-Api-Key` required to append, compared in constant time; reads are public by design |
| Input limits | 4 MiB request body, 64 KiB payload, 1,000 entries per batch, page size 1,000, bounded write queue |
| Secrets | None in the repository. `.env.example` holds clearly marked development-only values |
