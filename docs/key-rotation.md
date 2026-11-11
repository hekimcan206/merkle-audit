# Tree-head key rotation

Tree heads are signed with one active ECDSA P-256 key. Each head carries the key id (SHA-256 of the public key),
so heads signed by different keys coexist in one history. Rotating never re-signs or invalidates old heads.

## When

- On a schedule (for example yearly), or when staff with key access leave.
- Immediately if the key may have leaked (see "Compromise" below).

## Steps

1. **Generate the new key** somewhere the server can read it:

   ```bash
   docker compose run --rm keygen --ensure-key /keys/next /trusted
   # or locally: dotnet run --project src/MerkleAudit.Server -- --ensure-key ./.keys/next ./.keys/trusted
   ```

   This writes `next/sth-signing.pem` (private, mode 0600) and `trusted/<new key id>.pub.pem`.

2. **Distribute the new public key to every verifier first.** Add it next to the old one (`--key-dir` picks up both).
   Verifiers that do not know the new key would reject every head signed after the switch.

3. **Switch the signer**: point `Signing:KeyFile` at the new private key, move the old *public* key to
   `Signing:RetiredPublicKeyFiles` (so `GET /api/v1/keys` lists it as retired), restart or roll the servers.
   The next head is signed with the new key.

4. **Retire the old key at verifiers**: keep trusting it, but only for heads before the switch:

   ```bash
   merkle-verify audit --log https://log.example --key new.pub.pem \
       --key old.pub.pem,notAfter=2026-11-11T12:00:00Z
   ```

   Heads signed by the old key after `notAfter` are rejected with "signed by a retired key after its retirement".

5. **Destroy the old private key** once the switch is confirmed (`GET /api/v1/sth` shows the new key id).

The behaviour is covered by `TreeHeadSigningTests.Rotation_keeps_history_valid_and_bounds_the_retired_key`.

## Compromise

If the active key leaked, an attacker can sign heads for a rewritten history. Rotate as above with `notAfter` set
to the **earliest possible compromise time**, not the rotation time, and re-audit from the witness files auditors
kept: every head they copied before the compromise still binds the history up to its size, so any rewrite of that
part is still detected. Heads signed between compromise and rotation must be treated as untrusted and re-checked
against the rows.

## Why not rotate per head or per day automatically?

Every verifier must learn every new public key before it is used. Automatic rotation without an authenticated key
distribution channel just moves the trust problem; it is listed as a next step (keys in a KMS with an attested
public-key endpoint).
