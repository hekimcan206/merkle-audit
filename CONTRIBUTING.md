# Contributing

Thanks for taking the time to improve merkle-audit.

## Prerequisites

- .NET SDK 10.0.400 or later (`global.json` rolls forward to the latest feature band)
- Docker (integration tests start PostgreSQL through Testcontainers; `docker compose up` runs the demo)

## Workflow

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Branch from `main` and keep each pull request to one concern.
3. Before pushing:

   ```bash
   dotnet build                 # must be warning-free: warnings are errors
   dotnet test                  # unit, vector, property and integration tests (Docker running)
   dotnet format --verify-no-changes
   ```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are required. They keep the history readable, make the
hand-written CHANGELOG easy to assemble at release time, and show which version bump a change needs:

- `feat:` new capability (minor bump)
- `fix:` bug fix (patch bump)
- `feat!:` or a `BREAKING CHANGE:` footer (major bump)
- `docs:`, `test:`, `build:`, `ci:`, `refactor:`, `perf:`, `chore:` for everything else

## Changing the tree, the leaf encoding or the tree-head format

These are the contract with every verifier ([docs/log-format.md](docs/log-format.md)). A change:

1. must keep the RFC 6962 reference vectors (`tests/MerkleAudit.UnitTests/Vectors`) green;
2. needs the same change, written independently, in `src/MerkleAudit.Verifier` (it must not reference the server or
   Core: see [ADR 0003](docs/adr/0003-independent-verifier.md)), and the FsCheck agreement properties stay green;
3. bumps the leaf format version byte if existing leaves would hash differently, and updates `docs/log-format.md`;
4. regenerates the golden tamper report if its output changes:
   `UPDATE_GOLDEN=1 dotnet test --project tests/MerkleAudit.IntegrationTests`, then review the diff of
   `tests/MerkleAudit.IntegrationTests/Golden/tamper-report.txt` like code.

## Architecture decisions

A change to a decision recorded in `docs/adr/` needs a new ADR that supersedes the old one. Do not edit the old ADR in
place. Use the existing files as the format (MADR: context, options considered, decision, consequences).

## Database migrations

Migrations are numbered SQL files in `src/MerkleAudit.Server/Persistence/Migrations/` (`NNNN_name.sql`). They are
embedded in the assembly and applied by `--migrate-only`. Never edit a migration that has been applied anywhere: the
runner compares checksums and refuses to start. Add a new, higher-numbered file instead.
