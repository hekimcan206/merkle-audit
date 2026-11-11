#!/bin/sh
# Runs once, when the PostgreSQL data directory is first initialised (docker-entrypoint-initdb.d).
# Least privilege:
#   audit_migrator  owns the "audit" and "audit_admin" schemas and runs migrations (DDL);
#   audit_app       is what the log server connects as. The migrations grant it SELECT/INSERT on the log tables
#                   (no UPDATE, no DELETE) and UPDATE only on the single tree_state row;
#   audit_reader    read-only, for reporting and external auditors that prefer SQL to the HTTP API.
# The superuser ("postgres") can still change anything. That is the threat this project exists for: see
# docs/threat-model.md and the tamper demo, which plays exactly that rogue administrator.
set -eu

: "${MIGRATOR_PASSWORD:?MIGRATOR_PASSWORD must be set}"
: "${APP_PASSWORD:?APP_PASSWORD must be set}"
: "${READER_PASSWORD:?READER_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
     -v migrator_password="$MIGRATOR_PASSWORD" \
     -v app_password="$APP_PASSWORD" \
     -v reader_password="$READER_PASSWORD" \
     -v db="$POSTGRES_DB" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE audit_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE audit_app LOGIN PASSWORD :'app_password';
CREATE ROLE audit_reader LOGIN PASSWORD :'reader_password';

REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO audit_migrator, audit_app, audit_reader;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA audit AUTHORIZATION audit_migrator;
CREATE SCHEMA audit_admin AUTHORIZATION audit_migrator;
GRANT USAGE ON SCHEMA audit TO audit_app, audit_reader;
SQL
