-- The log: entries (the data), tree_nodes (the Merkle tree over it), tree_state (one row: current size and root),
-- tree_heads (signed commitments). Entries, nodes and heads are append-only; only tree_state is ever updated.

CREATE TABLE audit.entries (
    seq         bigint      PRIMARY KEY CHECK (seq >= 0),
    occurred_at timestamptz NOT NULL,
    actor       text        NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    action      text        NOT NULL CHECK (length(action) BETWEEN 1 AND 200),
    resource    text        NOT NULL CHECK (length(resource) BETWEEN 1 AND 500),
    -- Stored as text, not jsonb: the leaf hash covers these exact bytes, and jsonb would re-order keys.
    payload     text        NOT NULL CHECK (length(payload) <= 65536)
);

-- Every perfect subtree, level 0 (leaf hashes) included. Kept apart from entries on purpose: deleting or editing a row
-- leaves the tree's memory of it intact, which is what lets the verifier say exactly which row changed.
CREATE TABLE audit.tree_nodes (
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 62),
    idx   bigint   NOT NULL CHECK (idx >= 0),
    hash  bytea    NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (level, idx)
);

CREATE TABLE audit.tree_state (
    id         boolean     PRIMARY KEY DEFAULT true CHECK (id),
    tree_size  bigint      NOT NULL CHECK (tree_size >= 0),
    root_hash  bytea       NOT NULL CHECK (octet_length(root_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- SHA-256 of nothing: the RFC 6962 root of the empty tree.
INSERT INTO audit.tree_state (tree_size, root_hash)
VALUES (0, decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'));

CREATE TABLE audit.tree_heads (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tree_size    bigint NOT NULL CHECK (tree_size >= 0),
    timestamp_ms bigint NOT NULL CHECK (timestamp_ms >= 0),
    root_hash    bytea  NOT NULL CHECK (octet_length(root_hash) = 32),
    key_id       text   NOT NULL,
    signature    bytea  NOT NULL
);

CREATE INDEX tree_heads_size ON audit.tree_heads (tree_size, timestamp_ms);

-- Append-only enforcement for everyone who respects triggers. A superuser can bypass it
-- (session_replication_role = replica, or ALTER TABLE ... DISABLE TRIGGER); detection, not prevention, covers that.
CREATE FUNCTION audit.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit.% is append-only (% rejected)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER entries_append_only BEFORE UPDATE OR DELETE ON audit.entries
    FOR EACH ROW EXECUTE FUNCTION audit.reject_change();
CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON audit.entries
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_change();
CREATE TRIGGER tree_nodes_append_only BEFORE UPDATE OR DELETE ON audit.tree_nodes
    FOR EACH ROW EXECUTE FUNCTION audit.reject_change();
CREATE TRIGGER tree_nodes_no_truncate BEFORE TRUNCATE ON audit.tree_nodes
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_change();
CREATE TRIGGER tree_heads_append_only BEFORE UPDATE OR DELETE ON audit.tree_heads
    FOR EACH ROW EXECUTE FUNCTION audit.reject_change();
CREATE TRIGGER tree_heads_no_truncate BEFORE TRUNCATE ON audit.tree_heads
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_change();

-- Privileges: the application can append and read, and move tree_state forward. Nothing else.
GRANT SELECT, INSERT ON audit.entries, audit.tree_nodes, audit.tree_heads TO audit_app;
GRANT SELECT, UPDATE ON audit.tree_state TO audit_app;
GRANT SELECT ON audit.entries, audit.tree_nodes, audit.tree_heads, audit.tree_state TO audit_reader;
