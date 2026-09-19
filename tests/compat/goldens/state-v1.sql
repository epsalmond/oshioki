BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS devices (
  fingerprint TEXT PRIMARY KEY, credential_id TEXT NOT NULL UNIQUE,
  api_token_hash BLOB NOT NULL UNIQUE, public_record_json TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)), updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY, secret_hash BLOB NOT NULL, status TEXT NOT NULL,
  expires_at INTEGER NOT NULL, reply_subject TEXT NOT NULL, submission_hash BLOB, submission_json BLOB,
  fingerprint TEXT REFERENCES devices(fingerprint), updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, envelope_hash BLOB NOT NULL, envelope_json BLOB NOT NULL,
  host TEXT NOT NULL, user TEXT NOT NULL, issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, state TEXT NOT NULL, decision_hash BLOB,
  created_at INTEGER NOT NULL, resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS sealed_bodies (
  request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL, body_json BLOB NOT NULL,
  PRIMARY KEY(request_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS tombstones (
  kind TEXT NOT NULL, object_id TEXT NOT NULL, payload_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL, PRIMARY KEY(kind, object_id, payload_hash)
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, dedupe_key TEXT NOT NULL,
  subject TEXT NOT NULL, payload BLOB NOT NULL, created_at INTEGER NOT NULL,
  sent_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
  UNIQUE(kind, dedupe_key)
);
CREATE INDEX IF NOT EXISTS requests_expiry_idx ON requests(expires_at);
CREATE INDEX IF NOT EXISTS requests_created_idx ON requests(created_at);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(sent_at, id);
PRAGMA user_version = 1;
COMMIT;
