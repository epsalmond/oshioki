use std::{path::Path, sync::Mutex, time::Duration};

use anyhow::{Context, Result, bail};
use oshioki_protocol::{
    DecisionV1, DeviceKindV1, DevicePublicRecordV1, EnrollmentStatusV1, EnrollmentSubmissionV1,
    RequestEnvelopeV1, native_credential_id,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub struct Store {
    connection: Mutex<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult {
    Inserted,
    Identical,
    Conflict,
}

#[derive(Debug)]
pub struct SealedRequest {
    pub body_json: String,
    pub expires_at: i64,
}

#[derive(Debug)]
pub struct OutboxItem {
    pub id: i64,
    pub kind: String,
    pub subject: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct EnrollmentView {
    pub status: EnrollmentStatusV1,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestLifecycle {
    Pending,
    Gone,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create state directory {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open SQLite state {}", path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(MIGRATION_V1)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    fn memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(MIGRATION_V1)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn ready(&self) -> Result<()> {
        let connection = self.lock()?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != 1 {
            bail!("unsupported database schema version {version}");
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn put_device(&self, device: &DevicePublicRecordV1) -> Result<()> {
        device.validate().context("validate device")?;
        let api_token_hash = oshioki_protocol::decode_base64url(&device.api_token_hash)?;
        let public_json = serde_json::to_string(device)?;
        self.lock()?.execute(
            "INSERT INTO devices(fingerprint, credential_id, api_token_hash, public_record_json, active, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())
             ON CONFLICT(fingerprint) DO UPDATE SET credential_id=excluded.credential_id,
               api_token_hash=excluded.api_token_hash, public_record_json=excluded.public_record_json,
               active=excluded.active, updated_at=unixepoch()",
            params![device.fingerprint, device.credential_id, api_token_hash, public_json, device.active],
        )?;
        Ok(())
    }

    pub fn active_device(&self, fingerprint: &str) -> Result<Option<DevicePublicRecordV1>> {
        let json = self
            .lock()?
            .query_row(
                "SELECT public_record_json FROM devices WHERE fingerprint=?1 AND active=1",
                [fingerprint],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str(&value).context("decode stored device"))
            .transpose()
    }

    pub fn set_device_active(&self, fingerprint: &str, active: bool) -> Result<bool> {
        Ok(self.lock()?.execute(
            "UPDATE devices SET active=?2, updated_at=unixepoch() WHERE fingerprint=?1",
            params![fingerprint, active],
        )? == 1)
    }

    pub fn create_enrollment(
        &self,
        id: &str,
        secret_hash: &[u8],
        expires_at: i64,
        reply_subject: &str,
    ) -> Result<InsertResult> {
        let connection = self.lock()?;
        let existing = connection
            .query_row(
                "SELECT secret_hash, expires_at FROM enrollments WHERE id=?1",
                [id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((stored_hash, stored_expiry)) = existing {
            return Ok(
                if stored_hash == secret_hash && stored_expiry == expires_at {
                    connection.execute(
                        "UPDATE enrollments SET reply_subject=?2, updated_at=unixepoch() WHERE id=?1",
                        params![id, reply_subject],
                    )?;
                    connection.execute(
                        "UPDATE outbox SET subject=?2, sent_at=NULL WHERE kind='enrollment_submission' AND dedupe_key=?1",
                        params![id, reply_subject],
                    )?;
                    InsertResult::Identical
                } else {
                    InsertResult::Conflict
                },
            );
        }
        connection.execute(
            "INSERT INTO enrollments(id, secret_hash, status, expires_at, reply_subject, updated_at) VALUES (?1, ?2, 'pending', ?3, ?4, unixepoch())",
            params![id, secret_hash, expires_at, reply_subject],
        )?;
        Ok(InsertResult::Inserted)
    }

    pub fn submit_enrollment(
        &self,
        id: &str,
        submission: &EnrollmentSubmissionV1,
        now: i64,
    ) -> Result<InsertResult> {
        let raw = serde_json::to_vec(submission)?;
        let hash = Sha256::digest(&raw).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT status, expires_at, submission_hash, reply_subject FROM enrollments WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((status, expires_at, old_hash, reply_subject)) = row else {
            bail!("unknown enrollment")
        };
        if expires_at <= now || status == "expired" {
            bail!("expired enrollment");
        }
        if let Some(old_hash) = old_hash {
            return Ok(if old_hash == hash {
                InsertResult::Identical
            } else {
                InsertResult::Conflict
            });
        }
        if status != "pending" {
            return Ok(InsertResult::Conflict);
        }
        transaction.execute(
            "UPDATE enrollments SET submission_hash=?2, submission_json=?3, updated_at=unixepoch() WHERE id=?1",
            params![id, hash, raw],
        )?;
        transaction.execute(
            "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at)
             VALUES ('enrollment_submission', ?1, ?2, ?3, unixepoch())",
            params![id, reply_subject, raw],
        )?;
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    pub fn activate_enrollment(
        &self,
        id: &str,
        device: &DevicePublicRecordV1,
        now: i64,
    ) -> Result<()> {
        device.validate().context("validate activated device")?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, i64, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT status, expires_at, submission_json FROM enrollments WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((status, expires_at, submission_json)) = row else {
            bail!("unknown enrollment");
        };
        // Only a live, pending enrollment activates. A replayed activation
        // for an already-active or expired enrollment is not a second device;
        // it is either a duplicate delivery or someone else's enrollment id.
        if status != "pending" {
            bail!("enrollment is not pending");
        }
        if expires_at <= now {
            bail!("enrollment expired");
        }
        let raw = submission_json.context("enrollment has no submission")?;
        let submission: EnrollmentSubmissionV1 =
            serde_json::from_slice(&raw).context("decode stored submission")?;
        if !submission_binds_device(&submission, device)? {
            bail!("activation does not match the stored submission");
        }
        let api_token_hash = oshioki_protocol::decode_base64url(&device.api_token_hash)?;
        let public_json = serde_json::to_string(device)?;
        // Insert-only: an activation must never rewrite an enrolled record. A
        // replay naming an existing fingerprint either matches the stored row
        // (the same device enrolling again) or fails the check below instead
        // of replacing its API token.
        transaction.execute(
            "INSERT INTO devices(fingerprint, credential_id, api_token_hash, public_record_json, active, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, unixepoch())
             ON CONFLICT(fingerprint) DO NOTHING",
            params![device.fingerprint, device.credential_id, api_token_hash, public_json],
        )?;
        let stored: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT credential_id, api_token_hash FROM devices WHERE fingerprint=?1",
                [&device.fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_credential, stored_token)) = stored else {
            bail!("device insert failed");
        };
        if stored_credential != device.credential_id || stored_token != api_token_hash {
            bail!("activation names a different record for an enrolled device");
        }
        // Re-enrollment after revocation reactivates; a live row is untouched.
        transaction.execute(
            "UPDATE devices SET active=1, updated_at=unixepoch() WHERE fingerprint=?1",
            [&device.fingerprint],
        )?;
        let changed = transaction.execute(
            "UPDATE enrollments SET status='active', fingerprint=?2, updated_at=unixepoch()
             WHERE id=?1 AND status='pending'",
            params![id, device.fingerprint],
        )?;
        if changed != 1 {
            bail!("enrollment is not pending");
        }
        transaction.commit()?;
        Ok(())
    }
}

/// Whether an activation names the device its enrollment submitted. The
/// server never sees the enrollment secret, so it cannot re-verify the
/// submission's proof the way the hook does; what it can do is refuse an
/// activation for any other device than the submitted one. The credential
/// id, box key, API token hash, and label all have to match, and a native
/// submission additionally pins the credential key itself.
///
/// The `WebAuthn` credential key is deliberately not covered: it lives inside
/// the attestation object, which only the hook (with its RP ID) can parse.
/// What remains for a forged `WebAuthn` activation is a shadow record nobody
/// can authenticate as — the token hash is bound — and the hook's read-back
/// rejects it before the enrollment completes.
fn submission_binds_device(
    submission: &EnrollmentSubmissionV1,
    device: &DevicePublicRecordV1,
) -> Result<bool> {
    let expected_kind = match submission {
        EnrollmentSubmissionV1::Webauthn(_) => DeviceKindV1::Webauthn,
        EnrollmentSubmissionV1::SecureEnclave(_) => DeviceKindV1::SecureEnclave,
    };
    if device.kind != expected_kind {
        return Ok(false);
    }
    let (credential_id, credential_public_key, box_public_key, api_token_hash, label) =
        match submission {
            EnrollmentSubmissionV1::Webauthn(submission) => (
                submission.credential_id.clone(),
                None,
                submission.box_public_key.clone(),
                submission.api_token_hash.clone(),
                submission.label.clone(),
            ),
            EnrollmentSubmissionV1::SecureEnclave(submission) => {
                let public_key =
                    oshioki_protocol::decode_base64url(&submission.credential_public_key)
                        .context("decode submitted credential key")?;
                let credential_id =
                    oshioki_protocol::encode_base64url(&native_credential_id(&public_key));
                (
                    credential_id,
                    Some(submission.credential_public_key.clone()),
                    submission.box_public_key.clone(),
                    submission.api_token_hash.clone(),
                    submission.label.clone(),
                )
            }
        };
    if let Some(expected) = credential_public_key {
        if device.credential_public_key != expected {
            return Ok(false);
        }
    }
    Ok(device.credential_id == credential_id
        && device.box_public_key == box_public_key
        && device.api_token_hash == api_token_hash
        && device.label == label)
}

impl Store {
    pub fn enrollment_status(&self, id: &str, now: i64) -> Result<Option<EnrollmentView>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT status, expires_at, fingerprint FROM enrollments WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(status, expiry, fingerprint)| EnrollmentView {
            status: if expiry <= now && status == "pending" {
                EnrollmentStatusV1::Expired
            } else {
                match status.as_str() {
                    "active" => EnrollmentStatusV1::Active,
                    "rejected" => EnrollmentStatusV1::Rejected,
                    "expired" => EnrollmentStatusV1::Expired,
                    _ => EnrollmentStatusV1::Pending,
                }
            },
            fingerprint,
        }))
    }

    pub fn ingest_request(
        &self,
        raw: &[u8],
        envelope: &RequestEnvelopeV1,
        now: i64,
    ) -> Result<InsertResult> {
        if raw.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
            bail!("oversized request envelope");
        }
        envelope.validate().context("validate envelope")?;
        if envelope.expires_at <= now {
            bail!("expired request");
        }
        let hash = Sha256::digest(raw).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old_hash = transaction
            .query_row(
                "SELECT envelope_hash FROM requests WHERE id=?1",
                [&envelope.request_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(old_hash) = old_hash {
            if old_hash == hash {
                return Ok(InsertResult::Identical);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO tombstones(kind, object_id, payload_hash, expires_at) VALUES ('request_conflict', ?1, ?2, ?3)",
                params![envelope.request_id, hash, envelope.expires_at],
            )?;
            transaction.commit()?;
            return Ok(InsertResult::Conflict);
        }
        transaction.execute(
            "INSERT INTO requests(id, envelope_hash, envelope_json, host, user, issued_at, expires_at, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', unixepoch())",
            params![envelope.request_id, hash, raw, envelope.host, envelope.user, envelope.issued_at, envelope.expires_at],
        )?;
        for body in &envelope.sealed {
            transaction.execute(
                "INSERT INTO sealed_bodies(request_id, fingerprint, body_json) VALUES (?1, ?2, ?3)",
                params![
                    envelope.request_id,
                    body.device_fingerprint,
                    serde_json::to_vec(body)?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    pub fn queue_notification(
        &self,
        request_id: &str,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at)
             VALUES ('ntfy', ?1, ?2, ?3, unixepoch())
             ON CONFLICT(kind, dedupe_key) DO NOTHING",
            params![request_id, endpoint, payload],
        )?;
        Ok(())
    }

    pub fn sealed_request_for_token(
        &self,
        request_id: &str,
        token: &[u8],
        now: i64,
    ) -> Result<Option<SealedRequest>> {
        let token_hash = Sha256::digest(token).to_vec();
        self.lock()?.query_row(
            "SELECT CAST(b.body_json AS TEXT), r.expires_at FROM requests r
             JOIN sealed_bodies b ON b.request_id=r.id
             JOIN devices d ON d.fingerprint=b.fingerprint
             WHERE r.id=?1 AND r.state='pending' AND r.expires_at>?2 AND d.active=1 AND d.api_token_hash=?3",
            params![request_id, now, token_hash],
            |row| Ok(SealedRequest { body_json: row.get(0)?, expires_at: row.get(1)? }),
        ).optional().map_err(Into::into)
    }

    pub fn queue_decision(
        &self,
        request_id: &str,
        fingerprint: &str,
        decision: &DecisionV1,
        now: i64,
    ) -> Result<InsertResult> {
        let raw = serde_json::to_vec(decision)?;
        let hash = Sha256::digest(&raw).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT state, expires_at, decision_hash FROM requests WHERE id=?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((state, expires_at, old_hash)) = row else {
            bail!("unknown request")
        };
        if expires_at <= now {
            bail!("expired request");
        }
        let owns = transaction
            .query_row(
                "SELECT 1 FROM sealed_bodies b JOIN devices d ON d.fingerprint=b.fingerprint
             WHERE b.request_id=?1 AND b.fingerprint=?2 AND d.active=1",
                params![request_id, fingerprint],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !owns {
            bail!("device does not own request");
        }
        if state != "pending" {
            return Ok(if old_hash.as_deref() == Some(hash.as_slice()) {
                InsertResult::Identical
            } else {
                InsertResult::Conflict
            });
        }
        transaction.execute(
            "UPDATE requests SET state='resolved', decision_hash=?2, resolved_at=unixepoch() WHERE id=?1 AND state='pending'",
            params![request_id, hash],
        )?;
        transaction.execute(
            "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at)
             VALUES ('decision', ?1, ?2, ?3, unixepoch())",
            params![request_id, format!("oshioki.verdict.{request_id}"), raw],
        )?;
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    pub fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, kind, subject, payload FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(limit)?], |row| {
            Ok(OutboxItem {
                id: row.get(0)?,
                kind: row.get(1)?,
                subject: row.get(2)?,
                payload: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn request_lifecycle(
        &self,
        request_id: &str,
        now: i64,
    ) -> Result<Option<RequestLifecycle>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT state, expires_at FROM requests WHERE id=?1",
                [request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(row.map(|(state, expires_at)| {
            if state == "pending" && expires_at > now {
                RequestLifecycle::Pending
            } else {
                RequestLifecycle::Gone
            }
        }))
    }

    pub fn mark_outbox_sent(&self, id: i64) -> Result<()> {
        self.lock()?.execute(
            "UPDATE outbox SET sent_at=unixepoch(), attempts=attempts+1 WHERE id=?1",
            [id],
        )?;
        Ok(())
    }

    pub fn cleanup(&self, now: i64) -> Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "UPDATE enrollments SET status='expired' WHERE status='pending' AND expires_at<=?1",
            [now],
        )?;
        connection.execute("DELETE FROM requests WHERE expires_at < ?1", [now - 3600])?;
        connection.execute("DELETE FROM tombstones WHERE expires_at < ?1", [now])?;
        connection.execute(
            "DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?1",
            [now - 86_400],
        )?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite mutex poisoned"))
    }
}

const MIGRATION_V1: &str = r"
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
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(sent_at, id);
PRAGMA user_version = 1;
COMMIT;
";

#[cfg(test)]
mod tests {
    use super::*;
    use oshioki_protocol::{
        DenyV1, DeviceKindV1, EnrollmentSubmissionV1, NativeEnrollmentSubmissionV1,
        SealedDeviceBodyV1, WebauthnEnrollmentSubmissionV1, native_credential_id,
        v1::{VERSION_V1, encode_base64url},
    };
    use p256::ecdsa::SigningKey;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_database() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "oshioki-db-test-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    fn remove_database(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn device(token: &[u8]) -> DevicePublicRecordV1 {
        let credential_id = vec![1; 16];
        let signing = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let mut cose = BTreeMap::new();
        cose.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(2));
        cose.insert(
            serde_cbor::Value::Integer(3),
            serde_cbor::Value::Integer(-7),
        );
        cose.insert(
            serde_cbor::Value::Integer(-1),
            serde_cbor::Value::Integer(1),
        );
        cose.insert(
            serde_cbor::Value::Integer(-2),
            serde_cbor::Value::Bytes(point.x().unwrap().to_vec()),
        );
        cose.insert(
            serde_cbor::Value::Integer(-3),
            serde_cbor::Value::Bytes(point.y().unwrap().to_vec()),
        );
        let credential_public_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose)).unwrap();
        let box_public_key = vec![3; 32];
        let fingerprint = oshioki_protocol::device_fingerprint(
            &credential_id,
            &credential_public_key,
            &box_public_key,
        );
        DevicePublicRecordV1 {
            version: 1,
            kind: oshioki_protocol::DeviceKindV1::Webauthn,
            fingerprint,
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&credential_public_key),
            box_public_key: encode_base64url(&box_public_key),
            label: "test".into(),
            api_token_hash: encode_base64url(&Sha256::digest(token)),
            sign_count: 0,
            active: true,
        }
    }

    fn envelope(fingerprint: &str) -> RequestEnvelopeV1 {
        RequestEnvelopeV1 {
            version: 1,
            request_id: "request-1".into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at: 10,
            expires_at: 100,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: fingerprint.into(),
                ephemeral_pub: encode_base64url(&[4; 32]),
                nonce: encode_base64url(&[5; 12]),
                ciphertext: encode_base64url(&[6; 32]),
            }],
        }
    }

    #[test]
    fn request_redelivery_and_token_isolation() {
        let store = Store::memory().unwrap();
        let first = device(b"first");
        store.put_device(&first).unwrap();
        let envelope = envelope(&first.fingerprint);
        let raw = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            store.ingest_request(&raw, &envelope, 20).unwrap(),
            InsertResult::Inserted
        );
        assert_eq!(
            store.ingest_request(&raw, &envelope, 20).unwrap(),
            InsertResult::Identical
        );
        assert!(
            store
                .sealed_request_for_token("request-1", b"wrong", 20)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .sealed_request_for_token("request-1", b"first", 20)
                .unwrap()
                .is_some()
        );

        let mut conflicting = envelope.clone();
        conflicting.user = "somebody-else".into();
        let conflicting_raw = serde_json::to_vec(&conflicting).unwrap();
        assert_eq!(
            store
                .ingest_request(&conflicting_raw, &conflicting, 20)
                .unwrap(),
            InsertResult::Conflict
        );
    }

    #[test]
    fn first_decision_wins() {
        let store = Store::memory().unwrap();
        let device = device(b"first");
        store.put_device(&device).unwrap();
        let envelope = envelope(&device.fingerprint);
        let raw = serde_json::to_vec(&envelope).unwrap();
        store.ingest_request(&raw, &envelope, 20).unwrap();
        let decision = DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: "request-1".into(),
            device_fingerprint: device.fingerprint.clone(),
        });
        assert_eq!(
            store
                .queue_decision("request-1", &device.fingerprint, &decision, 20)
                .unwrap(),
            InsertResult::Inserted
        );
        assert_eq!(
            store
                .queue_decision("request-1", &device.fingerprint, &decision, 20)
                .unwrap(),
            InsertResult::Identical
        );
    }

    #[test]
    fn restart_replays_unsent_outbox_until_marked() {
        let path = temporary_database();
        let device = device(b"restart-token");
        let decision = DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: "request-1".into(),
            device_fingerprint: device.fingerprint.clone(),
        });

        {
            let store = Store::open(&path).unwrap();
            store.put_device(&device).unwrap();
            let envelope = envelope(&device.fingerprint);
            let raw = serde_json::to_vec(&envelope).unwrap();
            store.ingest_request(&raw, &envelope, 20).unwrap();
            store
                .queue_decision("request-1", &device.fingerprint, &decision, 20)
                .unwrap();
            assert_eq!(store.pending_outbox(10).unwrap().len(), 1);
        }

        {
            let store = Store::open(&path).unwrap();
            store.ready().unwrap();
            assert_eq!(
                store.request_lifecycle("request-1", 20).unwrap(),
                Some(RequestLifecycle::Gone)
            );
            assert!(
                store
                    .sealed_request_for_token("request-1", b"restart-token", 20)
                    .unwrap()
                    .is_none()
            );
            let pending = store.pending_outbox(10).unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].kind, "decision");
            assert_eq!(pending[0].subject, "oshioki.verdict.request-1");
            store.mark_outbox_sent(pending[0].id).unwrap();
            assert!(store.pending_outbox(10).unwrap().is_empty());

            let connection = store.lock().unwrap();
            let foreign_keys: i64 = connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                .unwrap();
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(foreign_keys, 1);
            assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        }

        remove_database(&path);
    }

    /// One native device with caller-chosen keys and API token: varying the
    /// token while the keys stay put builds exactly the replay shape that
    /// must not rewrite the stored record.
    fn native_pair(
        enrollment_id: &str,
        key_byte: u8,
        token: &[u8],
        label: &str,
    ) -> (EnrollmentSubmissionV1, DevicePublicRecordV1) {
        let signing = SigningKey::from_bytes((&[key_byte; 32]).into()).unwrap();
        let public = signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(public.len(), 65);
        let box_key = vec![key_byte ^ 0xa5; 32];
        let token_hash = Sha256::digest(token).to_vec();
        let credential_id = native_credential_id(&public);
        let fingerprint = oshioki_protocol::device_fingerprint(&credential_id, &public, &box_key);
        let submission = NativeEnrollmentSubmissionV1 {
            version: VERSION_V1,
            enrollment_id: enrollment_id.into(),
            credential_public_key: encode_base64url(&public),
            box_public_key: encode_base64url(&box_key),
            api_token_hash: encode_base64url(&token_hash),
            label: label.into(),
            proof_signature: encode_base64url(&[8; 32]),
            transcript_hmac: encode_base64url(&[0; 32]),
        };
        let device = DevicePublicRecordV1 {
            version: VERSION_V1,
            kind: DeviceKindV1::SecureEnclave,
            fingerprint,
            credential_id: encode_base64url(&credential_id),
            credential_public_key: encode_base64url(&public),
            box_public_key: encode_base64url(&box_key),
            label: label.into(),
            api_token_hash: encode_base64url(&token_hash),
            sign_count: 0,
            active: true,
        };
        device.validate().unwrap();
        (EnrollmentSubmissionV1::SecureEnclave(submission), device)
    }

    fn pending_enrollment(store: &Store, id: &str, expires_at: i64) {
        let secret_hash = Sha256::digest(b"enrollment-secret").to_vec();
        assert_eq!(
            store
                .create_enrollment(
                    id,
                    &secret_hash,
                    expires_at,
                    &format!("oshioki.enrollment.submission.{id}")
                )
                .unwrap(),
            InsertResult::Inserted
        );
    }

    fn submit(store: &Store, id: &str, submission: &EnrollmentSubmissionV1, now: i64) {
        assert_eq!(
            store.submit_enrollment(id, submission, now).unwrap(),
            InsertResult::Inserted
        );
    }

    /// The bound device activates: the row is inserted and the enrollment
    /// flips to active pointing at it.
    #[test]
    fn activation_inserts_the_submitted_device() {
        let store = Store::memory().unwrap();
        let (submission, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        store.activate_enrollment("enroll-1", &device, 100).unwrap();
        assert_eq!(
            store.active_device(&device.fingerprint).unwrap(),
            Some(device.clone())
        );
        let view = store.enrollment_status("enroll-1", 100).unwrap().unwrap();
        assert_eq!(view.status, EnrollmentStatusV1::Active);
        assert_eq!(
            view.fingerprint.as_deref(),
            Some(device.fingerprint.as_str())
        );
    }

    /// A replay after success is rejected and leaves the device row exactly
    /// as the first activation wrote it.
    #[test]
    fn activation_replay_changes_nothing() {
        let store = Store::memory().unwrap();
        let (submission, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        store.activate_enrollment("enroll-1", &device, 100).unwrap();
        let stored_before = store.active_device(&device.fingerprint).unwrap();
        let error = store
            .activate_enrollment("enroll-1", &device, 100)
            .unwrap_err();
        assert!(error.to_string().contains("not pending"), "{error:?}");
        assert_eq!(
            store.active_device(&device.fingerprint).unwrap(),
            stored_before
        );
        let view = store.enrollment_status("enroll-1", 100).unwrap().unwrap();
        assert_eq!(view.status, EnrollmentStatusV1::Active);
    }

    /// An enrollment that expired before the activation arrived stays dead,
    /// and no device row is created for it.
    #[test]
    fn activation_rejects_an_expired_enrollment() {
        let store = Store::memory().unwrap();
        let (submission, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 150);
        submit(&store, "enroll-1", &submission, 100);
        let error = store
            .activate_enrollment("enroll-1", &device, 150)
            .unwrap_err();
        assert!(error.to_string().contains("expired"), "{error:?}");
        assert!(store.active_device(&device.fingerprint).unwrap().is_none());
    }

    /// Same keys, different API token: a second enrollment's activation must
    /// not replace the enrolled record's token, which would let the replay's
    /// author authenticate as the device.
    #[test]
    fn activation_rejects_a_token_replacement() {
        let store = Store::memory().unwrap();
        let (submission_one, device_one) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission_one, 100);
        store
            .activate_enrollment("enroll-1", &device_one, 100)
            .unwrap();
        let (submission_two, device_two) = native_pair("enroll-2", 9, b"token-two", "laptop");
        pending_enrollment(&store, "enroll-2", 300);
        submit(&store, "enroll-2", &submission_two, 100);
        let error = store
            .activate_enrollment("enroll-2", &device_two, 100)
            .unwrap_err();
        assert!(error.to_string().contains("different record"), "{error:?}");
        assert_eq!(
            store.active_device(&device_one.fingerprint).unwrap(),
            Some(device_one.clone())
        );
        let view = store.enrollment_status("enroll-2", 100).unwrap().unwrap();
        assert_eq!(view.status, EnrollmentStatusV1::Pending);
    }

    /// An activation for another device than the submitted one is refused,
    /// even while its enrollment is pending and unexpired.
    #[test]
    fn activation_rejects_an_unbound_device() {
        let store = Store::memory().unwrap();
        let (submission, _) = native_pair("enroll-1", 9, b"token-one", "laptop");
        let (_, stranger) = native_pair("enroll-1", 11, b"token-two", "other");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        let error = store
            .activate_enrollment("enroll-1", &stranger, 100)
            .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error:?}");
        assert!(
            store
                .active_device(&stranger.fingerprint)
                .unwrap()
                .is_none()
        );
    }

    /// Without a stored submission there is nothing to bind the activation
    /// to, so there is nothing to activate.
    #[test]
    fn activation_needs_a_stored_submission() {
        let store = Store::memory().unwrap();
        let (_, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        let error = store
            .activate_enrollment("enroll-1", &device, 100)
            .unwrap_err();
        assert!(error.to_string().contains("no submission"), "{error:?}");
        assert!(store.active_device(&device.fingerprint).unwrap().is_none());
    }

    /// The submission kind and the device kind travel together: a `WebAuthn`
    /// submission never binds a Secure Enclave record, even when every
    /// compared field agrees.
    #[test]
    fn activation_rejects_a_kind_mismatch() {
        let store = Store::memory().unwrap();
        let (_, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        let submission = EnrollmentSubmissionV1::Webauthn(WebauthnEnrollmentSubmissionV1 {
            version: VERSION_V1,
            enrollment_id: "enroll-1".into(),
            registration_client_data_json: encode_base64url(b"{}"),
            attestation_object: encode_base64url(&[0]),
            proof_authenticator_data: encode_base64url(&[0]),
            proof_client_data_json: encode_base64url(b"{}"),
            proof_signature: encode_base64url(&[0; 32]),
            credential_id: device.credential_id.clone(),
            box_public_key: device.box_public_key.clone(),
            api_token_hash: device.api_token_hash.clone(),
            label: device.label.clone(),
            transcript_hmac: encode_base64url(&[0; 32]),
        });
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        let error = store
            .activate_enrollment("enroll-1", &device, 100)
            .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error:?}");
        assert!(store.active_device(&device.fingerprint).unwrap().is_none());
    }
}
