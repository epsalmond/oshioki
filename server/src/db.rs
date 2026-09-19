use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use oshioki_protocol::{
    AuthDecisionV1, AuthEnvelopeV1, DecisionV1, DeliveryV1, DeviceKindV1, DevicePublicRecordV1,
    EnrollmentStatusV1, EnrollmentSubmissionV1, RequestEnvelopeV1, native_credential_id,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

/// The server keeps request state only briefly after its local receipt time.
/// This bound is intentionally independent of timestamps supplied by a
/// publisher, including timestamps in a conflicting redelivery.
pub const SERVER_REQUEST_RETENTION_SECS: i64 = 5 * 60;
pub const PUSH_MAX_ENDPOINT_BYTES: usize = 2048;
pub const PUSH_AUTH_BYTES: usize = 16;
pub const PUSH_P256DH_BYTES: usize = 65;
pub const PUSH_MAX_ATTEMPTS: i64 = 5;
pub const PUSH_LEASE_SECS: i64 = 30;
pub const PUSH_DISABLED_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
/// Schema version this binary writes after migrate. Older files snapshot,
/// then move forward; newer files refuse to open. See `docs/compatibility.md`.
pub const SCHEMA_VERSION: i64 = 3;

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
    pub subject: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushStatus {
    pub version: u8,
    pub enabled: bool,
    pub registered: bool,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct PushItem {
    pub id: i64,
    pub subscription_id: String,
    pub endpoint: String,
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
    pub payload: Vec<u8>,
    pub request_kind: String,
    pub request_id: String,
    pub expires_at: i64,
    pub claim_token: String,
    pub attempts: i64,
}

type PushClaimRow = (
    i64,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    i64,
    i64,
);

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
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0..=2 => {
                create_verified_restore_snapshot(&connection, path, version)?;
                match version {
                    0 => {
                        connection.execute_batch(MIGRATION_V1)?;
                        connection.execute_batch(MIGRATION_V2)?;
                        connection.execute_batch(MIGRATION_V3)?;
                    }
                    1 => {
                        connection.execute_batch(MIGRATION_V2)?;
                        connection.execute_batch(MIGRATION_V3)?;
                    }
                    2 => connection.execute_batch(MIGRATION_V3)?,
                    _ => unreachable!("matched 0|1|2"),
                }
            }
            SCHEMA_VERSION => {}
            newer => bail!("unsupported database schema version {newer}"),
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    fn memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(MIGRATION_V1)?;
        connection.execute_batch(MIGRATION_V2)?;
        connection.execute_batch(MIGRATION_V3)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn ready(&self) -> Result<()> {
        let connection = self.lock()?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
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
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE devices SET active=?2, updated_at=unixepoch() WHERE fingerprint=?1",
            params![fingerprint, active],
        )?;
        if !active && changed != 0 {
            transaction.execute(
                "UPDATE push_subscriptions SET disabled_at=unixepoch(), updated_at=unixepoch()
                 WHERE device_fingerprint=?1 AND disabled_at IS NULL",
                [fingerprint],
            )?;
            transaction.execute(
                "UPDATE push_outbox SET abandoned_at=unixepoch(), claim_token=NULL, claimed_until=NULL
                 WHERE subscription_id IN (SELECT id FROM push_subscriptions WHERE device_fingerprint=?1)
                   AND sent_at IS NULL AND abandoned_at IS NULL",
                [fingerprint],
            )?;
        }
        transaction.commit()?;
        Ok(changed == 1)
    }

    pub fn register_push_subscription(
        &self,
        token: &[u8],
        endpoint: &str,
        p256dh: &[u8],
        auth: &[u8],
        expiration_at: Option<i64>,
        now: i64,
    ) -> Result<String> {
        validate_push_endpoint(endpoint)?;
        if p256dh.len() != PUSH_P256DH_BYTES || p256dh.first() != Some(&4) {
            bail!("invalid p256dh key");
        }
        if p256::PublicKey::from_sec1_bytes(p256dh).is_err() {
            bail!("invalid p256dh key");
        }
        if auth.len() != PUSH_AUTH_BYTES {
            bail!("invalid auth secret");
        }
        if let Some(expiration_at) = expiration_at {
            if expiration_at <= now {
                bail!("expired subscription");
            }
        }
        let token_hash = Sha256::digest(token).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let fingerprint: String = transaction
            .query_row(
                "SELECT fingerprint FROM devices WHERE api_token_hash=?1 AND active=1
                 AND COALESCE(json_extract(public_record_json, '$.kind'), 'webauthn')='webauthn'",
                [&token_hash],
                |row| row.get(0),
            )
            .optional()?
            .context("active WebAuthn device not found")?;
        let existing: Option<(String, String, Option<i64>, bool)> = transaction
            .query_row(
                "SELECT p.id, p.device_fingerprint, p.disabled_at, COALESCE(d.active, 0)
                 FROM push_subscriptions p LEFT JOIN devices d ON d.fingerprint=p.device_fingerprint
                 WHERE p.endpoint=?1",
                [endpoint],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let id = if let Some((id, owner, disabled_at, owner_active)) = existing {
            if owner != fingerprint && disabled_at.is_none() && owner_active {
                bail!("push endpoint belongs to another active device");
            }
            transaction.execute(
                "UPDATE push_subscriptions SET device_fingerprint=?2, p256dh=?3, auth=?4,
                 expiration_at=?5, updated_at=?6, disabled_at=NULL, last_error=NULL
                 WHERE id=?1",
                params![id, fingerprint, p256dh, auth, expiration_at, now],
            )?;
            id
        } else {
            let id = format!("ps_{}", uuid::Uuid::new_v4().simple());
            transaction.execute(
                "INSERT INTO push_subscriptions
                 (id, device_fingerprint, endpoint, p256dh, auth, expiration_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![id, fingerprint, endpoint, p256dh, auth, expiration_at, now],
            )?;
            id
        };
        transaction.commit()?;
        Ok(id)
    }

    pub fn push_status(&self, token: &[u8]) -> Result<PushStatus> {
        let token_hash = Sha256::digest(token).to_vec();
        let connection = self.lock()?;
        let owner: Option<String> = connection
            .query_row(
                "SELECT fingerprint FROM devices WHERE api_token_hash=?1 AND active=1
                 AND COALESCE(json_extract(public_record_json, '$.kind'), 'webauthn')='webauthn'",
                [&token_hash],
                |row| row.get(0),
            )
            .optional()?;
        let Some(owner) = owner else {
            bail!("active WebAuthn device not found");
        };
        let count: usize = connection
            .query_row(
                "SELECT COUNT(*) FROM push_subscriptions
                 WHERE device_fingerprint=?1 AND disabled_at IS NULL",
                [owner],
                |row| row.get::<_, i64>(0),
            )?
            .try_into()
            .context("push subscription count overflow")?;
        Ok(PushStatus {
            version: 1,
            enabled: true,
            registered: count != 0,
            count,
        })
    }

    pub fn delete_push_subscription(&self, token: &[u8], id: &str, now: i64) -> Result<bool> {
        let token_hash = Sha256::digest(token).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owner_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE api_token_hash=?1 AND active=1
             AND COALESCE(json_extract(public_record_json, '$.kind'), 'webauthn')='webauthn')",
            [&token_hash],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if !owner_exists {
            bail!("active WebAuthn device not found");
        }
        let changed = transaction.execute(
            "UPDATE push_subscriptions SET disabled_at=?3, updated_at=?3
             WHERE id=?1 AND disabled_at IS NULL AND device_fingerprint IN
               (SELECT fingerprint FROM devices WHERE api_token_hash=?2 AND active=1)",
            params![id, token_hash, now],
        )?;
        if changed != 0 {
            transaction.execute(
                "UPDATE push_outbox SET abandoned_at=?2, claim_token=NULL, claimed_until=NULL
                 WHERE subscription_id=?1 AND sent_at IS NULL AND abandoned_at IS NULL",
                params![id, now],
            )?;
        }
        transaction.commit()?;
        Ok(changed == 1)
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
        // The upsert refreshes the public record but never the pinned
        // credential: a re-enrollment with a new label converges the served
        // record, while a replay naming an existing fingerprint keeps the
        // stored credential_id and api_token_hash and fails the check below
        // instead of replacing the API token. Reactivation rides along, so
        // re-enrollment after revocation needs no second write.
        transaction.execute(
            "INSERT INTO devices(fingerprint, credential_id, api_token_hash, public_record_json, active, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, unixepoch())
             ON CONFLICT(fingerprint) DO UPDATE SET public_record_json=excluded.public_record_json,
                active=1, updated_at=unixepoch()",
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
        EnrollmentSubmissionV1::Software(_) => DeviceKindV1::Software,
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
            EnrollmentSubmissionV1::Software(submission)
            | EnrollmentSubmissionV1::SecureEnclave(submission) => {
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
        envelope.validate_at(now).context("validate envelope")?;
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
                params![
                    envelope.request_id,
                    hash,
                    envelope
                        .expires_at
                        .min(now.saturating_add(SERVER_REQUEST_RETENTION_SECS))
                ],
            )?;
            transaction.commit()?;
            return Ok(InsertResult::Conflict);
        }
        transaction.execute(
            "INSERT INTO requests(id, envelope_hash, envelope_json, host, user, issued_at, expires_at, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            params![
                envelope.request_id,
                hash,
                raw,
                envelope.host,
                envelope.user,
                envelope.issued_at,
                envelope.expires_at,
                now,
            ],
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
        let push_payload = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "lane": "request",
            "request_id": envelope.request_id,
        }))?;
        transaction.execute(
            "INSERT OR IGNORE INTO push_outbox
             (request_kind, request_id, subscription_id, payload, created_at, available_at)
             SELECT 'request', ?1, p.id, ?2, ?3, ?3
             FROM push_subscriptions p
             JOIN devices d ON d.fingerprint=p.device_fingerprint
             JOIN sealed_bodies b ON b.fingerprint=d.fingerprint AND b.request_id=?1
             WHERE d.active=1 AND p.disabled_at IS NULL
               AND (p.expiration_at IS NULL OR p.expiration_at>?3)",
            params![envelope.request_id, push_payload, now],
        )?;
        // Routing is part of the same durable transaction as the request:
        // only an active device record already bound to one of the sealed
        // bodies can cause a server delivery receipt. A browser receipt is a
        // relay commitment, never evidence that a browser has opened the
        // request; that second signal remains the authenticated AliveV1 POST.
        let has_active_browser = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sealed_bodies b
                 JOIN devices d ON d.fingerprint=b.fingerprint
                 WHERE b.request_id=?1 AND d.active=1
                   AND COALESCE(json_extract(d.public_record_json, '$.kind'), 'webauthn')='webauthn'
             )",
            [&envelope.request_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if has_active_browser {
            let delivery = serde_json::to_vec(&DeliveryV1::for_request(&envelope.request_id))?;
            transaction.execute(
                "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at, expires_at)
                 VALUES ('delivery', ?1, ?2, ?3, unixepoch(), ?4)",
                params![
                    envelope.request_id,
                    format!("oshioki.delivery.{}", envelope.request_id),
                    delivery,
                    envelope.expires_at
                ],
            )?;
        }
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    /// Stores one contextual sudo authentication envelope.
    ///
    /// Deliberately a separate table from `requests` rather than a type
    /// column on it: the two lanes answer different questions, and keeping
    /// their rows apart is what makes a legacy approval posted against an
    /// authentication id — or the reverse — a plain "no such request"
    /// instead of a lookup that half succeeds. Raw bytes and their hash are
    /// kept exactly as `ingest_request` keeps them: the sealed body is what
    /// a device signs, and the server never re-serializes it.
    pub fn ingest_auth_request(
        &self,
        raw: &[u8],
        envelope: &AuthEnvelopeV1,
        now: i64,
    ) -> Result<InsertResult> {
        if raw.len() > oshioki_protocol::v1::MAX_ENVELOPE_BYTES {
            bail!("oversized authentication envelope");
        }
        envelope
            .validate_at(now)
            .context("validate authentication envelope")?;
        let hash = Sha256::digest(raw).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old_hash = transaction
            .query_row(
                "SELECT envelope_hash FROM auth_requests WHERE id=?1",
                [&envelope.request_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(old_hash) = old_hash {
            if old_hash == hash {
                return Ok(InsertResult::Identical);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO tombstones(kind, object_id, payload_hash, expires_at) VALUES ('auth_request_conflict', ?1, ?2, ?3)",
                params![
                    envelope.request_id,
                    hash,
                    envelope
                        .expires_at
                        .min(now.saturating_add(SERVER_REQUEST_RETENTION_SECS))
                ],
            )?;
            transaction.commit()?;
            return Ok(InsertResult::Conflict);
        }
        transaction.execute(
            "INSERT INTO auth_requests(id, envelope_hash, envelope_json, host, issued_at, expires_at, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
            params![
                envelope.request_id,
                hash,
                raw,
                envelope.host,
                envelope.issued_at,
                envelope.expires_at,
                now,
            ],
        )?;
        for body in &envelope.sealed {
            transaction.execute(
                "INSERT INTO auth_sealed_bodies(request_id, fingerprint, body_json) VALUES (?1, ?2, ?3)",
                params![
                    envelope.request_id,
                    body.device_fingerprint,
                    serde_json::to_vec(body)?
                ],
            )?;
        }
        let push_payload = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "lane": "auth",
            "request_id": envelope.request_id,
        }))?;
        transaction.execute(
            "INSERT OR IGNORE INTO push_outbox
             (request_kind, request_id, subscription_id, payload, created_at, available_at)
             SELECT 'auth', ?1, p.id, ?2, ?3, ?3
             FROM push_subscriptions p
             JOIN devices d ON d.fingerprint=p.device_fingerprint
             JOIN auth_sealed_bodies b ON b.fingerprint=d.fingerprint AND b.request_id=?1
             WHERE d.active=1 AND p.disabled_at IS NULL
               AND (p.expiration_at IS NULL OR p.expiration_at>?3)",
            params![envelope.request_id, push_payload, now],
        )?;
        // Same rule as the command lane: a delivery receipt is a relay
        // commitment for an enrolled browser recipient, never evidence that
        // a browser opened anything. The authenticated AliveV1 POST remains
        // the only signal that says a browser did.
        let has_active_browser = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM auth_sealed_bodies b
                 JOIN devices d ON d.fingerprint=b.fingerprint
                 WHERE b.request_id=?1 AND d.active=1
                   AND COALESCE(json_extract(d.public_record_json, '$.kind'), 'webauthn')='webauthn'
             )",
            [&envelope.request_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if has_active_browser {
            let delivery = serde_json::to_vec(&DeliveryV1::for_request(&envelope.request_id))?;
            transaction.execute(
                "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at, expires_at)
                 VALUES ('delivery', ?1, ?2, ?3, unixepoch(), ?4)",
                params![
                    envelope.request_id,
                    format!("oshioki.delivery.{}", envelope.request_id),
                    delivery,
                    envelope.expires_at
                ],
            )?;
        }
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    /// The sealed authentication body addressed to the device holding this
    /// API token, while the request is still answerable.
    pub fn sealed_auth_request_for_token(
        &self,
        request_id: &str,
        token: &[u8],
        now: i64,
    ) -> Result<Option<SealedRequest>> {
        let token_hash = Sha256::digest(token).to_vec();
        self.lock()?.query_row(
            "SELECT CAST(b.body_json AS TEXT), r.expires_at FROM auth_requests r
             JOIN auth_sealed_bodies b ON b.request_id=r.id
             JOIN devices d ON d.fingerprint=b.fingerprint
             WHERE r.id=?1 AND r.state='pending' AND r.expires_at>?2 AND d.active=1 AND d.api_token_hash=?3",
            params![request_id, now, token_hash],
            |row| Ok(SealedRequest { body_json: row.get(0)?, expires_at: row.get(1)? }),
        ).optional().map_err(Into::into)
    }

    /// Records one authentication assertion and queues it for the verdict
    /// subject the hook is waiting on.
    ///
    /// There is no denial counterpart, here or anywhere on this lane: an
    /// authentication either produces a hardware assertion or nothing at
    /// all, and the host then asks for a password.
    pub fn queue_auth_decision(
        &self,
        request_id: &str,
        fingerprint: &str,
        decision: &AuthDecisionV1,
        now: i64,
    ) -> Result<InsertResult> {
        let raw = serde_json::to_vec(decision)?;
        let hash = Sha256::digest(&raw).to_vec();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT state, expires_at, decision_hash FROM auth_requests WHERE id=?1",
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
            bail!("unknown authentication request")
        };
        if expires_at <= now {
            bail!("expired authentication request");
        }
        // Ownership on this lane also means assurance: only a hardware kind
        // may answer an authentication. The hook re-checks this against its
        // own pinned registry before it accepts anything, but a software
        // device must not even be able to occupy the request by answering
        // first. `kind` is stored as its wire spelling inside
        // `public_record_json`; records written before native devices
        // existed carry no field and are WebAuthn, as elsewhere.
        let owns = transaction
            .query_row(
                "SELECT 1 FROM auth_sealed_bodies b JOIN devices d ON d.fingerprint=b.fingerprint
             WHERE b.request_id=?1 AND b.fingerprint=?2 AND d.active=1
               AND COALESCE(json_extract(d.public_record_json, '$.kind'), 'webauthn')
                   IN ('webauthn', 'secure-enclave')",
                params![request_id, fingerprint],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !owns {
            bail!("device does not own authentication request");
        }
        if state != "pending" {
            return Ok(if old_hash.as_deref() == Some(hash.as_slice()) {
                InsertResult::Identical
            } else {
                InsertResult::Conflict
            });
        }
        transaction.execute(
            "UPDATE auth_requests SET state='resolved', decision_hash=?2, resolved_at=unixepoch() WHERE id=?1 AND state='pending'",
            params![request_id, hash],
        )?;
        transaction.execute(
            "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at)
             VALUES ('auth_decision', ?1, ?2, ?3, unixepoch())",
            params![request_id, format!("oshioki.verdict.{request_id}"), raw],
        )?;
        transaction.commit()?;
        Ok(InsertResult::Inserted)
    }

    /// The retained copy of a queued authentication assertion. Kept in its
    /// own outbox kind, so a command verdict can never be read back as an
    /// authentication or the other way round.
    pub fn recorded_auth_verdict(&self, request_id: &str) -> Result<Option<Vec<u8>>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT payload FROM outbox WHERE kind='auth_decision' AND dedupe_key=?1 ORDER BY id DESC LIMIT 1",
                [request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn auth_request_lifecycle(
        &self,
        request_id: &str,
        now: i64,
    ) -> Result<Option<RequestLifecycle>> {
        let row = self
            .lock()?
            .query_row(
                "SELECT state, expires_at FROM auth_requests WHERE id=?1",
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

    /// The retained copy of a queued API verdict, for hooks confirming a
    /// relayed denial they cannot verify by signature. The outbox row is the
    /// server's record of what its authenticated API accepted; mark-sent
    /// rows are kept, so the record survives delivery.
    pub fn recorded_verdict(&self, request_id: &str) -> Result<Option<Vec<u8>>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT payload FROM outbox WHERE kind='decision' AND dedupe_key=?1 ORDER BY id DESC LIMIT 1",
                [request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Claims one eligible push row. The validity check and lease update are
    /// one SQLite transaction, so two worker loops cannot send the same row
    /// concurrently. A stale lease is reclaimable after a worker crash.
    pub fn claim_push(&self, now: i64, lease_secs: i64) -> Result<Option<PushItem>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<PushClaimRow> =
            transaction
                .query_row(
                    "SELECT p.id, p.subscription_id, s.endpoint, s.p256dh, s.auth, p.payload,
                            p.request_kind, p.request_id,
                            CASE p.request_kind WHEN 'request' THEN r.expires_at ELSE a.expires_at END,
                            p.attempts
                     FROM push_outbox p
                     JOIN push_subscriptions s ON s.id=p.subscription_id
                     LEFT JOIN requests r ON p.request_kind='request' AND r.id=p.request_id
                     LEFT JOIN auth_requests a ON p.request_kind='auth' AND a.id=p.request_id
                     JOIN devices d ON d.fingerprint=s.device_fingerprint
                     WHERE p.sent_at IS NULL AND p.abandoned_at IS NULL
                       AND p.available_at<=?1
                       AND (p.claimed_until IS NULL OR p.claimed_until<=?1)
                       AND p.attempts < ?2
                       AND d.active=1 AND s.disabled_at IS NULL
                       AND (s.expiration_at IS NULL OR s.expiration_at>?1)
                       AND ((p.request_kind='request' AND r.state='pending' AND r.expires_at>?1)
                            OR (p.request_kind='auth' AND a.state='pending' AND a.expires_at>?1))
                     ORDER BY p.id LIMIT 1",
                    params![now, PUSH_MAX_ATTEMPTS],
                    |row| {
                        Ok((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                            row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                        ))
                    },
                )
                .optional()?;
        let Some((
            id,
            subscription_id,
            endpoint,
            p256dh,
            auth,
            payload,
            request_kind,
            request_id,
            expires_at,
            attempts,
        )) = row
        else {
            transaction.execute(
                "UPDATE push_outbox SET abandoned_at=?1, claim_token=NULL, claimed_until=NULL,
                 last_error='attempt_limit' WHERE sent_at IS NULL AND abandoned_at IS NULL
                 AND attempts>=?2 AND (claimed_until IS NULL OR claimed_until<=?1)",
                params![now, PUSH_MAX_ATTEMPTS],
            )?;
            transaction.execute(
                "UPDATE push_outbox SET abandoned_at=?1 WHERE sent_at IS NULL AND abandoned_at IS NULL
                 AND ((request_kind='request' AND NOT EXISTS
                      (SELECT 1 FROM requests r WHERE r.id=push_outbox.request_id AND r.state='pending' AND r.expires_at>?1))
                   OR (request_kind='auth' AND NOT EXISTS
                      (SELECT 1 FROM auth_requests a WHERE a.id=push_outbox.request_id AND a.state='pending' AND a.expires_at>?1))
                   OR NOT EXISTS (SELECT 1 FROM devices d JOIN push_subscriptions s ON s.device_fingerprint=d.fingerprint
                                  WHERE s.id=push_outbox.subscription_id AND d.active=1 AND s.disabled_at IS NULL
                                    AND (s.expiration_at IS NULL OR s.expiration_at>?1)))",
                [now],
            )?;
            transaction.commit()?;
            return Ok(None);
        };
        let claim_token = format!("pc_{}", uuid::Uuid::new_v4().simple());
        let changed = transaction.execute(
            "UPDATE push_outbox SET claim_token=?2, claimed_until=?3, attempts=attempts+1
             WHERE id=?1 AND sent_at IS NULL AND abandoned_at IS NULL
               AND (claimed_until IS NULL OR claimed_until<=?4)",
            params![id, claim_token, now.saturating_add(lease_secs), now],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(None);
        }
        transaction.commit()?;
        Ok(Some(PushItem {
            id,
            subscription_id,
            endpoint,
            p256dh,
            auth,
            payload,
            request_kind,
            request_id,
            expires_at,
            claim_token,
            attempts: attempts + 1,
        }))
    }

    pub fn mark_push_sent(&self, id: i64, claim_token: &str, now: i64) -> Result<bool> {
        Ok(self.lock()?.execute(
            "UPDATE push_outbox SET sent_at=?3, claim_token=NULL, claimed_until=NULL
             WHERE id=?1 AND claim_token=?2 AND sent_at IS NULL AND abandoned_at IS NULL",
            params![id, claim_token, now],
        )? == 1)
    }

    pub fn retry_push(&self, id: i64, claim_token: &str, now: i64, error: &str) -> Result<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempts: Option<i64> = transaction
            .query_row(
                "SELECT attempts FROM push_outbox WHERE id=?1 AND claim_token=?2
                 AND sent_at IS NULL AND abandoned_at IS NULL",
                params![id, claim_token],
                |row| row.get(0),
            )
            .optional()?;
        let Some(attempts) = attempts else {
            transaction.commit()?;
            return Ok(false);
        };
        if attempts >= PUSH_MAX_ATTEMPTS {
            transaction.execute(
                "UPDATE push_outbox SET abandoned_at=?3, claim_token=NULL, claimed_until=NULL, last_error=?4
                 WHERE id=?1 AND claim_token=?2 AND sent_at IS NULL AND abandoned_at IS NULL",
                params![id, claim_token, now, error],
            )?;
        } else {
            let delay = 1_i64 << (attempts - 1).clamp(0, 4);
            transaction.execute(
                "UPDATE push_outbox SET available_at=?3, claim_token=NULL, claimed_until=NULL, last_error=?4
                 WHERE id=?1 AND claim_token=?2 AND sent_at IS NULL AND abandoned_at IS NULL",
                params![id, claim_token, now.saturating_add(delay), error],
            )?;
        }
        let changed = transaction.changes() == 1;
        transaction.commit()?;
        Ok(changed)
    }

    pub fn abandon_push(&self, id: i64, claim_token: &str, now: i64, error: &str) -> Result<bool> {
        Ok(self.lock()?.execute(
            "UPDATE push_outbox SET abandoned_at=?3, claim_token=NULL, claimed_until=NULL, last_error=?4
             WHERE id=?1 AND claim_token=?2 AND sent_at IS NULL AND abandoned_at IS NULL",
            params![id, claim_token, now, error],
        )? == 1)
    }

    pub fn disable_push_for_claim(
        &self,
        id: i64,
        subscription_id: &str,
        claim_token: &str,
        now: i64,
        error: &str,
    ) -> Result<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE push_outbox SET abandoned_at=?4, claim_token=NULL, claimed_until=NULL, last_error=?5
             WHERE id=?1 AND subscription_id=?2 AND claim_token=?3
               AND sent_at IS NULL AND abandoned_at IS NULL",
            params![id, subscription_id, claim_token, now, error],
        )?;
        if changed == 1 {
            transaction.execute(
                "UPDATE push_subscriptions SET disabled_at=?2, updated_at=?2, last_error=?3
                 WHERE id=?1 AND disabled_at IS NULL",
                params![subscription_id, now, error],
            )?;
        }
        transaction.commit()?;
        Ok(changed == 1)
    }

    /// Verdicts, delivery receipts, and enrollment relays publish to NATS.
    /// Notifications are deliberately not here: one failed ntfy delivery
    /// must never hold up the approval path, so each lane drains its own rows.
    pub fn pending_verdicts(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        self.pending_outbox_where("kind != 'ntfy'", limit)
    }

    pub fn pending_notifications(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        self.pending_outbox_where("kind = 'ntfy'", limit)
    }

    fn pending_outbox_where(&self, condition: &str, limit: usize) -> Result<Vec<OutboxItem>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(&format!(
            "SELECT id, subject, payload FROM outbox WHERE sent_at IS NULL AND {condition} ORDER BY id LIMIT ?1",
        ))?;
        let rows = statement.query_map([i64::try_from(limit)?], |row| {
            Ok(OutboxItem {
                id: row.get(0)?,
                subject: row.get(1)?,
                payload: row.get(2)?,
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

    /// Drops undelivered rows whose request deadline has passed.
    ///
    /// Only browser delivery receipts carry a deadline. A receipt says a
    /// relay committed a request to an enrolled browser while that request
    /// could still be answered; past its deadline it says nothing anyone can
    /// act on. The lane drains in id order, so after a NATS outage a backlog
    /// of dead receipts would sit in front of the live request the hook is
    /// waiting on, which is exactly the delay this removes. Verdicts and
    /// enrollment relays carry no deadline and are never touched: a verdict
    /// is delivered whenever it can be.
    ///
    /// Dropping the row rather than marking it keeps request idempotency
    /// intact: the row is the receipt's one-per-request guard only while the
    /// request is still ingestible, and an envelope past its deadline is
    /// refused before it can queue a second one.
    pub fn expire_stale_deliveries(&self, now: i64) -> Result<usize> {
        let dropped = self.lock()?.execute(
            "DELETE FROM outbox WHERE kind='delivery' AND sent_at IS NULL
             AND expires_at IS NOT NULL AND expires_at<=?1",
            [now],
        )?;
        Ok(dropped)
    }

    pub fn mark_outbox_sent(&self, id: i64) -> Result<()> {
        self.lock()?.execute(
            "UPDATE outbox SET sent_at=unixepoch(), attempts=attempts+1 WHERE id=?1",
            [id],
        )?;
        Ok(())
    }

    pub fn cleanup(&self, now: i64) -> Result<()> {
        self.expire_stale_deliveries(now)?;
        let connection = self.lock()?;
        connection.execute(
            "UPDATE enrollments SET status='expired' WHERE status='pending' AND expires_at<=?1",
            [now],
        )?;
        connection.execute(
            "DELETE FROM requests WHERE created_at < ?1",
            [now.saturating_sub(SERVER_REQUEST_RETENTION_SECS)],
        )?;
        connection.execute(
            "DELETE FROM auth_requests WHERE created_at < ?1",
            [now.saturating_sub(SERVER_REQUEST_RETENTION_SECS)],
        )?;
        connection.execute("DELETE FROM tombstones WHERE expires_at < ?1", [now])?;
        connection.execute(
            "DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?1",
            [now - 86_400],
        )?;
        connection.execute(
            "DELETE FROM push_outbox WHERE (sent_at IS NOT NULL OR abandoned_at IS NOT NULL) AND
             COALESCE(sent_at, abandoned_at) < ?1",
            [now - SERVER_REQUEST_RETENTION_SECS],
        )?;
        connection.execute(
            "DELETE FROM push_subscriptions WHERE disabled_at IS NOT NULL AND disabled_at < ?1",
            [now - PUSH_DISABLED_RETENTION_SECS],
        )?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite mutex poisoned"))
    }
}

pub fn validate_push_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.is_empty()
        || endpoint.len() > PUSH_MAX_ENDPOINT_BYTES
        || endpoint.chars().any(char::is_control)
    {
        bail!("invalid push endpoint");
    }
    let url = Url::parse(endpoint).context("parse push endpoint")?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid push endpoint policy");
    }
    let Some(host) = url.host_str() else {
        bail!("push endpoint has no host");
    };
    if matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)))
        || host.parse::<std::net::IpAddr>().is_ok()
        || url.port().is_some_and(|port| port == 0)
    {
        bail!("push endpoint host is not allowed");
    }
    Ok(())
}

/// Restore snapshot beside the live database: `state.sqlite3` at version 2
/// becomes `state.pre-v2.sqlite3`. Each upgrade attempt writes a fresh copy
/// of the current live file; a previous snapshot at that path is renamed
/// aside so a later rollback cannot rewind past intervening enrollments.
pub fn restore_snapshot_path(path: &Path, from_version: i64) -> PathBuf {
    sibling_with_name(path, &restore_snapshot_name(path, from_version))
}

fn restore_snapshot_name(path: &Path, from_version: i64) -> String {
    let file_name = path.file_name().map_or_else(
        || "state.sqlite3".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    match file_name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}.pre-v{from_version}.{ext}"),
        None => format!("{file_name}.pre-v{from_version}"),
    }
}

fn sibling_with_name(path: &Path, name: &str) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

fn archive_restore_snapshot_path(snapshot: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let file_name = snapshot.file_name().map_or_else(
        || "state.pre-v.sqlite3".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    match file_name.rsplit_once('.') {
        Some((stem, ext)) => sibling_with_name(snapshot, &format!("{stem}.{stamp}.{ext}")),
        None => sibling_with_name(snapshot, &format!("{file_name}.{stamp}")),
    }
}

fn create_verified_restore_snapshot(
    connection: &Connection,
    live_path: &Path,
    from_version: i64,
) -> Result<()> {
    let snapshot = restore_snapshot_path(live_path, from_version);
    let staging = sibling_with_name(
        &snapshot,
        &format!(
            "{}.creating",
            snapshot.file_name().map_or_else(
                || "state.pre-v.sqlite3".into(),
                |name| name.to_string_lossy().into_owned()
            )
        ),
    );
    if staging.exists() {
        std::fs::remove_file(&staging)
            .with_context(|| format!("remove leftover snapshot staging {}", staging.display()))?;
    }
    let dest = staging
        .to_str()
        .with_context(|| format!("restore snapshot path {} is not UTF-8", staging.display()))?;
    connection
        .execute("VACUUM INTO ?1", [dest])
        .with_context(|| format!("create restore snapshot {}", staging.display()))?;
    if let Err(error) = verify_restore_snapshot(&staging, from_version) {
        let _ = std::fs::remove_file(&staging);
        return Err(error).context(format!(
            "restore snapshot {} failed verification; left the live database unmigrated",
            staging.display()
        ));
    }
    if snapshot.exists() {
        let archived = archive_restore_snapshot_path(&snapshot);
        std::fs::rename(&snapshot, &archived).with_context(|| {
            format!(
                "archive previous restore snapshot {} to {}",
                snapshot.display(),
                archived.display()
            )
        })?;
    }
    std::fs::rename(&staging, &snapshot).with_context(|| {
        format!(
            "install restore snapshot {} from {}",
            snapshot.display(),
            staging.display()
        )
    })?;
    Ok(())
}

fn verify_restore_snapshot(path: &Path, expected_version: i64) -> Result<()> {
    let connection = Connection::open(path)
        .with_context(|| format!("open restore snapshot {}", path.display()))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != expected_version {
        bail!(
            "restore snapshot {} has schema version {version}, expected {expected_version}",
            path.display()
        );
    }
    if expected_version >= 1 {
        let tables: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='devices'",
            [],
            |row| row.get(0),
        )?;
        if tables != 1 {
            bail!(
                "restore snapshot {} is missing the devices table",
                path.display()
            );
        }
    }
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .with_context(|| format!("prepare integrity_check for {}", path.display()))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .with_context(|| format!("run integrity_check for {}", path.display()))?
        .collect::<rusqlite::Result<Vec<String>>>()
        .with_context(|| format!("read integrity_check for {}", path.display()))?;
    if rows != ["ok"] {
        bail!(
            "restore snapshot {} failed integrity_check: {}",
            path.display(),
            rows.join("; ")
        );
    }
    Ok(())
}

/// The schema, applied on every open. It is additive only and stays at
/// `user_version = 1`: every statement is `CREATE ... IF NOT EXISTS`, so an
/// existing database gains the authentication tables on the next start
/// without a version step, and a server rolled back to an older build still
/// reads the command lane exactly as it did before.
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
CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY, envelope_hash BLOB NOT NULL, envelope_json BLOB NOT NULL,
  host TEXT NOT NULL, issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, state TEXT NOT NULL, decision_hash BLOB,
  created_at INTEGER NOT NULL, resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS auth_sealed_bodies (
  request_id TEXT NOT NULL REFERENCES auth_requests(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS auth_requests_expiry_idx ON auth_requests(expires_at);
CREATE INDEX IF NOT EXISTS auth_requests_created_idx ON auth_requests(created_at);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(sent_at, id);
PRAGMA user_version = 1;
COMMIT;
";

/// Adds the deadline an outbox row is worth delivering until.
///
/// `ALTER TABLE ... ADD COLUMN` is not idempotent, so unlike V1 and V2 this
/// step runs exactly once, on the 2 -> 3 upgrade. The column is nullable and
/// only browser delivery receipts carry a value: a verdict or an enrollment
/// relay has no deadline of its own and is delivered whenever it can be.
const MIGRATION_V3: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE outbox ADD COLUMN expires_at INTEGER;
CREATE INDEX IF NOT EXISTS outbox_expiry_idx ON outbox(sent_at, expires_at);
PRAGMA user_version = 3;
COMMIT;
";

const MIGRATION_V2: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY, envelope_hash BLOB NOT NULL, envelope_json BLOB NOT NULL,
  host TEXT NOT NULL, issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, state TEXT NOT NULL, decision_hash BLOB,
  created_at INTEGER NOT NULL, resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS auth_sealed_bodies (
  request_id TEXT NOT NULL REFERENCES auth_requests(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL, body_json BLOB NOT NULL,
  PRIMARY KEY(request_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS auth_requests_expiry_idx ON auth_requests(expires_at);
CREATE INDEX IF NOT EXISTS auth_requests_created_idx ON auth_requests(created_at);
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  device_fingerprint TEXT NOT NULL REFERENCES devices(fingerprint),
  endpoint TEXT NOT NULL UNIQUE,
  p256dh BLOB NOT NULL,
  auth BLOB NOT NULL,
  expiration_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  disabled_at INTEGER,
  last_error TEXT
);
CREATE INDEX IF NOT EXISTS push_subscriptions_device_idx
  ON push_subscriptions(device_fingerprint, disabled_at);
CREATE TABLE IF NOT EXISTS push_outbox (
  id INTEGER PRIMARY KEY,
  request_kind TEXT NOT NULL CHECK(request_kind IN ('request','auth')),
  request_id TEXT NOT NULL,
  subscription_id TEXT NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  available_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_at INTEGER,
  abandoned_at INTEGER,
  claim_token TEXT,
  claimed_until INTEGER,
  last_error TEXT,
  UNIQUE(request_kind, request_id, subscription_id)
);
CREATE INDEX IF NOT EXISTS push_outbox_pending_idx
  ON push_outbox(sent_at, abandoned_at, available_at, id);
PRAGMA user_version = 2;
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
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_database() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oshioki-db-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.sqlite3")
    }

    fn remove_database(path: &Path) {
        if let Some(parent) = path.parent() {
            let name = parent
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.starts_with("oshioki-db-test-") {
                let _ = std::fs::remove_dir_all(parent);
                let _ = std::fs::create_dir_all(parent);
                return;
            }
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn device(token: &[u8]) -> DevicePublicRecordV1 {
        let credential_id = vec![1; 16];
        let signing = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let cose = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut credential_public_key = Vec::new();
        ciborium::ser::into_writer(&cose, &mut credential_public_key).unwrap();
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

    fn alternate_device(token: &[u8]) -> DevicePublicRecordV1 {
        let mut value = device(token);
        let credential_id = vec![2; 16];
        value.credential_id = encode_base64url(&credential_id);
        value.fingerprint = oshioki_protocol::device_fingerprint(
            &credential_id,
            &oshioki_protocol::decode_base64url(&value.credential_public_key).unwrap(),
            &oshioki_protocol::decode_base64url(&value.box_public_key).unwrap(),
        );
        value
    }

    fn envelope(fingerprint: &str) -> RequestEnvelopeV1 {
        RequestEnvelopeV1 {
            version: 1,
            request_id: "request-1".into(),
            host: "nas".into(),
            user: "eric".into(),
            issued_at: 20,
            expires_at: 110,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: fingerprint.into(),
                ephemeral_pub: encode_base64url(&[4; 32]),
                nonce: encode_base64url(&[5; 12]),
                ciphertext: encode_base64url(&[6; 32]),
            }],
        }
    }

    /// The schema a server carried before the authentication lane existed:
    /// the command-lane statements verbatim, with no `auth_*` tables.
    const COMMAND_ONLY_SCHEMA_V1: &str = include_str!("../../tests/compat/goldens/state-v1.sql");

    fn table_names(store: &Store) -> Vec<String> {
        let connection = store.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    fn auth_envelope(fingerprint: &str, id: &str, now: i64) -> AuthEnvelopeV1 {
        AuthEnvelopeV1 {
            message_type: oshioki_protocol::AUTH_ENVELOPE_TYPE.into(),
            version: oshioki_protocol::AUTH_WIRE_VERSION,
            request_id: id.into(),
            host: "nas".into(),
            issued_at: now - 1,
            expires_at: now + 60,
            sealed: vec![SealedDeviceBodyV1 {
                device_fingerprint: fingerprint.to_owned(),
                ephemeral_pub: encode_base64url(&[4; 32]),
                nonce: encode_base64url(&[5; 12]),
                ciphertext: encode_base64url(&[6; 32]),
            }],
        }
    }

    fn push_material() -> (Vec<u8>, Vec<u8>) {
        let signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let mut p256dh = vec![4];
        p256dh.extend_from_slice(point.x().unwrap());
        p256dh.extend_from_slice(point.y().unwrap());
        (p256dh, vec![9; PUSH_AUTH_BYTES])
    }

    #[test]
    fn v1_upgrade_is_exact_and_newer_versions_are_refused() {
        let path = temporary_database();
        remove_database(&path);
        {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(MIGRATION_V1).unwrap();
        }
        let store = Store::open(&path).unwrap();
        store.ready().unwrap();
        let version: i64 = store
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        drop(store);
        let snapshot = restore_snapshot_path(&path, 1);
        assert!(snapshot.exists(), "{}", snapshot.display());
        verify_restore_snapshot(&snapshot, 1).unwrap();
        let _ = std::fs::remove_file(&snapshot);
        {
            let connection = Connection::open(&path).unwrap();
            connection.pragma_update(None, "user_version", 99).unwrap();
        }
        assert!(Store::open(&path).is_err());
        remove_database(&path);
    }

    #[test]
    fn push_registration_is_owned_and_redelivery_is_deduplicated() {
        let store = Store::memory().unwrap();
        let token = b"push-token";
        let browser = device(token);
        store.put_device(&browser).unwrap();
        let (p256dh, auth) = push_material();
        let id = store
            .register_push_subscription(
                token,
                "https://push.example.test/send/1",
                &p256dh,
                &auth,
                None,
                20,
            )
            .unwrap();
        assert_eq!(store.push_status(token).unwrap().count, 1);
        assert_eq!(
            store
                .register_push_subscription(
                    token,
                    "https://push.example.test/send/1",
                    &p256dh,
                    &auth,
                    None,
                    20,
                )
                .unwrap(),
            id
        );
        let envelope = envelope(&browser.fingerprint);
        let raw = serde_json::to_vec(&envelope).unwrap();
        store.ingest_request(&raw, &envelope, 20).unwrap();
        store.ingest_request(&raw, &envelope, 20).unwrap();
        let item = store.claim_push(20, PUSH_LEASE_SECS).unwrap().unwrap();
        assert_eq!(item.subscription_id, id);
        let payload: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(
            payload,
            serde_json::json!({"version":1,"lane":"request","request_id":"request-1"})
        );
        assert!(store.claim_push(20, PUSH_LEASE_SECS).unwrap().is_none());
        assert!(
            store
                .mark_push_sent(item.id, &item.claim_token, 20)
                .unwrap()
        );
        let id2 = store
            .register_push_subscription(
                token,
                "https://push.example.test/send/2",
                &p256dh,
                &auth,
                None,
                20,
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO push_outbox(request_kind, request_id, subscription_id, payload, created_at, available_at)
                 VALUES ('request', ?1, ?2, ?3, ?4, ?4)",
                params!["request-1", id2, serde_json::to_vec(&payload).unwrap(), 20],
            )
            .unwrap();
        let item2 = store.claim_push(20, PUSH_LEASE_SECS).unwrap().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE push_outbox SET attempts=?2, claimed_until=?1 WHERE id=?3",
                params![20, PUSH_MAX_ATTEMPTS, item2.id],
            )
            .unwrap();
        assert!(store.claim_push(20, PUSH_LEASE_SECS).unwrap().is_none());
        assert!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT abandoned_at IS NOT NULL FROM push_outbox WHERE id=?1",
                    [item2.id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        assert!(
            !store
                .mark_push_sent(item2.id, &item2.claim_token, 20)
                .unwrap()
        );
        assert!(store.push_status(b"wrong-token").is_err());
    }

    #[test]
    fn push_endpoint_policy_rejects_private_forms_and_key_bounds() {
        for endpoint in [
            "http://push.example.test/send",
            "https://user:pass@push.example.test/send",
            "https://push.example.test/send#fragment",
            "https://127.0.0.1/send",
            "https://[::1]/send",
        ] {
            assert!(validate_push_endpoint(endpoint).is_err(), "{endpoint}");
        }
        let store = Store::memory().unwrap();
        let token = b"push-key-token";
        store.put_device(&device(token)).unwrap();
        let (p256dh, auth) = push_material();
        assert!(
            store
                .register_push_subscription(
                    token,
                    "https://push.example.test/send",
                    &p256dh[..64],
                    &auth,
                    None,
                    20,
                )
                .is_err()
        );
    }

    #[test]
    fn push_endpoint_ownership_allows_inactive_reassignment_and_revoke_cleanup() {
        let store = Store::memory().unwrap();
        let first_token = b"first-push-owner";
        let second_token = b"second-push-owner";
        let first = device(first_token);
        let second = alternate_device(second_token);
        store.put_device(&first).unwrap();
        store.put_device(&second).unwrap();
        let (p256dh, auth) = push_material();
        let endpoint = "https://push.example.test/owned";
        let id = store
            .register_push_subscription(first_token, endpoint, &p256dh, &auth, None, 20)
            .unwrap();
        assert!(
            store
                .register_push_subscription(second_token, endpoint, &p256dh, &auth, None, 20)
                .is_err()
        );
        assert!(store.set_device_active(&first.fingerprint, false).unwrap());
        assert_eq!(
            store
                .register_push_subscription(second_token, endpoint, &p256dh, &auth, None, 20)
                .unwrap(),
            id
        );
        let envelope = envelope(&second.fingerprint);
        store
            .ingest_request(&serde_json::to_vec(&envelope).unwrap(), &envelope, 20)
            .unwrap();
        assert!(store.set_device_active(&second.fingerprint, false).unwrap());
        assert!(store.push_status(second_token).is_err());
        assert!(store.claim_push(20, PUSH_LEASE_SECS).unwrap().is_none());
        let disabled: bool = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT disabled_at IS NOT NULL FROM push_subscriptions WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(disabled);
    }

    #[test]
    fn auth_fanout_payload_is_minimal_and_lane_specific() {
        let store = Store::memory().unwrap();
        let token = b"auth-push-token";
        let browser = device(token);
        store.put_device(&browser).unwrap();
        let (p256dh, auth) = push_material();
        store
            .register_push_subscription(
                token,
                "https://push.example.test/auth",
                &p256dh,
                &auth,
                None,
                20,
            )
            .unwrap();
        let envelope = auth_envelope(&browser.fingerprint, "auth-push", 20);
        store
            .ingest_auth_request(&serde_json::to_vec(&envelope).unwrap(), &envelope, 20)
            .unwrap();
        let item = store.claim_push(20, PUSH_LEASE_SECS).unwrap().unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
        assert_eq!(
            payload,
            serde_json::json!({"version":1,"lane":"auth","request_id":"auth-push"})
        );
    }

    /// A database written by a server that predates the authentication lane
    /// gains the new lane and push tables on the next open, keeps every
    /// command-lane row it already held, and advances to schema version 2.
    /// Opening it twice more changes nothing: the migration is idempotent.
    #[test]
    fn an_existing_database_gains_the_authentication_tables_in_place() {
        let path = temporary_database();
        remove_database(&path);
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(COMMAND_ONLY_SCHEMA_V1).unwrap();
            let names: Vec<String> = old
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(!names.iter().any(|name| name.starts_with("auth_")));
        }
        // The shared `envelope` helper is issued at 20 and expires at 110,
        // so the clock here sits inside its window as the other tests' does.
        let now = 30;
        // A command-lane row written against the old schema.
        {
            let store = Store::open(&path).unwrap();
            let device = device(b"token-before-the-auth-lane-000000");
            store.put_device(&device).unwrap();
            let envelope = envelope(&device.fingerprint);
            store
                .ingest_request(&serde_json::to_vec(&envelope).unwrap(), &envelope, now)
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        store.ready().unwrap();
        let names = table_names(&store);
        assert!(names.iter().any(|name| name == "auth_requests"));
        assert!(names.iter().any(|name| name == "auth_sealed_bodies"));
        // The pre-existing row survived the migration untouched.
        assert_eq!(
            store.request_lifecycle("request-1", now).unwrap(),
            Some(RequestLifecycle::Pending)
        );
        // And the new lane works on the upgraded database.
        let device = store
            .active_device(&device(b"token-before-the-auth-lane-000000").fingerprint)
            .unwrap()
            .unwrap();
        let auth = auth_envelope(&device.fingerprint, "auth-upgraded", now);
        assert_eq!(
            store
                .ingest_auth_request(&serde_json::to_vec(&auth).unwrap(), &auth, now)
                .unwrap(),
            InsertResult::Inserted
        );
        drop(store);
        // Re-opening applies the same batch again and changes nothing.
        let reopened = Store::open(&path).unwrap();
        reopened.ready().unwrap();
        assert_eq!(table_names(&reopened), names);
        assert_eq!(
            reopened.request_lifecycle("request-1", now).unwrap(),
            Some(RequestLifecycle::Pending)
        );
        assert_eq!(
            reopened
                .auth_request_lifecycle("auth-upgraded", now)
                .unwrap(),
            Some(RequestLifecycle::Pending)
        );
        drop(reopened);
        remove_database(&path);
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
    fn delivery_receipt_is_durable_only_for_an_active_browser_recipient() {
        let store = Store::memory().unwrap();
        let browser = device(b"delivery-token");
        store.put_device(&browser).unwrap();
        let browser_envelope = envelope(&browser.fingerprint);
        let raw = serde_json::to_vec(&browser_envelope).unwrap();
        assert_eq!(
            store.ingest_request(&raw, &browser_envelope, 20).unwrap(),
            InsertResult::Inserted
        );
        let pending = store.pending_verdicts(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].subject, "oshioki.delivery.request-1");
        let receipt: DeliveryV1 = serde_json::from_slice(&pending[0].payload).unwrap();
        receipt.validate("request-1").unwrap();
        let mut invalid_receipt = receipt.clone();
        invalid_receipt.request_id = "request-2".into();
        assert!(invalid_receipt.validate("request-1").is_err());

        let mut inactive = browser.clone();
        inactive.active = false;
        store.put_device(&inactive).unwrap();
        let mut second = envelope(&inactive.fingerprint);
        second.request_id = "request-2".into();
        let second_raw = serde_json::to_vec(&second).unwrap();
        store.ingest_request(&second_raw, &second, 20).unwrap();
        assert!(
            store
                .pending_verdicts(10)
                .unwrap()
                .iter()
                .all(|item| item.subject != "oshioki.delivery.request-2")
        );

        let (_, native) = native_pair("native-receipt", 9, b"native-token", "native");
        store.put_device(&native).unwrap();
        let mut native_request = envelope(&native.fingerprint);
        native_request.request_id = "request-native".into();
        let native_raw = serde_json::to_vec(&native_request).unwrap();
        store
            .ingest_request(&native_raw, &native_request, 20)
            .unwrap();
        assert!(
            store
                .pending_verdicts(10)
                .unwrap()
                .iter()
                .all(|item| item.subject != "oshioki.delivery.request-native")
        );

        let legacy_json = serde_json::to_value(&browser).unwrap();
        let mut legacy_object = legacy_json.as_object().unwrap().clone();
        legacy_object.remove("kind");
        let legacy_json = serde_json::to_string(&legacy_object).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE devices SET active=1, public_record_json=?1 WHERE fingerprint=?2",
                rusqlite::params![legacy_json, browser.fingerprint.clone()],
            )
            .unwrap();
        let mut legacy_request = envelope(&browser.fingerprint);
        legacy_request.request_id = "request-legacy".into();
        let legacy_raw = serde_json::to_vec(&legacy_request).unwrap();
        store
            .ingest_request(&legacy_raw, &legacy_request, 20)
            .unwrap();
        assert!(
            store
                .pending_verdicts(10)
                .unwrap()
                .iter()
                .any(|item| item.subject == "oshioki.delivery.request-legacy")
        );
    }

    /// #59: a NATS outage leaves the outbox holding receipts for requests
    /// that died while it was down. The lane drains in id order, so those
    /// receipts would sit in front of the one the hook is waiting on now.
    /// A database carrying the V2 schema gains the receipt deadline in
    /// place, keeps the rows it already held, and dates the receipts it
    /// queues from then on. Rows written before the upgrade have no deadline
    /// and are delivered as they always were.
    #[test]
    fn a_v2_database_gains_the_receipt_deadline_in_place() {
        let path = temporary_database();
        remove_database(&path);
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(MIGRATION_V1).unwrap();
            old.execute_batch(MIGRATION_V2).unwrap();
            old.execute(
                "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at)
                 VALUES ('delivery', 'request-before', 'oshioki.delivery.request-before', x'7b7d', 20)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        store.ready().unwrap();
        let version: i64 = store
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);

        let browser = device(b"upgrade-token");
        store.put_device(&browser).unwrap();
        let envelope = envelope(&browser.fingerprint);
        store
            .ingest_request(&serde_json::to_vec(&envelope).unwrap(), &envelope, 20)
            .unwrap();
        store.expire_stale_deliveries(200).unwrap();
        let pending = store.pending_verdicts(10).unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            // The row from before the upgrade carries no deadline, so it is
            // not expired; the one queued after it is, at 110.
            vec!["oshioki.delivery.request-before"]
        );
        drop(store);
        let snapshot = restore_snapshot_path(&path, 2);
        assert!(snapshot.exists(), "{}", snapshot.display());
        verify_restore_snapshot(&snapshot, 2).unwrap();
        let old = Connection::open(&snapshot).unwrap();
        let snapshot_version: i64 = old
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(snapshot_version, 2);
        let subject: String = old
            .query_row(
                "SELECT subject FROM outbox WHERE dedupe_key='request-before'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(subject, "oshioki.delivery.request-before");
        let _ = std::fs::remove_file(&snapshot);
        remove_database(&path);
    }

    fn insert_device_on(connection: &Connection, device: &DevicePublicRecordV1) {
        let api_token_hash = oshioki_protocol::decode_base64url(&device.api_token_hash).unwrap();
        connection
            .execute(
                "INSERT INTO devices(fingerprint, credential_id, api_token_hash, public_record_json, active, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, unixepoch())",
                rusqlite::params![
                    device.fingerprint,
                    device.credential_id,
                    api_token_hash,
                    serde_json::to_string(device).unwrap(),
                ],
            )
            .unwrap();
    }

    fn device_fingerprints(path: &Path) -> Vec<String> {
        let connection = Connection::open(path).unwrap();
        let mut statement = connection
            .prepare("SELECT fingerprint FROM devices ORDER BY fingerprint")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn a_second_upgrade_refreshes_the_restore_snapshot() {
        let path = temporary_database();
        remove_database(&path);
        let first = device(b"first-enroll");
        let later = alternate_device(b"later-enroll");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(MIGRATION_V1).unwrap();
            old.execute_batch(MIGRATION_V2).unwrap();
            insert_device_on(&old, &first);
        }
        let snapshot = restore_snapshot_path(&path, 2);
        {
            let store = Store::open(&path).unwrap();
            store.ready().unwrap();
            drop(store);
        }
        assert_eq!(
            device_fingerprints(&snapshot),
            vec![first.fingerprint.clone()]
        );
        std::fs::copy(&snapshot, &path).unwrap();
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        {
            let old = Connection::open(&path).unwrap();
            assert_eq!(
                old.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                2
            );
            insert_device_on(&old, &later);
        }
        {
            let store = Store::open(&path).unwrap();
            store.ready().unwrap();
            assert!(store.active_device(&later.fingerprint).unwrap().is_some());
            drop(store);
        }
        let mut fingerprints = device_fingerprints(&snapshot);
        fingerprints.sort();
        let mut expected = vec![first.fingerprint.clone(), later.fingerprint.clone()];
        expected.sort();
        assert_eq!(fingerprints, expected);
        remove_database(&path);
    }

    #[test]
    fn a_restore_snapshot_with_corrupt_data_pages_is_rejected() {
        let path = temporary_database();
        remove_database(&path);
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(MIGRATION_V1).unwrap();
            old.execute_batch(MIGRATION_V2).unwrap();
            let device = device(b"corrupt-me");
            let api_token_hash =
                oshioki_protocol::decode_base64url(&device.api_token_hash).unwrap();
            old.execute(
                "INSERT INTO devices(fingerprint, credential_id, api_token_hash, public_record_json, active, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, unixepoch())",
                rusqlite::params![
                    device.fingerprint,
                    device.credential_id,
                    api_token_hash,
                    serde_json::to_string(&device).unwrap(),
                ],
            )
            .unwrap();
        }
        let snapshot = restore_snapshot_path(&path, 2);
        {
            let live = Connection::open(&path).unwrap();
            live.execute("VACUUM INTO ?1", [snapshot.to_str().unwrap()])
                .unwrap();
        }
        verify_restore_snapshot(&snapshot, 2).unwrap();
        let mut bytes = std::fs::read(&snapshot).unwrap();
        let offset = if bytes.len() > 8192 {
            4096
        } else {
            bytes.len() / 2
        };
        assert!(offset >= 100, "snapshot too small to corrupt a data page");
        for byte in bytes.iter_mut().skip(offset).take(64) {
            *byte ^= 0xff;
        }
        std::fs::write(&snapshot, bytes).unwrap();
        let result = verify_restore_snapshot(&snapshot, 2);
        let error = result.expect_err("corrupt snapshot must not verify");
        let detail = format!("{error:#}");
        assert!(
            detail.contains("integrity_check")
                || detail.contains("malformed")
                || detail.contains("corrupt")
                || detail.contains("disk image"),
            "{detail}"
        );
        let _ = std::fs::remove_file(&snapshot);
        remove_database(&path);
    }

    #[test]
    fn restore_snapshot_path_keeps_the_live_stem() {
        assert_eq!(
            restore_snapshot_path(Path::new("/var/lib/oshioki/state.sqlite3"), 2),
            PathBuf::from("/var/lib/oshioki/state.pre-v2.sqlite3")
        );
        assert_eq!(
            restore_snapshot_path(Path::new("state.sqlite3"), 1),
            PathBuf::from("state.pre-v1.sqlite3")
        );
    }

    #[test]
    fn expired_delivery_receipts_do_not_delay_live_ones() {
        let store = Store::memory().unwrap();
        let browser = device(b"outage-token");
        store.put_device(&browser).unwrap();
        let stale = envelope(&browser.fingerprint);
        let stale_raw = serde_json::to_vec(&stale).unwrap();
        store.ingest_request(&stale_raw, &stale, 20).unwrap();
        // A verdict for that same dead request: it is not a receipt and must
        // still be delivered whenever the transport comes back.
        let decision = DecisionV1::Deny(DenyV1 {
            version: 1,
            request_id: stale.request_id.clone(),
            device_fingerprint: browser.fingerprint.clone(),
            signature: None,
        });
        store
            .queue_decision(&stale.request_id, &browser.fingerprint, &decision, 30)
            .unwrap();

        let mut live = envelope(&browser.fingerprint);
        live.request_id = "request-live".into();
        live.issued_at = 200;
        live.expires_at = 260;
        let live_raw = serde_json::to_vec(&live).unwrap();
        store.ingest_request(&live_raw, &live, 200).unwrap();

        // A row of another kind carrying a deadline: only receipts expire,
        // whatever else a future lane may date its rows with.
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO outbox(kind, dedupe_key, subject, payload, created_at, expires_at)
                 VALUES ('decision', 'request-dated', 'oshioki.verdict.request-dated', x'7b7d', 20, 110)",
                [],
            )
            .unwrap();

        store.expire_stale_deliveries(200).unwrap();
        let pending = store.pending_verdicts(10).unwrap();
        assert!(
            pending
                .iter()
                .all(|item| item.subject != "oshioki.delivery.request-1"),
            "a receipt past its request deadline is not worth delivering"
        );
        assert!(
            pending
                .iter()
                .any(|item| item.subject == "oshioki.verdict.request-dated"),
            "expiry is keyed on the receipt lane, not on carrying a deadline"
        );
        assert_eq!(
            pending
                .iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            // The verdict for the dead request stays: expiry is for receipts
            // only, and a verdict is delivered whenever it can be.
            vec![
                "oshioki.verdict.request-1",
                "oshioki.delivery.request-live",
                "oshioki.verdict.request-dated",
            ],
            "the live receipt must not queue behind the outage backlog"
        );
    }

    #[test]
    fn request_receiver_rejects_stale_future_skew_and_long_lived_envelopes() {
        let store = Store::memory().unwrap();
        let fingerprint = device(b"timing-token").fingerprint;
        let now = 1_000;
        let base = envelope(&fingerprint);

        let mut future = base.clone();
        future.issued_at = now + oshioki_protocol::MAX_REQUEST_ISSUANCE_SKEW_SECS + 1;
        future.expires_at = future.issued_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS;
        let future_raw = serde_json::to_vec(&future).unwrap();
        assert!(store.ingest_request(&future_raw, &future, now).is_err());

        let mut stale = base.clone();
        stale.issued_at = now - oshioki_protocol::MAX_REQUEST_ISSUANCE_SKEW_SECS - 1;
        stale.expires_at = now + 1;
        let stale_raw = serde_json::to_vec(&stale).unwrap();
        assert!(store.ingest_request(&stale_raw, &stale, now).is_err());

        let mut long_lived = base;
        long_lived.issued_at = now;
        long_lived.expires_at = now + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS + 1;
        let long_lived_raw = serde_json::to_vec(&long_lived).unwrap();
        assert!(
            store
                .ingest_request(&long_lived_raw, &long_lived, now)
                .is_err()
        );
    }

    #[test]
    fn cleanup_uses_server_receipt_time_not_message_expiry() {
        let store = Store::memory().unwrap();
        let device = device(b"retention-token");
        store.put_device(&device).unwrap();
        let received_at = 1_000;
        let mut request = envelope(&device.fingerprint);
        request.issued_at = received_at;
        request.expires_at = received_at + oshioki_protocol::MAX_REQUEST_LIFETIME_SECS;
        let raw = serde_json::to_vec(&request).unwrap();
        store.ingest_request(&raw, &request, received_at).unwrap();

        store
            .cleanup(received_at + SERVER_REQUEST_RETENTION_SECS + 1)
            .unwrap();
        assert_eq!(
            store
                .request_lifecycle("request-1", received_at + SERVER_REQUEST_RETENTION_SECS + 1)
                .unwrap(),
            None
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
            signature: None,
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

    /// The retained verdict copy answers hooks confirming relayed denials,
    /// including after delivery: only the request's own record matches.
    #[test]
    fn recorded_verdict_returns_the_queued_decision() {
        let store = Store::memory().unwrap();
        let device = device(b"recorded-token");
        store.put_device(&device).unwrap();
        let envelope = envelope(&device.fingerprint);
        let raw = serde_json::to_vec(&envelope).unwrap();
        store.ingest_request(&raw, &envelope, 20).unwrap();
        let decision = DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: "request-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: None,
        });
        store
            .queue_decision("request-1", &device.fingerprint, &decision, 20)
            .unwrap();
        assert_eq!(
            store.recorded_verdict("request-1").unwrap(),
            Some(serde_json::to_vec(&decision).unwrap())
        );
        assert_eq!(store.recorded_verdict("request-9").unwrap(), None);
        let pending = store.pending_verdicts(10).unwrap();
        let verdict = pending
            .iter()
            .find(|item| item.subject == "oshioki.verdict.request-1")
            .unwrap();
        store.mark_outbox_sent(verdict.id).unwrap();
        assert_eq!(
            store.recorded_verdict("request-1").unwrap(),
            Some(serde_json::to_vec(&decision).unwrap())
        );
    }

    /// Verdicts and notifications drain through separate lanes: a stuck
    /// notification row is invisible to the verdict reader and vice versa,
    /// so a dead ntfy endpoint cannot head-of-line-block an approval.
    #[test]
    fn verdict_and_notification_lanes_are_separate() {
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
            signature: None,
        });
        store
            .queue_decision("request-1", &device.fingerprint, &decision, 20)
            .unwrap();
        store
            .queue_notification("request-1", "https://ntfy.example/x", b"{}")
            .unwrap();
        let verdicts = store.pending_verdicts(10).unwrap();
        assert_eq!(verdicts.len(), 2);
        assert_eq!(
            verdicts
                .iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            ["oshioki.delivery.request-1", "oshioki.verdict.request-1"]
        );
        let notifications = store.pending_notifications(10).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].subject, "https://ntfy.example/x");
        let decision = verdicts
            .iter()
            .find(|item| item.subject == "oshioki.verdict.request-1")
            .unwrap();
        store.mark_outbox_sent(decision.id).unwrap();
        assert_eq!(store.pending_verdicts(10).unwrap().len(), 1);
        assert_eq!(store.pending_notifications(10).unwrap().len(), 1);
    }

    #[test]
    fn restart_replays_unsent_outbox_until_marked() {
        let path = temporary_database();
        let device = device(b"restart-token");
        let decision = DecisionV1::Deny(DenyV1 {
            version: VERSION_V1,
            request_id: "request-1".into(),
            device_fingerprint: device.fingerprint.clone(),
            signature: None,
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
            assert_eq!(store.pending_verdicts(10).unwrap().len(), 2);
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
            let pending = store.pending_verdicts(10).unwrap();
            assert_eq!(pending.len(), 2);
            assert_eq!(pending[0].subject, "oshioki.delivery.request-1");
            assert_eq!(pending[1].subject, "oshioki.verdict.request-1");
            for item in pending {
                store.mark_outbox_sent(item.id).unwrap();
            }
            assert!(store.pending_verdicts(10).unwrap().is_empty());

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
    /// Re-enrolling the same identity with a new label converges the served
    /// record: the enrollment activates and the hook's whole-record match
    /// sees the new label, instead of consuming the enrollment on a stale
    /// record and failing after the activation timeout.
    #[test]
    fn a_relabel_reenrollment_converges_the_served_record() {
        let store = Store::memory().unwrap();
        let (submission, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        store.activate_enrollment("enroll-1", &device, 100).unwrap();
        assert_eq!(
            store
                .active_device(&device.fingerprint)
                .unwrap()
                .unwrap()
                .label,
            "laptop"
        );

        let (resubmission, relabeled) = native_pair("enroll-2", 9, b"token-one", "work laptop");
        assert_eq!(relabeled.fingerprint, device.fingerprint);
        pending_enrollment(&store, "enroll-2", 300);
        submit(&store, "enroll-2", &resubmission, 100);
        store
            .activate_enrollment("enroll-2", &relabeled, 100)
            .unwrap();
        assert_eq!(
            store
                .active_device(&device.fingerprint)
                .unwrap()
                .unwrap()
                .label,
            "work laptop"
        );
    }

    /// The converged record still pins the credential: the same label move
    /// with a different API token fails instead of replacing the token.
    #[test]
    fn a_relabel_with_a_new_token_still_fails() {
        let store = Store::memory().unwrap();
        let (submission, device) = native_pair("enroll-1", 9, b"token-one", "laptop");
        pending_enrollment(&store, "enroll-1", 300);
        submit(&store, "enroll-1", &submission, 100);
        store.activate_enrollment("enroll-1", &device, 100).unwrap();

        let (resubmission, relabeled) = native_pair("enroll-2", 9, b"token-two", "work laptop");
        pending_enrollment(&store, "enroll-2", 300);
        submit(&store, "enroll-2", &resubmission, 100);
        let error = store
            .activate_enrollment("enroll-2", &relabeled, 100)
            .unwrap_err();
        assert!(error.to_string().contains("different record"), "{error:?}");
        assert_eq!(
            store
                .active_device(&device.fingerprint)
                .unwrap()
                .unwrap()
                .label,
            "laptop"
        );
    }

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
