// Included inside db::tests so the migration fixtures share the existing builders.

struct MultiPush {
    store: Store,
    first: DevicePublicRecordV1,
    second: DevicePublicRecordV1,
    key: Vec<u8>,
    auth: Vec<u8>,
    capability: String,
    endpoint: &'static str,
}

impl MultiPush {
    fn new() -> Self {
        let store = Store::memory().unwrap();
        let first = device(b"multi-a");
        let second = alternate_device(b"multi-b");
        store.put_device(&first).unwrap();
        store.put_device(&second).unwrap();
        let (key, auth) = push_material();
        Self {
            store,
            first,
            second,
            key,
            auth,
            capability: encode_base64url(&[42; 32]),
            endpoint: "https://push.example/multi",
        }
    }

    fn register(&self, bearer: &[u8], capability: Option<&str>) -> Result<String> {
        self.store.register_push_membership(
            bearer,
            self.endpoint,
            &self.key,
            &self.auth,
            None,
            capability,
            20,
        )
    }

    fn both(&self) -> (String, String) {
        (
            self.register(b"multi-a", Some(&self.capability)).unwrap(),
            self.register(b"multi-b", Some(&self.capability)).unwrap(),
        )
    }

    fn queue(&self, lane: &str, id: &str, first: bool, second: bool, now: i64) {
        match lane {
            "request" => {
                let mut req = envelope(&self.first.fingerprint);
                req.request_id = id.into();
                req.issued_at = now;
                req.expires_at = now + 90;
                if second {
                    let mut body = req.sealed[0].clone();
                    body.device_fingerprint = self.second.fingerprint.clone();
                    req.sealed.push(body);
                }
                if !first {
                    req.sealed.remove(0);
                }
                let raw = serde_json::to_vec(&req).unwrap();
                self.store.ingest_request(&raw, &req, now).unwrap();
                self.store.ingest_request(&raw, &req, now).unwrap();
            }
            "auth" => {
                let mut req = auth_envelope(&self.first.fingerprint, id, now);
                if second {
                    let mut body = req.sealed[0].clone();
                    body.device_fingerprint = self.second.fingerprint.clone();
                    req.sealed.push(body);
                }
                if !first {
                    req.sealed.remove(0);
                }
                let raw = serde_json::to_vec(&req).unwrap();
                self.store.ingest_auth_request(&raw, &req, now).unwrap();
                self.store.ingest_auth_request(&raw, &req, now).unwrap();
            }
            "tool" => {
                let mut req = tool_envelope(&self.first.fingerprint, id, now);
                if second {
                    let mut body = req.sealed[0].clone();
                    body.device_fingerprint = self.second.fingerprint.clone();
                    req.sealed.push(body);
                }
                if !first {
                    req.sealed.remove(0);
                }
                let raw = serde_json::to_vec(&req).unwrap();
                self.store.ingest_tool_request(&raw, &req, now).unwrap();
                self.store.ingest_tool_request(&raw, &req, now).unwrap();
            }
            _ => unreachable!(),
        }
    }

    fn pending(&self, lane: &str, id: &str) -> bool {
        self.store.lock().unwrap().query_row(
            "SELECT sent_at IS NULL AND abandoned_at IS NULL FROM push_outbox WHERE request_kind=?1 AND request_id=?2",
            params![lane, id], |row| row.get(0),
        ).unwrap()
    }
}

#[test]
fn multi_push_capability_is_hashed_and_memberships_are_stable() {
    let f = MultiPush::new();
    let (a, b) = f.both();
    assert_ne!(a, b);
    assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
    assert_eq!(f.register(b"multi-b", Some(&f.capability)).unwrap(), b);
    assert_eq!(f.register(b"multi-a", None).unwrap(), a);
    let conn = f.store.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM push_endpoints", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let hash: Vec<u8> = conn
        .query_row(
            "SELECT installation_token_hash FROM push_endpoints",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hash, Sha256::digest([42; 32]).to_vec());
    drop(conn);
    assert_eq!(f.store.push_status(b"multi-b").unwrap().count, 1);
}

#[test]
fn multi_push_rejects_missing_wrong_malformed_and_revoked_credentials_without_mutation() {
    let f = MultiPush::new();
    let a = f.register(b"multi-a", Some(&f.capability)).unwrap();
    assert!(f.register(b"multi-b", None).is_err());
    for bearer in [b"multi-a".as_slice(), b"multi-b"] {
        assert!(
            f.register(bearer, Some(&encode_base64url(&[43; 32])))
                .is_err()
        );
    }
    for token in [
        "a".repeat(43),
        "A".repeat(42),
        format!("{}=", "A".repeat(43)),
        "!".repeat(43),
        format!("{}B", "A".repeat(42)),
    ] {
        // The all-lowercase value is canonical and is a wrong capability; all others are malformed.
        assert!(f.register(b"multi-b", Some(&token)).is_err());
    }
    let replacement_auth = vec![11; PUSH_AUTH_BYTES];
    assert!(
        f.store
            .register_push_membership(
                b"multi-a",
                f.endpoint,
                &f.key,
                &replacement_auth,
                None,
                None,
                20
            )
            .is_err()
    );
    assert!(
        !f.store
            .delete_push_subscription(b"multi-b", &a, 20)
            .unwrap()
    );
    assert!(
        f.store
            .delete_push_subscription(b"multi-a", &a, 20)
            .unwrap()
    );
    assert!(f.register(b"multi-a", None).is_err());
    assert!(f.register(b"multi-b", None).is_err());
    assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
    f.store
        .set_device_active(&f.second.fingerprint, false)
        .unwrap();
    assert!(f.register(b"multi-b", Some(&f.capability)).is_err());
    assert!(f.register(b"invalid", Some(&f.capability)).is_err());
    let conn = f.store.lock().unwrap();
    let saved: (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT auth,installation_token_hash FROM push_endpoints",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(saved, (f.auth.clone(), Sha256::digest([42; 32]).to_vec()));
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM push_subscriptions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn multi_push_capability_never_authorizes_request_access() {
    let f = MultiPush::new();
    f.both();
    f.queue("request", "private", false, true, 20);
    assert!(
        f.store
            .sealed_request_for_token("private", f.capability.as_bytes(), 20)
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .sealed_request_for_token("private", b"multi-a", 20)
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .sealed_request_for_token("private", b"multi-b", 20)
            .unwrap()
            .is_some()
    );
}

#[test]
fn multi_push_legacy_owner_claims_and_inactive_or_disabled_owner_can_be_reclaimed() {
    for revoke in [false, true] {
        let f = MultiPush::new();
        let a = f.register(b"multi-a", None).unwrap();
        assert!(f.register(b"multi-b", Some(&f.capability)).is_err());
        assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
        assert_ne!(f.register(b"multi-b", Some(&f.capability)).unwrap(), a);
        let other = MultiPush::new();
        let old = other.register(b"multi-a", None).unwrap();
        if revoke {
            other
                .store
                .set_device_active(&other.first.fingerprint, false)
                .unwrap();
        } else {
            other
                .store
                .delete_push_subscription(b"multi-a", &old, 20)
                .unwrap();
        }
        let new = other.register(b"multi-b", Some(&other.capability)).unwrap();
        assert_ne!(new, old);
        assert!(other.register(b"multi-a", None).is_err());
    }
}

#[test]
fn multi_push_enqueues_once_per_endpoint_and_exact_lane_even_for_shared_recipients() {
    let f = MultiPush::new();
    f.both();
    f.store
        .register_push_membership(
            b"multi-a",
            "https://push.example/another",
            &f.key,
            &f.auth,
            None,
            Some(&encode_base64url(&[12; 32])),
            20,
        )
        .unwrap();
    for lane in ["request", "auth", "tool"] {
        f.queue(lane, "same-id", true, true, 20);
    }
    let mut delivered = std::collections::BTreeMap::new();
    while let Some(item) = f.store.claim_push(20, 30).unwrap() {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&item.payload)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            3
        );
        *delivered.entry(item.request_kind).or_insert(0) += 1;
        f.store
            .mark_push_sent(item.id, &item.claim_token, 20)
            .unwrap();
    }
    assert_eq!(
        delivered,
        [
            ("auth".into(), 2),
            ("request".into(), 2),
            ("tool".into(), 2)
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn multi_push_delete_and_revoke_preserve_only_exact_remaining_recipients_and_clear_claims() {
    for revoke in [false, true] {
        let f = MultiPush::new();
        let (a, b) = f.both();
        let now = unix_now();
        for lane in ["request", "auth", "tool"] {
            f.queue(lane, "a-only", true, false, now);
            f.queue(lane, "b-only", false, true, now);
            f.queue(lane, "shared", true, true, now);
        }
        // Claim A's first request to exercise late worker ownership after abandonment.
        let claimed = f.store.claim_push(now, 30).unwrap().unwrap();
        assert_eq!(claimed.request_id, "a-only");
        if revoke {
            f.store
                .set_device_active(&f.first.fingerprint, false)
                .unwrap();
        } else {
            assert!(
                f.store
                    .delete_push_subscription(b"multi-a", &a, now)
                    .unwrap()
            );
        }
        assert!(
            !f.store
                .mark_push_sent(claimed.id, &claimed.claim_token, now)
                .unwrap()
        );
        assert!(
            !f.store
                .retry_push(claimed.id, &claimed.claim_token, now, "late")
                .unwrap()
        );
        assert!(
            !f.store
                .disable_push_for_claim(
                    claimed.id,
                    &claimed.endpoint_id,
                    &claimed.claim_token,
                    now,
                    "gone"
                )
                .unwrap()
        );
        assert_eq!(f.store.push_status(b"multi-b").unwrap().count, 1);
        assert!(
            !f.store
                .delete_push_subscription(b"multi-b", &a, now)
                .unwrap()
        );
        for lane in ["request", "auth", "tool"] {
            assert!(!f.pending(lane, "a-only"));
            assert!(f.pending(lane, "b-only"));
            assert!(f.pending(lane, "shared"));
        }
        assert_eq!(f.register(b"multi-b", Some(&f.capability)).unwrap(), b);
        // Rejoining must never revive A-only abandoned work.
        if !revoke {
            assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
            assert!(!f.pending("request", "a-only"));
        }
    }
}

#[test]
fn multi_push_provider_gone_disables_physical_endpoint_and_terminal_rejection_only_one_row() {
    let f = MultiPush::new();
    f.both();
    let other = f
        .store
        .register_push_membership(
            b"multi-a",
            "https://push.example/other",
            &f.key,
            &f.auth,
            None,
            Some(&f.capability),
            20,
        )
        .unwrap();
    f.queue("request", "one", true, true, 20);
    f.queue("auth", "two", true, true, 20);
    let one = f.store.claim_push(20, 30).unwrap().unwrap();
    assert!(
        f.store
            .abandon_push(one.id, &one.claim_token, 20, "provider_rejected")
            .unwrap()
    );
    assert_eq!(f.store.push_status(b"multi-b").unwrap().count, 1);
    let two = f.store.claim_push(20, 30).unwrap().unwrap();
    assert!(
        f.store
            .disable_push_for_claim(
                two.id,
                &two.endpoint_id,
                &two.claim_token,
                20,
                "endpoint_gone"
            )
            .unwrap()
    );
    assert!(
        !f.store
            .mark_push_sent(two.id, &two.claim_token, 20)
            .unwrap()
    );
    let conn = f.store.lock().unwrap();
    assert_eq!(conn.query_row("SELECT COUNT(*) FROM push_outbox WHERE endpoint_id=?1 AND sent_at IS NULL AND abandoned_at IS NULL",[&two.endpoint_id],|r|r.get::<_,i64>(0)).unwrap(),0);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM devices WHERE active=1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    drop(conn);
    let other_endpoint = endpoint_for(&f.store, &other);
    // Depending on ID order, the gone row may belong to either endpoint; exactly one remains usable.
    assert_eq!(
        f.store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM push_endpoints WHERE disabled_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert!(!other_endpoint.is_empty());
}

#[test]
fn multi_push_cleanup_retains_protection_and_membership_ids_past_retention() {
    for mode in ["delete", "revoke", "gone"] {
        let f = MultiPush::new();
        let (a, b) = f.both();
        if mode == "gone" {
            f.queue("request", "gone", true, true, 20);
            let item = f.store.claim_push(20, 30).unwrap().unwrap();
            f.store
                .disable_push_for_claim(
                    item.id,
                    &item.endpoint_id,
                    &item.claim_token,
                    20,
                    "endpoint_gone",
                )
                .unwrap();
        }
        if mode == "revoke" {
            f.store
                .set_device_active(&f.first.fingerprint, false)
                .unwrap();
            f.store
                .set_device_active(&f.second.fingerprint, false)
                .unwrap();
        } else {
            f.store
                .delete_push_subscription(b"multi-a", &a, 20)
                .unwrap();
            f.store
                .delete_push_subscription(b"multi-b", &b, 20)
                .unwrap();
        }
        f.store
            .cleanup(unix_now() + PUSH_DISABLED_RETENTION_SECS + 1)
            .unwrap();
        if mode == "revoke" {
            f.store.put_device(&f.first).unwrap();
            f.store.put_device(&f.second).unwrap();
        }
        assert!(f.register(b"multi-a", None).is_err());
        assert!(
            f.register(b"multi-b", Some(&encode_base64url(&[99; 32])))
                .is_err()
        );
        assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
        assert_eq!(f.register(b"multi-b", Some(&f.capability)).unwrap(), b);
    }
}

#[test]
fn multi_push_concurrent_first_claim_serializes_and_loser_cannot_replace_hash() {
    let path = temporary_database();
    let store = Store::open(&path).unwrap();
    store.put_device(&device(b"multi-a")).unwrap();
    store.put_device(&alternate_device(b"multi-b")).unwrap();
    drop(store);
    for legacy in [false, true] {
        let endpoint = if legacy {
            "https://push.example/race-legacy"
        } else {
            "https://push.example/race-new"
        };
        if legacy {
            let s = Store::open(&path).unwrap();
            let (k, a) = push_material();
            s.register_push_subscription(b"multi-a", endpoint, &k, &a, None, 20)
                .unwrap();
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = [42, 43].map(|value| {
            let barrier = barrier.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                let s = Store::open(&path).unwrap();
                let (k, a) = push_material();
                barrier.wait();
                s.register_push_membership(
                    b"multi-a",
                    endpoint,
                    &k,
                    &a,
                    None,
                    Some(&encode_base64url(&[value; 32])),
                    20,
                )
            })
        });
        barrier.wait();
        let results = workers.map(|w| w.join().unwrap());
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
    }
    remove_database(&path);
}

fn v4_push_fixture() -> (PathBuf, DevicePublicRecordV1, Vec<u8>, Vec<u8>) {
    let path = temporary_database();
    let first = device(b"multi-a");
    let (k, a) = push_material();
    {
        let old = Connection::open(&path).unwrap();
        old.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4] {
            old.execute_batch(migration).unwrap();
        }
        insert_device_on(&old, &first);
        old.execute("INSERT INTO push_subscriptions(id,device_fingerprint,endpoint,p256dh,auth,expiration_at,created_at,updated_at,last_error) VALUES ('ps_legacy',?1,'https://push.example/legacy',?2,?3,1000,20,21,'previous')",params![first.fingerprint,k,a]).unwrap();
        let req = envelope(&first.fingerprint);
        old.execute("INSERT INTO requests(id,envelope_hash,envelope_json,host,user,issued_at,expires_at,state,created_at) VALUES ('request-1',x'01',?1,'host','user',20,110,'pending',20)",[serde_json::to_vec(&req).unwrap()]).unwrap();
        old.execute("INSERT INTO sealed_bodies(request_id,fingerprint,body_json) VALUES ('request-1',?1,?2)",params![first.fingerprint,serde_json::to_vec(&req.sealed[0]).unwrap()]).unwrap();
        for (id, sent, abandoned, claim) in [
            (1, None, None, Some("old-claim")),
            (2, Some(22), None, None),
            (3, None, Some(23), None),
        ] {
            old.execute("INSERT INTO push_outbox(id,request_kind,request_id,subscription_id,payload,created_at,available_at,attempts,sent_at,abandoned_at,claim_token,claimed_until,last_error) VALUES (?1,'request',?2,'ps_legacy',x'7b7d',20,24,2,?3,?4,?5,25,'retry')",params![id,format!("request-{id}"),sent,abandoned,claim]).unwrap();
        }
    }
    (path, first, k, a)
}

fn verify_v4_push_snapshot(snapshot: &Path, first: &DevicePublicRecordV1, k: &[u8], a: &[u8]) {
    let old = Connection::open(snapshot).unwrap();
    assert_eq!(
        old.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        old.query_row(
            "SELECT endpoint FROM push_subscriptions WHERE id='ps_legacy'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "https://push.example/legacy"
    );
    let material: (Vec<u8>, Vec<u8>, String) = old
        .query_row(
            "SELECT p256dh,auth,device_fingerprint FROM push_subscriptions WHERE id='ps_legacy'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        material,
        (k.to_vec(), a.to_vec(), first.fingerprint.clone())
    );
    assert!(
        old.query_row(
            "SELECT active FROM devices WHERE fingerprint=?1",
            [&first.fingerprint],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    assert_eq!(old.query_row("SELECT COUNT(*) FROM requests r JOIN sealed_bodies b ON r.id=b.request_id JOIN push_outbox o ON o.request_id=r.id WHERE r.state='pending' AND o.subscription_id='ps_legacy' AND o.sent_at IS NULL AND o.abandoned_at IS NULL",[],|r|r.get::<_,i64>(0)).unwrap(),1);
}

#[test]
fn multi_push_v4_upgrade_preserves_restore_snapshot_and_all_delivery_state() {
    let (path, first, k, a) = v4_push_fixture();
    let store = Store::open(&path).unwrap();
    store.ready().unwrap();
    let snapshot = restore_snapshot_path(&path, 4);
    verify_restore_snapshot(&snapshot, 4).unwrap();
    verify_v4_push_snapshot(&snapshot, &first, &k, &a);
    {
        let c = store.lock().unwrap();
        let migrated: (String, Vec<u8>, Vec<u8>, i64, String, String) = c.query_row(
            "SELECT s.id,e.p256dh,e.auth,e.expiration_at,e.last_error,s.device_fingerprint FROM push_endpoints e JOIN push_subscriptions s ON s.endpoint_id=e.id",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).unwrap();
        assert_eq!(
            migrated,
            (
                "ps_legacy".into(),
                k.clone(),
                a.clone(),
                1000,
                "previous".into(),
                first.fingerprint.clone()
            )
        );
        assert_eq!(
            c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert!(
            c.query_row(
                "SELECT installation_token_hash IS NULL FROM push_endpoints",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
        );
        assert_eq!(c.query_row("SELECT COUNT(*) FROM push_outbox WHERE attempts=2 AND payload=x'7b7d' AND created_at=20 AND available_at=24 AND claimed_until=25 AND last_error='retry'",[],|r|r.get::<_,i64>(0)).unwrap(),3);
        assert_eq!(
            c.query_row("SELECT claim_token FROM push_outbox WHERE id=1", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "old-claim"
        );
        assert_eq!(
            c.query_row("SELECT sent_at FROM push_outbox WHERE id=2", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            22
        );
        assert_eq!(
            c.query_row("SELECT abandoned_at FROM push_outbox WHERE id=3", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            23
        );
    }
    assert_eq!(
        store
            .register_push_membership(
                b"multi-a",
                "https://push.example/legacy",
                &k,
                &a,
                Some(1000),
                Some(&encode_base64url(&[42; 32])),
                20
            )
            .unwrap(),
        "ps_legacy"
    );
    drop(store);
    let reopened = Store::open(&path).unwrap();
    reopened.ready().unwrap();
    let item = reopened.claim_push(26, 30).unwrap().unwrap();
    assert_eq!(item.request_id, "request-1");
    reopened
        .mark_push_sent(item.id, &item.claim_token, 26)
        .unwrap();
    assert!(reopened.claim_push(26, 30).unwrap().is_none());
    drop(reopened);
    let reopened = Store::open(&path).unwrap();
    assert!(reopened.claim_push(26, 30).unwrap().is_none());
    drop(reopened);
    remove_database(&path);
}

#[test]
fn multi_push_v5_failure_is_atomic_and_v3_open_advances_to_v5() {
    let path = temporary_database();
    {
        let c = Connection::open(&path).unwrap();
        for migration in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4] {
            c.execute_batch(migration).unwrap();
        }
        // A pre-existing incompatible object causes failure after the new endpoint DDL ran.
        c.execute("CREATE TABLE push_subscriptions_v4(sentinel TEXT)", [])
            .unwrap();
    }
    assert!(Store::open(&path).is_err());
    {
        let c = Connection::open(&path).unwrap();
        assert_eq!(
            c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            4
        );
        assert_eq!(
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='push_endpoints'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(c.query_row("SELECT COUNT(*) FROM pragma_table_info('push_outbox') WHERE name='subscription_id'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert_eq!(
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='push_outbox_v4'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    verify_restore_snapshot(&restore_snapshot_path(&path, 4), 4).unwrap();
    remove_database(&path);
    let path = temporary_database();
    {
        let c = Connection::open(&path).unwrap();
        for m in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3] {
            c.execute_batch(m).unwrap();
        }
    }
    Store::open(&path).unwrap().ready().unwrap();
    verify_restore_snapshot(&restore_snapshot_path(&path, 3), 3).unwrap();
    remove_database(&path);
}

#[test]
fn multi_push_same_id_in_another_lane_does_not_preserve_unreadable_request() {
    let f = MultiPush::new();
    let (a, _) = f.both();
    f.queue("request", "cross-lane", true, false, 20);
    f.queue("auth", "cross-lane", false, true, 20);
    f.queue("tool", "cross-lane", false, true, 20);
    f.store
        .delete_push_subscription(b"multi-a", &a, 20)
        .unwrap();
    assert!(!f.pending("request", "cross-lane"));
    assert!(f.pending("auth", "cross-lane"));
    assert!(f.pending("tool", "cross-lane"));
}

#[test]
fn multi_push_provider_disabled_legacy_endpoint_retains_old_reclaim_contract() {
    let f = MultiPush::new();
    let a = f.register(b"multi-a", None).unwrap();
    f.queue("request", "gone-legacy", true, false, 20);
    let item = f.store.claim_push(20, 30).unwrap().unwrap();
    f.store
        .disable_push_for_claim(
            item.id,
            &item.endpoint_id,
            &item.claim_token,
            20,
            "endpoint_gone",
        )
        .unwrap();
    let b = f.register(b"multi-b", Some(&f.capability)).unwrap();
    assert_ne!(a, b);
    assert!(f.register(b"multi-a", None).is_err());
}

#[test]
fn multi_push_status_requires_usable_endpoint_and_capability_to_reactivate_gone_transport() {
    let f = MultiPush::new();
    let (a, b) = f.both();
    f.store
        .lock()
        .unwrap()
        .execute(
            "UPDATE push_endpoints SET expiration_at=?1",
            [unix_now() - 1],
        )
        .unwrap();
    assert_eq!(f.store.push_status(b"multi-a").unwrap().count, 0);
    assert_eq!(f.register(b"multi-a", Some(&f.capability)).unwrap(), a);
    f.queue("request", "gone-status", true, true, 20);
    let item = f.store.claim_push(20, 30).unwrap().unwrap();
    f.store
        .disable_push_for_claim(
            item.id,
            &item.endpoint_id,
            &item.claim_token,
            20,
            "endpoint_gone",
        )
        .unwrap();
    assert_eq!(f.store.push_status(b"multi-b").unwrap().count, 0);
    assert!(f.register(b"multi-b", None).is_err());
    assert_eq!(f.register(b"multi-b", Some(&f.capability)).unwrap(), b);
    assert_eq!(f.store.push_status(b"multi-a").unwrap().count, 1);
}

#[test]
fn multi_push_v4_auth_receipt_namespace_preserves_redelivery_and_accepts_same_id_command() {
    let path = temporary_database();
    let first = device(b"multi-a");
    let auth = auth_envelope(&first.fingerprint, "shared-upgrade-id", 20);
    let auth_raw = serde_json::to_vec(&auth).unwrap();
    {
        let c = Connection::open(&path).unwrap();
        for migration in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4] {
            c.execute_batch(migration).unwrap();
        }
        insert_device_on(&c, &first);
        c.execute("INSERT INTO auth_requests(id,envelope_hash,envelope_json,host,issued_at,expires_at,state,created_at) VALUES (?1,?2,?3,'nas',19,80,'pending',20)",params![auth.request_id,Sha256::digest(&auth_raw).to_vec(),auth_raw]).unwrap();
        c.execute(
            "INSERT INTO auth_sealed_bodies(request_id,fingerprint,body_json) VALUES (?1,?2,?3)",
            params![
                auth.request_id,
                first.fingerprint,
                serde_json::to_vec(&auth.sealed[0]).unwrap()
            ],
        )
        .unwrap();
        let payload = serde_json::to_vec(&DeliveryV1::for_request(&auth.request_id)).unwrap();
        c.execute("INSERT INTO outbox(kind,dedupe_key,subject,payload,created_at,sent_at,attempts,expires_at) VALUES ('delivery',?1,?2,?3,20,21,2,80)",params![auth.request_id,format!("oshioki.delivery.{}",auth.request_id),payload]).unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(
        store.ingest_auth_request(&auth_raw, &auth, 20).unwrap(),
        InsertResult::Identical
    );
    let mut command = envelope(&first.fingerprint);
    command.request_id = auth.request_id.clone();
    let command_raw = serde_json::to_vec(&command).unwrap();
    assert_eq!(
        store.ingest_request(&command_raw, &command, 20).unwrap(),
        InsertResult::Inserted
    );
    assert_eq!(
        store.ingest_request(&command_raw, &command, 20).unwrap(),
        InsertResult::Identical
    );
    {
        let c = store.lock().unwrap();
        let receipt:(i64,i64,String,Vec<u8>)=c.query_row("SELECT sent_at,attempts,subject,payload FROM outbox WHERE kind='delivery' AND dedupe_key='auth:shared-upgrade-id'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(
            receipt,
            (
                21,
                2,
                "oshioki.delivery.shared-upgrade-id".into(),
                serde_json::to_vec(&DeliveryV1::for_request(&auth.request_id)).unwrap()
            )
        );
        assert_eq!(
            c.query_row(
                "SELECT COUNT(*) FROM outbox WHERE kind='delivery'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            c.query_row(
                "SELECT COUNT(*) FROM outbox WHERE kind='delivery' AND sent_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
    drop(store);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened.ingest_auth_request(&auth_raw, &auth, 20).unwrap(),
        InsertResult::Identical
    );
    assert_eq!(reopened.pending_verdicts(10).unwrap().len(), 1);
    drop(reopened);
    verify_restore_snapshot(&restore_snapshot_path(&path, 4), 4).unwrap();
    remove_database(&path);
}
