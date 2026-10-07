// Fixed synthetic keys only; all sequencing drives production transaction/gate
// and lifecycle helpers. These tests never construct a network transport.
fn revocation_directory(name: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt as _;
    let root = std::env::var_os("OSHIOKI_REVOCATION_TEST_STATE")
        .map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = root.join(format!("{name}-{}", Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    seed_hook_config(&dir);
    dir
}

fn revocation_command_decision(
    signing: &SigningKey,
    device: &DevicePublicRecordV1,
    request: &RequestV1,
    raw: &[u8],
    counter: u32,
) -> DecisionV1 {
    let client = serde_json::to_vec(&serde_json::json!({"type":"webauthn.get",
        "challenge":URL_SAFE_NO_PAD.encode(oshioki_protocol::approve_challenge(raw)),
        "origin":TEST_ORIGIN,"crossOrigin":false}))
    .unwrap();
    let mut data = Sha256::digest(TEST_RP_ID.as_bytes()).to_vec();
    data.push(5);
    data.extend_from_slice(&counter.to_be_bytes());
    let mut signed = data.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let signature: p256::ecdsa::Signature = signing.sign(&signed);
    DecisionV1::Approve(oshioki_protocol::ApproveV1 {
        version: VERSION_V1,
        request_id: request.request_id.clone(),
        device_fingerprint: device.fingerprint.clone(),
        credential_id: device.credential_id.clone(),
        authenticator_data: URL_SAFE_NO_PAD.encode(data),
        client_data_json: URL_SAFE_NO_PAD.encode(client),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
    })
}
fn revocation_native_command(
    signing: &SigningKey,
    device: &DevicePublicRecordV1,
    request: &RequestV1,
    raw: &[u8],
) -> DecisionV1 {
    let signature: p256::ecdsa::Signature = signing.sign(&oshioki_protocol::approve_challenge(raw));
    DecisionV1::ApproveNative(oshioki_protocol::ApproveNativeV1 {
        version: VERSION_V1,
        request_id: request.request_id.clone(),
        device_fingerprint: device.fingerprint.clone(),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
    })
}
async fn revocation_success(directory: &Path, fingerprint: &str) {
    revoke_with(
        directory,
        fingerprint,
        || async { Ok(()) },
        registry::persist,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn revocation_stale_command_and_auth_cannot_restore_or_accept_positive_or_zero() {
    for counter in [0, 17] {
        let dir = revocation_directory("stale-webauthn");
        let (device, key) = webauthn_test_device();
        seed_registry(&dir, vec![device.clone()]);
        let snapshot = registry::snapshot(&dir).unwrap();
        let command = build_synthetic_request();
        let command_raw = command.raw_json().unwrap();
        let auth = auth_request();
        let auth_raw = auth.raw_json().unwrap();
        let error = revoke_with(
            &dir,
            &device.fingerprint,
            || async { bail!("synthetic connect/revoke failure") },
            registry::persist,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("local device disabled; remote revoke pending")
        );
        for phase in ["inactive", "removed"] {
            if phase == "removed" {
                revocation_success(&dir, &device.fingerprint).await;
            }
            let error = apply_decision(
                revocation_command_decision(&key, &device, &command, &command_raw, counter),
                &command,
                &command_raw,
                &snapshot.registry.devices,
                snapshot.revocation_epoch,
                &dir,
            )
            .await
            .unwrap_err();
            assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
            let decision = webauthn_decision(&key, &device, &auth.request_id, &auth_raw, counter);
            let error = apply_auth_decision(
                &decision,
                &auth,
                &auth_raw,
                &snapshot.registry.devices,
                snapshot.revocation_epoch,
                &dir,
            )
            .unwrap_err();
            assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
            let current = registry::snapshot(&dir).unwrap();
            assert_eq!(current.revocation_epoch, 1);
            assert!(current.registry.devices.iter().all(|d| !d.active));
            assert_eq!(
                current.registry.devices.len(),
                usize::from(phase == "inactive")
            );
        }
    }
}

#[tokio::test]
async fn revocation_stale_native_both_command_kinds_and_auth_fail_without_write() {
    for kind in [DeviceKindV1::Software, DeviceKindV1::SecureEnclave] {
        let dir = revocation_directory("stale-native");
        let (mut device, key) = auth_test_device();
        device.kind = kind;
        seed_registry(&dir, vec![device.clone()]);
        let snapshot = registry::snapshot(&dir).unwrap();
        let command = build_synthetic_request();
        let raw = command.raw_json().unwrap();
        let auth = auth_request();
        let auth_raw = auth.raw_json().unwrap();
        let error = revoke_with(
            &dir,
            &device.fingerprint,
            || async { bail!("remote unavailable") },
            registry::persist,
        )
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<RevokeFailure>().is_some());
        for removed in [false, true] {
            if removed {
                revocation_success(&dir, &device.fingerprint).await;
            }
            assert!(
                apply_decision(
                    revocation_native_command(&key, &device, &command, &raw),
                    &command,
                    &raw,
                    &snapshot.registry.devices,
                    snapshot.revocation_epoch,
                    &dir
                )
                .await
                .is_err()
            );
            if kind == DeviceKindV1::SecureEnclave {
                let decision = native_decision(&key, &device, &auth.request_id, &auth_raw);
                let error = apply_auth_decision(
                    &decision,
                    &auth,
                    &auth_raw,
                    &snapshot.registry.devices,
                    snapshot.revocation_epoch,
                    &dir,
                )
                .unwrap_err();
                assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
            }
            assert!(
                registry::snapshot(&dir)
                    .unwrap()
                    .registry
                    .devices
                    .iter()
                    .all(|d| !d.active)
            );
        }
    }
}

#[tokio::test]
async fn revocation_epoch_blocks_identical_record_aba_and_fresh_requests_work() {
    let dir = revocation_directory("aba");
    let (device, key) = webauthn_test_device();
    seed_registry(&dir, vec![device.clone()]);
    let old = registry::snapshot(&dir).unwrap();
    let command = build_synthetic_request();
    let raw = command.raw_json().unwrap();
    let auth = auth_request();
    let auth_raw = auth.raw_json().unwrap();
    // A passed gate before revoke is allowed ordering, not cancellable execution.
    apply_decision(
        revocation_command_decision(&key, &device, &command, &raw, 0),
        &command,
        &raw,
        &old.registry.devices,
        old.revocation_epoch,
        &dir,
    )
    .await
    .unwrap();
    revocation_success(&dir, &device.fingerprint).await;
    let mut input = io::Cursor::new(format!("{}\n", device.fingerprint));
    pin_device_record(&dir, &device, &mut input).unwrap();
    assert_eq!(registry::snapshot(&dir).unwrap().revocation_epoch, 1);
    assert!(
        apply_decision(
            revocation_command_decision(&key, &device, &command, &raw, 17),
            &command,
            &raw,
            &old.registry.devices,
            old.revocation_epoch,
            &dir
        )
        .await
        .is_err()
    );
    assert!(
        apply_auth_decision(
            &webauthn_decision(&key, &device, &auth.request_id, &auth_raw, 17),
            &auth,
            &auth_raw,
            &old.registry.devices,
            old.revocation_epoch,
            &dir
        )
        .is_err()
    );
    let fresh = registry::snapshot(&dir).unwrap();
    let next = build_synthetic_request();
    let next_raw = next.raw_json().unwrap();
    apply_decision(
        revocation_command_decision(&key, &device, &next, &next_raw, 18),
        &next,
        &next_raw,
        &fresh.registry.devices,
        fresh.revocation_epoch,
        &dir,
    )
    .await
    .unwrap();
    let next = auth_request();
    let next_raw = next.raw_json().unwrap();
    apply_auth_decision(
        &webauthn_decision(&key, &device, &next.request_id, &next_raw, 19),
        &next,
        &next_raw,
        &fresh.registry.devices,
        fresh.revocation_epoch,
        &dir,
    )
    .unwrap();
    assert_eq!(
        registry::snapshot(&dir).unwrap().registry.devices[0].sign_count,
        19
    );
}

#[tokio::test]
async fn revocation_counters_merge_current_rows_and_pin_enroll_preserve_high_water() {
    let dir = revocation_directory("counter-merge");
    let (device, key) = webauthn_test_device();
    let (other, _) = auth_test_device();
    seed_registry(&dir, vec![device.clone()]);
    let snapshot = registry::snapshot(&dir).unwrap();
    // Production enrollment inserts an unrelated row while old requests wait.
    enroll_device_with(&dir, &other, || async { Ok(()) })
        .await
        .unwrap();
    let command = build_synthetic_request();
    let raw = command.raw_json().unwrap();
    for counter in [40, 9, 0] {
        apply_decision(
            revocation_command_decision(&key, &device, &command, &raw, counter),
            &command,
            &raw,
            &snapshot.registry.devices,
            snapshot.revocation_epoch,
            &dir,
        )
        .await
        .unwrap();
    }
    let auth = auth_request();
    let raw = auth.raw_json().unwrap();
    for counter in [60, 19, 0] {
        apply_auth_decision(
            &webauthn_decision(&key, &device, &auth.request_id, &raw, counter),
            &auth,
            &raw,
            &snapshot.registry.devices,
            snapshot.revocation_epoch,
            &dir,
        )
        .unwrap();
    }
    let mut refreshed = device.clone();
    refreshed.sign_count = 3;
    refreshed.label = "new label".into();
    let mut input = io::Cursor::new(format!("{}\n", device.fingerprint));
    pin_device_record(&dir, &refreshed, &mut input).unwrap();
    enroll_device_with(&dir, &device, || async { Ok(()) })
        .await
        .unwrap();
    let state = registry::snapshot(&dir).unwrap();
    assert_eq!(state.registry.devices.len(), 2);
    assert_eq!(state.revocation_epoch, 0);
    assert!(state.registry.devices.contains(&other));
    assert_eq!(
        state
            .registry
            .devices
            .iter()
            .find(|d| d.fingerprint == device.fingerprint)
            .unwrap()
            .sign_count,
        60
    );
    // Rotating routing/token metadata cannot reset the same authenticator.
    let mut rotated = device.clone();
    rotated.api_token_hash = URL_SAFE_NO_PAD.encode([77; 32]);
    enroll_device_with(&dir, &rotated, || async { Ok(()) })
        .await
        .unwrap();
    assert_eq!(
        registry::snapshot(&dir)
            .unwrap()
            .registry
            .devices
            .iter()
            .find(|d| d.fingerprint == device.fingerprint)
            .unwrap()
            .sign_count,
        60
    );
    // Revoking the other row deliberately invalidates this device's old epoch too.
    revocation_success(&dir, &other.fingerprint).await;
    let command = build_synthetic_request();
    let raw = command.raw_json().unwrap();
    assert!(
        apply_decision(
            revocation_command_decision(&key, &device, &command, &raw, 70),
            &command,
            &raw,
            &snapshot.registry.devices,
            snapshot.revocation_epoch,
            &dir
        )
        .await
        .is_err()
    );
    let state = registry::snapshot(&dir).unwrap();
    assert_eq!(state.registry.devices.len(), 1);
    assert_eq!(state.registry.devices[0].sign_count, 60);
}

#[tokio::test]
async fn revocation_exact_identity_gate_rejects_token_kind_and_key_changes_but_allows_label_count()
{
    let dir = revocation_directory("identity");
    let (device, key) = auth_test_device();
    seed_registry(&dir, vec![device.clone()]);
    let snapshot = registry::snapshot(&dir).unwrap();
    let command = build_synthetic_request();
    let raw = command.raw_json().unwrap();
    let auth = auth_request();
    let auth_raw = auth.raw_json().unwrap();
    for field in ["token", "kind", "public", "box", "credential"] {
        let mut changed = device.clone();
        match field {
            "token" => changed.api_token_hash = URL_SAFE_NO_PAD.encode([88; 32]),
            "kind" => changed.kind = DeviceKindV1::Software,
            // These synthetically changed, individually valid records retain the
            // fingerprint; gate equality must not use fingerprint alone.
            "public" => {}
            "box" => changed.box_public_key = URL_SAFE_NO_PAD.encode([89; 32]),
            "credential" => changed.credential_id = URL_SAFE_NO_PAD.encode([90; 32]),
            _ => unreachable!(),
        }
        if field == "public" {
            let other = SigningKey::from_bytes((&[88; 32]).into()).unwrap();
            changed.credential_public_key =
                URL_SAFE_NO_PAD.encode(other.verifying_key().to_encoded_point(false).as_bytes());
        }
        // Keep each replacement internally valid: key/credential/box changes
        // change fingerprint too; token/kind replacements retain fingerprint.
        if field == "public" {
            let public =
                oshioki_protocol::decode_base64url(&changed.credential_public_key).unwrap();
            changed.credential_id =
                URL_SAFE_NO_PAD.encode(oshioki_protocol::native_credential_id(&public));
        }
        if field == "credential" {
            changed.kind = DeviceKindV1::Webauthn;
            changed.credential_public_key = webauthn_test_device().0.credential_public_key;
        }
        changed.fingerprint = oshioki_protocol::device_fingerprint(
            &oshioki_protocol::decode_base64url(&changed.credential_id).unwrap(),
            &oshioki_protocol::decode_base64url(&changed.credential_public_key).unwrap(),
            &oshioki_protocol::decode_base64url(&changed.box_public_key).unwrap(),
        );
        changed.validate().unwrap();
        seed_registry(&dir, vec![changed]);
        let error = apply_decision(
            revocation_native_command(&key, &device, &command, &raw),
            &command,
            &raw,
            &snapshot.registry.devices,
            snapshot.revocation_epoch,
            &dir,
        )
        .await
        .unwrap_err();
        assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
        let error = apply_auth_decision(
            &native_decision(&key, &device, &auth.request_id, &auth_raw),
            &auth,
            &auth_raw,
            &snapshot.registry.devices,
            snapshot.revocation_epoch,
            &dir,
        )
        .unwrap_err();
        assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
    }
    let mut metadata = device.clone();
    metadata.label = "renamed".into();
    metadata.sign_count = 0;
    seed_registry(&dir, vec![metadata]);
    apply_decision(
        revocation_native_command(&key, &device, &command, &raw),
        &command,
        &raw,
        &snapshot.registry.devices,
        0,
        &dir,
    )
    .await
    .unwrap();
    apply_auth_decision(
        &native_decision(&key, &device, &auth.request_id, &auth_raw),
        &auth,
        &auth_raw,
        &snapshot.registry.devices,
        0,
        &dir,
    )
    .unwrap();
}

#[test]
fn revocation_final_expiry_host_fault_and_counter_write_policy() {
    let dir = revocation_directory("gate-policy");
    let (device, _) = webauthn_test_device();
    seed_registry(&dir, vec![device.clone()]);
    assert!(matches!(
        registry::authorize_with(
            &dir,
            &device,
            0,
            100,
            Some(17),
            false,
            || 100,
            |_, _| panic!("expired decision must not write")
        ),
        Err(registry::GateError::Denied(_))
    ));
    for warning_only in [true, false] {
        let result = registry::authorize_with(
            &dir,
            &device,
            0,
            now() + 60,
            Some(17),
            warning_only,
            now,
            |_, _| bail!("synthetic counter write error"),
        );
        if warning_only {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(registry::GateError::Host(_))));
        }
        assert_eq!(
            registry::snapshot(&dir).unwrap().registry.devices[0].sign_count,
            0
        );
    }
    // A real signature followed by mandatory read/lock faults never approves.
    let (native, key) = auth_test_device();
    seed_registry(&dir, vec![native.clone()]);
    let auth = auth_request();
    let raw = auth.raw_json().unwrap();
    let decision = native_decision(&key, &native, &auth.request_id, &raw);
    {
        let _held = registry::Transaction::acquire(&dir).unwrap();
        let error = apply_auth_decision(
            &decision,
            &auth,
            &raw,
            std::slice::from_ref(&native),
            0,
            &dir,
        )
        .unwrap_err();
        assert_eq!(check_error_exit_code(&error), CHECK_RC_UNAVAILABLE);
    }
    for bytes in [
        b"broken json".as_slice(),
        b"{\"version\":99,\"devices\":[]}".as_slice(),
    ] {
        fs::write(dir.join("devices.json"), bytes).unwrap();
        let error = apply_auth_decision(
            &decision,
            &auth,
            &raw,
            std::slice::from_ref(&native),
            0,
            &dir,
        )
        .unwrap_err();
        assert_eq!(check_error_exit_code(&error), CHECK_RC_UNAVAILABLE);
    }
    seed_registry(&dir, vec![]);
    let error = apply_auth_decision(
        &decision,
        &auth,
        &raw,
        std::slice::from_ref(&native),
        0,
        &dir,
    )
    .unwrap_err();
    assert_eq!(check_error_exit_code(&error), CHECK_RC_DENIED);
}

#[tokio::test]
async fn revocation_remote_failure_pending_refuses_pin_and_enroll_restart_retry_finishes() {
    for failure in ["connect", "revoke"] {
        let dir = revocation_directory(failure);
        let (device, _) = auth_test_device();
        seed_registry(&dir, vec![device.clone()]);
        let error = revoke_with(
            &dir,
            &device.fingerprint,
            || async {
                let state = registry::snapshot(&dir).unwrap();
                assert_eq!(state.revocation_epoch, 1);
                assert!(!state.registry.devices[0].active);
                bail!("synthetic {failure} failure")
            },
            registry::persist,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("local device disabled; remote revoke pending")
        );
        let mut input = io::Cursor::new(format!("{}\n", device.fingerprint));
        assert!(
            pin_device_record(&dir, &device, &mut input)
                .unwrap_err()
                .to_string()
                .contains("revocation is pending")
        );
        assert!(
            enroll_device_with(&dir, &device, || async {
                panic!("pending must not activate")
            })
            .await
            .is_err()
        );
        // No in-memory state retained: fresh production retry reads tombstone.
        revocation_success(&dir, &device.fingerprint).await;
        let state = registry::snapshot(&dir).unwrap();
        assert!(state.registry.devices.is_empty());
        assert_eq!(state.revocation_epoch, 1);
        revocation_success(&dir, &device.fingerprint).await; // absent recovery idempotent
        assert_eq!(registry::snapshot(&dir).unwrap().revocation_epoch, 1);
    }
}

#[tokio::test]
async fn revocation_real_atomic_failures_before_and_after_rename_report_and_retry_safely() {
    for failed_call in [1, 2] {
        for failed_stage in [
            AtomicWriteStage::BeforeRename,
            AtomicWriteStage::AfterRename,
        ] {
            let dir = revocation_directory("atomic-failure");
            let (device, _) = auth_test_device();
            seed_registry(&dir, vec![device.clone()]);
            let mut calls = 0;
            let remote_called = std::cell::Cell::new(false);
            let error = revoke_with(
                &dir,
                &device.fingerprint,
                || async {
                    remote_called.set(true);
                    assert!(!registry::snapshot(&dir).unwrap().registry.devices[0].active);
                    Ok(())
                },
                |tx, state| {
                    calls += 1;
                    if calls != failed_call {
                        return tx.write(state);
                    }
                    atomic_write_json_with(&dir.join("devices.json"), state, 0o600, |stage| {
                        if stage == failed_stage {
                            bail!("synthetic write stage failure");
                        }
                        Ok(())
                    })
                },
            )
            .await
            .unwrap_err();
            let error = error.downcast_ref::<RevokeFailure>().unwrap();
            let state = registry::snapshot(&dir).unwrap();
            if failed_call == 1 {
                assert!(!remote_called.get());
                assert!(error.phase.contains("remote revoke was not attempted"));
                assert_eq!(
                    state.registry.devices[0].active,
                    failed_stage == AtomicWriteStage::BeforeRename
                );
                assert_eq!(
                    state.revocation_epoch,
                    u64::from(failed_stage == AtomicWriteStage::AfterRename)
                );
            } else {
                assert!(remote_called.get());
                assert!(error.phase.contains("local cleanup not durably confirmed"));
                assert_eq!(
                    state.registry.devices.is_empty(),
                    failed_stage == AtomicWriteStage::AfterRename
                );
                assert!(state.registry.devices.iter().all(|d| !d.active));
                assert_eq!(
                    error.readback,
                    if failed_stage == AtomicWriteStage::AfterRename {
                        "local readback: device absent"
                    } else {
                        "local readback: device inactive"
                    }
                );
                assert_eq!(state.revocation_epoch, 1);
            }
            revocation_success(&dir, &device.fingerprint).await;
            let state = registry::snapshot(&dir).unwrap();
            assert!(state.registry.devices.is_empty());
            assert_eq!(state.revocation_epoch, 1);
        }
    }
}

#[tokio::test]
async fn revocation_lifecycle_orders_live_activation_revoke_and_reenrollment() {
    let dir = std::sync::Arc::new(revocation_directory("lifecycle"));
    let (device, _) = auth_test_device();
    let (activation_started, activation_ready) = tokio::sync::oneshot::channel();
    let (release_activation, activation_release) = tokio::sync::oneshot::channel();
    let enroll_dir = dir.clone();
    let enroll_device = device.clone();
    let enrollment = tokio::spawn(async move {
        enroll_device_with(&enroll_dir, &enroll_device, || async {
            activation_started.send(()).unwrap();
            activation_release.await.unwrap();
            Ok(())
        })
        .await
    });
    activation_ready.await.unwrap();
    // Activation holds lifecycle, but never the registry lock across await.
    assert!(registry::snapshot(&dir).unwrap().registry.devices[0].active);
    let error = revoke_with(
        &dir,
        &device.fingerprint,
        || async { panic!("busy revoke must not publish") },
        registry::persist,
    )
    .await
    .unwrap_err();
    assert!(error.downcast_ref::<registry::Busy>().is_some());
    let mut input = io::Cursor::new(format!("{}\n", device.fingerprint));
    assert!(
        pin_device_record(&dir, &device, &mut input)
            .unwrap_err()
            .downcast_ref::<registry::Busy>()
            .is_some()
    );
    release_activation.send(()).unwrap();
    enrollment.await.unwrap().unwrap();
    let (revoke_started, revoke_ready) = tokio::sync::oneshot::channel();
    let (release_revoke, revoke_release) = tokio::sync::oneshot::channel();
    let revoke_dir = dir.clone();
    let fingerprint = device.fingerprint.clone();
    let revocation = tokio::spawn(async move {
        revoke_with(
            &revoke_dir,
            &fingerprint,
            || async {
                revoke_started.send(()).unwrap();
                revoke_release.await.unwrap();
                Ok(())
            },
            registry::persist,
        )
        .await
    });
    revoke_ready.await.unwrap();
    assert!(!registry::snapshot(&dir).unwrap().registry.devices[0].active);
    assert!(
        enroll_device_with(&dir, &device, || async {
            panic!("busy enrollment must not activate")
        })
        .await
        .is_err()
    );
    assert!(
        revoke_with(
            &dir,
            &device.fingerprint,
            || async { panic!("duplicate revoke must not publish") },
            registry::persist
        )
        .await
        .unwrap_err()
        .downcast_ref::<registry::Busy>()
        .is_some()
    );
    release_revoke.send(()).unwrap();
    revocation.await.unwrap().unwrap();
    enroll_device_with(&dir, &device, || async { Ok(()) })
        .await
        .unwrap();
    let state = registry::snapshot(&dir).unwrap();
    assert!(state.registry.devices[0].active);
    assert_eq!(state.revocation_epoch, 1);
}

#[test]
fn revocation_legacy_epoch_default_overflow_and_lock_path_validation() {
    use std::os::unix::fs::symlink;
    let dir = revocation_directory("lock-paths");
    let (device, _) = auth_test_device();
    seed_registry(&dir, vec![device]);
    assert_eq!(registry::snapshot(&dir).unwrap().revocation_epoch, 0);
    let parent_alias = dir.with_extension("symlink");
    symlink(&dir, &parent_alias).unwrap();
    assert!(registry::snapshot(&parent_alias).is_err());
    let lock_path = dir.join(".devices.lock");
    fs::remove_file(&lock_path).unwrap();
    symlink(dir.join("devices.json"), &lock_path).unwrap();
    assert!(registry::snapshot(&dir).is_err());
    fs::remove_file(&lock_path).unwrap();
    fs::write(&lock_path, b"").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(registry::snapshot(&dir).is_err());
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(registry::snapshot(&dir).is_err());
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o755
    ); // refuse, never silently repair
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(dir.join("devices.json")).unwrap();
    assert!(
        registry::snapshot(&dir)
            .unwrap()
            .registry
            .devices
            .is_empty()
    );
    symlink(dir.join("missing"), dir.join("devices.json")).unwrap();
    assert!(registry::snapshot(&dir).is_err());
}

#[tokio::test]
async fn revocation_epoch_overflow_fails_without_remote_or_mutation() {
    let dir = revocation_directory("epoch-overflow");
    let (device, _) = auth_test_device();
    seed_registry(&dir, vec![device.clone()]);
    {
        let tx = registry::Transaction::acquire(&dir).unwrap();
        let mut state = tx.load().unwrap();
        state.revocation_epoch = u64::MAX;
        tx.write(&state).unwrap();
    }
    let error = revoke_with(
        &dir,
        &device.fingerprint,
        || async { panic!("overflow must not publish") },
        registry::persist,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("epoch exhausted"));
    let state = registry::snapshot(&dir).unwrap();
    assert!(state.registry.devices[0].active);
    assert_eq!(state.revocation_epoch, u64::MAX);
}

// Test binary child role. Each process independently opens the real stable
// flock. Parent uses bounded async pipe handshakes, never timing sleeps.
#[test]
fn revocation_lock_child() {
    let Some(dir) = std::env::var_os("OSHIOKI_LOCK_CHILD_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    if std::env::var_os("OSHIOKI_LOCK_CHILD_CONTEND").is_some() {
        let error = registry::Transaction::acquire(&dir)
            .err()
            .expect("held process lock must contend");
        assert!(error.downcast_ref::<registry::Busy>().is_some());
        println!("REVOCATION-CONTENDED");
        io::stdout().flush().unwrap();
        return;
    }
    let transaction = registry::Transaction::acquire(&dir).unwrap();
    println!("REVOCATION-HELD");
    io::stdout().flush().unwrap();
    let mut command = String::new();
    io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "rename");
    let state = transaction.load().unwrap();
    transaction.write(&state).unwrap();
    println!("REVOCATION-RENAMED");
    io::stdout().flush().unwrap();
    command.clear();
    io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "exit");
    // Drop/exit releases, no explicit unlink and no inherited lock handle.
}

#[tokio::test]
async fn revocation_independent_process_lock_survives_atomic_rename_and_exit() {
    use std::os::unix::fs::MetadataExt as _;
    use tokio::io::AsyncBufReadExt as _;
    async fn marker(
        lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
        wanted: &str,
    ) {
        while let Some(line) = lines.next_line().await.unwrap() {
            if line == wanted {
                return;
            }
        }
        panic!("child exited without {wanted}");
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = revocation_directory("process-lock");
        let (device, _) = auth_test_device();
        seed_registry(&dir, vec![device]);
        let executable = std::env::current_exe().unwrap();
        let mut holder = tokio::process::Command::new(&executable)
            .args([
                "--exact",
                "auth_tests::revocation_lock_child",
                "--nocapture",
            ])
            .env("OSHIOKI_LOCK_CHILD_DIR", &dir)
            .env_remove("OSHIOKI_LOCK_CHILD_CONTEND")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = holder.stdin.take().unwrap();
        let mut output = tokio::io::BufReader::new(holder.stdout.take().unwrap()).lines();
        marker(&mut output, "REVOCATION-HELD").await;
        let lock_before = fs::metadata(dir.join(".devices.lock")).unwrap();
        let registry_before = fs::metadata(dir.join("devices.json")).unwrap();
        input.write_all(b"rename\n").await.unwrap();
        marker(&mut output, "REVOCATION-RENAMED").await;
        assert_eq!(
            lock_before.ino(),
            fs::metadata(dir.join(".devices.lock")).unwrap().ino()
        );
        assert_ne!(
            registry_before.ino(),
            fs::metadata(dir.join("devices.json")).unwrap().ino()
        );
        let mut contender = tokio::process::Command::new(&executable)
            .args([
                "--exact",
                "auth_tests::revocation_lock_child",
                "--nocapture",
            ])
            .env("OSHIOKI_LOCK_CHILD_DIR", &dir)
            .env("OSHIOKI_LOCK_CHILD_CONTEND", "1")
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut output = tokio::io::BufReader::new(contender.stdout.take().unwrap()).lines();
        marker(&mut output, "REVOCATION-CONTENDED").await;
        assert!(contender.wait().await.unwrap().success());
        assert!(
            registry::Transaction::acquire(&dir)
                .err()
                .unwrap()
                .downcast_ref::<registry::Busy>()
                .is_some()
        );
        input.write_all(b"exit\n").await.unwrap();
        assert!(holder.wait().await.unwrap().success());
        assert!(registry::Transaction::acquire(&dir).is_ok());
    })
    .await
    .expect("bounded child process handshakes");
}

#[tokio::test]
async fn revocation_cleanup_preserves_new_other_device_counter_during_remote_work() {
    let dir = revocation_directory("cleanup-merge");
    let (revoked, _) = auth_test_device();
    let (other, key) = webauthn_test_device();
    seed_registry(&dir, vec![revoked.clone(), other.clone()]);
    revoke_with(
        &dir,
        &revoked.fingerprint,
        || async {
            let snapshot = registry::snapshot(&dir).unwrap();
            assert_eq!(snapshot.revocation_epoch, 1);
            let auth = auth_request();
            let raw = auth.raw_json().unwrap();
            apply_auth_decision(
                &webauthn_decision(&key, &other, &auth.request_id, &raw, 52),
                &auth,
                &raw,
                &auth_recipients(&snapshot.registry),
                snapshot.revocation_epoch,
                &dir,
            )?;
            Ok(())
        },
        registry::persist,
    )
    .await
    .unwrap();
    let state = registry::snapshot(&dir).unwrap();
    assert_eq!(state.registry.devices.len(), 1);
    assert_eq!(state.registry.devices[0].fingerprint, other.fingerprint);
    assert_eq!(state.registry.devices[0].sign_count, 52);
    assert_eq!(state.revocation_epoch, 1);
}

#[tokio::test]
async fn revocation_cleanup_refuses_changed_tombstone_or_incarnation() {
    for change_epoch in [false, true] {
        let dir = revocation_directory("cleanup-identity");
        let (device, _) = auth_test_device();
        seed_registry(&dir, vec![device.clone()]);
        let error = revoke_with(
            &dir,
            &device.fingerprint,
            || async {
                // Inject a current-state change through a real locked transaction;
                // cleanup must compare the captured tombstone, not delete by fp.
                let tx = registry::Transaction::acquire(&dir)?;
                let mut state = tx.load()?;
                if change_epoch {
                    state.revocation_epoch += 1;
                } else {
                    state.registry.devices[0].api_token_hash = URL_SAFE_NO_PAD.encode([99; 32]);
                }
                tx.write(&state)?;
                Ok(())
            },
            registry::persist,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pending revocation identity changed before cleanup")
        );
        let state = registry::snapshot(&dir).unwrap();
        assert_eq!(state.registry.devices.len(), 1);
        assert!(!state.registry.devices[0].active);
        revocation_success(&dir, &device.fingerprint).await;
        assert!(
            registry::snapshot(&dir)
                .unwrap()
                .registry
                .devices
                .is_empty()
        );
    }
}
