//! Real wrapper + browser-launcher subprocesses against disposable NATS.
//! The Google and Mac boundaries are simulated; no accounts are contacted.

use std::{
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt as _;
use oshioki_browser_relay::{Action, Message, approval_challenge, sign, verify};
use oshioki_protocol::encode_base64url;
use p256::ecdsa::{SigningKey, signature::Signer as _};
use tokio::{process::Command, time::timeout};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end fixture owns all subprocess cleanup.
#[ignore = "requires nats-server and python3; run scripts/test-browser-relay"]
async fn wrapper_preserves_browser_flow_and_fails_on_google_denial_or_mac_failure() {
    for (google_exit, mac_fails) in [(0, false), (1, false), (0, true)] {
        let dir = Temp(PathBuf::from(format!(
            "/tmp/oshioki-relay-cli-{}",
            uuid::Uuid::new_v4()
        )));
        std::fs::create_dir(&dir.0).unwrap();
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = bound.local_addr().unwrap().port();
        drop(bound);
        let mut broker = Command::new("nats-server")
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let nats_url = format!("nats://127.0.0.1:{port}");
        let client = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(client) = async_nats::connect(&nats_url).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let host = SigningKey::random(&mut rand::rngs::OsRng);
        let mac = SigningKey::random(&mut rand::rngs::OsRng);
        let lane = uuid::Uuid::new_v4().to_string();
        let key = dir.0.join("key");
        std::fs::write(&key, encode_base64url(&host.to_bytes())).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.0.join("config.json");
        std::fs::write(&config, serde_json::to_vec(&serde_json::json!({
            "lane": lane, "nats_url": nats_url, "private_key": key,
            "peer_public_key": encode_base64url(mac.verifying_key().to_encoded_point(false).as_bytes())
        })).unwrap()).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gcloud = dir.0.join("gcloud");
        std::fs::write(&gcloud, r"#!/usr/bin/env python3
import os, shlex, subprocess, sys
assert sys.argv[1:] == ['auth', 'login', '--force', '--launch-browser']
assert os.environ['DISPLAY'] == 'oshioki-browser-relay'
assert os.environ['CLOUDSDK_AUTH_DISABLE_CODE_VERIFIER'] == 'false'
# Match Python webbrowser's custom BROWSER argument substitution.
args = [part.replace('%s', os.environ['TEST_OAUTH_URL']) for part in shlex.split(os.environ['BROWSER'])]
result = subprocess.call(args)
sys.exit(result or int(os.environ['TEST_GOOGLE_EXIT']))
").unwrap();
        std::fs::set_permissions(&gcloud, std::fs::Permissions::from_mode(0o700)).unwrap();
        let url = format!(
            "https://accounts.google.com/o/oauth2/auth?client_id=32555940559.apps.googleusercontent.com&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid&state=example&code_challenge_method=S256&code_challenge={}",
            encode_base64url(&[7; 32])
        );
        let subject = format!("oshioki.browser.v1.{lane}");
        let mut requests = client.subscribe(subject).await.unwrap();
        client.flush().await.unwrap();
        let mut wrapper = Command::new(env!("CARGO_BIN_EXE_oshioki-browser-relay"))
            .args(["login", "--config"])
            .arg(config)
            .env(
                "PATH",
                format!("{}:{}", dir.0.display(), std::env::var("PATH").unwrap()),
            )
            .env("TEST_OAUTH_URL", &url)
            .env("TEST_GOOGLE_EXIT", google_exit.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let receiver = async {
            let probe = verify(
                &requests.next().await.unwrap().payload,
                host.verifying_key(),
                now(),
            )
            .unwrap();
            assert!(probe.action == Action::Probe);
            let reply = format!("oshioki.browser.v1.{lane}.reply.{}", probe.attempt);
            let mut response = Message {
                action: Action::Offer {
                    nonce: "fresh-mac-nonce".into(),
                },
                ..probe.clone()
            };
            client
                .publish(reply.clone(), sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
            let start = verify(
                &requests.next().await.unwrap().payload,
                host.verifying_key(),
                now(),
            )
            .unwrap();
            assert!(
                matches!(start.action, Action::Start { nonce, url: sent } if nonce == "fresh-mac-nonce" && sent == url)
            );
            response.action = if mac_fails {
                Action::Failed
            } else {
                Action::Ready
            };
            client
                .publish(reply.clone(), sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
            let stop = verify(
                &requests.next().await.unwrap().payload,
                host.verifying_key(),
                now(),
            )
            .unwrap();
            assert!(stop.action == Action::Stop);
            response.action = Action::Closed;
            client
                .publish(reply, sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
            probe.attempt
        };
        let (attempt, status) = timeout(Duration::from_secs(10), async {
            tokio::join!(receiver, wrapper.wait())
        })
        .await
        .unwrap();
        assert_eq!(status.unwrap().success(), google_exit == 0 && !mac_fails);
        assert!(!PathBuf::from(format!("/tmp/oshioki-browser-{attempt}")).exists());
        broker.kill().await.unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires nats-server and python3; run scripts/test-browser-relay"]
async fn account_bound_flow_approves_headless_reuse_and_browser_fallback() {
    for (denied, browser, stall) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let dir = Temp(PathBuf::from(format!(
            "/tmp/oshioki-relay-account-{}",
            uuid::Uuid::new_v4()
        )));
        std::fs::create_dir(&dir.0).unwrap();
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = bound.local_addr().unwrap().port();
        drop(bound);
        let mut broker = Command::new("nats-server")
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let nats_url = format!("nats://127.0.0.1:{port}");
        let client = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(client) = async_nats::connect(&nats_url).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let host = SigningKey::random(&mut rand::rngs::OsRng);
        let mac = SigningKey::random(&mut rand::rngs::OsRng);
        let approval = SigningKey::random(&mut rand::rngs::OsRng);
        let lane = uuid::Uuid::new_v4().to_string();
        let key = dir.0.join("key");
        std::fs::write(&key, encode_base64url(&host.to_bytes())).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let marker = dir.0.join("gcloud-started");
        let config = dir.0.join("config.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "lane": lane,
                "nats_url": nats_url,
                "private_key": key,
                "peer_public_key": encode_base64url(mac.verifying_key().to_encoded_point(false).as_bytes()),
                "google_account": "selected@example.com",
                "approval_public_key": encode_base64url(approval.verifying_key().to_encoded_point(false).as_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gcloud = dir.0.join("gcloud");
        std::fs::write(
            &gcloud,
            r"#!/usr/bin/env python3
import os, shlex, subprocess, sys
if sys.argv[1:3] == ['auth', 'print-access-token']:
    print('synthetic-access-token')
    sys.exit(0)
assert sys.argv[1:] == ['auth', 'login', 'selected@example.com', '--launch-browser']
open(os.environ['TEST_MARKER'], 'w').close()
if os.environ['TEST_BROWSER'] == '1':
    args = [part.replace('%s', os.environ['TEST_OAUTH_URL']) for part in shlex.split(os.environ['BROWSER'])]
    sys.exit(subprocess.call(args))
sys.exit(0)
",
        )
        .unwrap();
        std::fs::set_permissions(&gcloud, std::fs::Permissions::from_mode(0o700)).unwrap();
        let url = format!(
            "https://accounts.google.com/o/oauth2/auth?client_id=32555940559.apps.googleusercontent.com&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid&state=example&code_challenge_method=S256&code_challenge={}",
            encode_base64url(&[7; 32])
        );
        let subject = format!("oshioki.browser.v1.{lane}");
        let mut requests = client.subscribe(subject).await.unwrap();
        client.flush().await.unwrap();
        let mut wrapper = Command::new(env!("CARGO_BIN_EXE_oshioki-browser-relay"))
            .args(["login", "--config"])
            .arg(&config)
            .env(
                "PATH",
                format!("{}:{}", dir.0.display(), std::env::var("PATH").unwrap()),
            )
            .env("TEST_MARKER", &marker)
            .env("TEST_BROWSER", if browser { "1" } else { "0" })
            .env("TEST_OAUTH_URL", &url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let receiver = async {
            let probe = verify(
                &requests.next().await.unwrap().payload,
                host.verifying_key(),
                now(),
            )
            .unwrap();
            let reply = format!("oshioki.browser.v1.{lane}.reply.{}", probe.attempt);
            let mut response = Message {
                action: Action::Offer {
                    nonce: "fresh-mac-nonce".into(),
                },
                ..probe.clone()
            };
            client
                .publish(reply.clone(), sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
            if stall {
                tokio::time::sleep(Duration::from_secs(10)).await;
                return;
            }
            let authorize = verify(
                &requests.next().await.unwrap().payload,
                host.verifying_key(),
                now(),
            )
            .unwrap();
            let Action::Authorize { nonce, account } = authorize.action else {
                panic!("expected account authorization")
            };
            assert_eq!(nonce, "fresh-mac-nonce");
            assert_eq!(account, "selected@example.com");
            let approval_signature: p256::ecdsa::Signature = approval.sign(
                &oshioki_protocol::browser_relay_signature_payload(&approval_challenge(
                    &lane,
                    &probe.attempt,
                    probe.expires,
                    "fresh-mac-nonce",
                    &account,
                )),
            );
            response.action = if denied {
                Action::Failed
            } else {
                Action::Authorized {
                    nonce,
                    signature: encode_base64url(approval_signature.to_der().as_bytes()),
                }
            };
            client
                .publish(reply.clone(), sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
            if denied {
                let stop = verify(
                    &requests.next().await.unwrap().payload,
                    host.verifying_key(),
                    now(),
                )
                .unwrap();
                assert!(stop.action == Action::Stop);
            } else if browser {
                let start = verify(
                    &requests.next().await.unwrap().payload,
                    host.verifying_key(),
                    now(),
                )
                .unwrap();
                assert!(matches!(start.action, Action::Start { url: sent, .. } if sent == url));
                response.action = Action::Ready;
                client
                    .publish(reply.clone(), sign(&response, &mac).unwrap().into())
                    .await
                    .unwrap();
                client.flush().await.unwrap();
                let stop = verify(
                    &requests.next().await.unwrap().payload,
                    host.verifying_key(),
                    now(),
                )
                .unwrap();
                assert!(stop.action == Action::Stop);
            } else {
                let stop = verify(
                    &requests.next().await.unwrap().payload,
                    host.verifying_key(),
                    now(),
                )
                .unwrap();
                assert!(stop.action == Action::Stop);
            }
            response.action = Action::Closed;
            client
                .publish(reply, sign(&response, &mac).unwrap().into())
                .await
                .unwrap();
            client.flush().await.unwrap();
        };
        let combined = timeout(Duration::from_secs(if stall { 2 } else { 10 }), async {
            tokio::join!(receiver, wrapper.wait())
        })
        .await;
        if stall {
            assert!(
                combined.is_err(),
                "the stalled approval should require external cleanup"
            );
            let _ = wrapper.kill().await;
            let _ = wrapper.wait().await;
            assert!(!marker.exists());
            broker.kill().await.unwrap();
            continue;
        }
        let ((), status) = combined.unwrap();
        assert_eq!(status.unwrap().success(), !denied);
        assert_eq!(marker.exists(), !denied);
        broker.kill().await.unwrap();
    }
}
