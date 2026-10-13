//! Live NATS check that the hook-side waits ignore anything a co-tenant
//! publisher can inject on a request's reply subjects. Spawns a throwaway
//! `nats-server` from `PATH` (no `JetStream` needed: the hook lane is core
//! pub/sub) and skips when none is installed.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result};
use futures::StreamExt as _;
use oshioki_protocol::{
    AliveV1, DecisionV1, DeliveryV1, DenyV1, VERSION_V1,
    auth_v1::{AUTH_WIRE_VERSION, AuthApproveNativeV1, AuthDecisionV1},
};
use oshioki_transport::{HookTransport as _, HookTransportFailure, nats::NatsTransport};

struct Broker {
    child: Child,
    url: String,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn nats_server() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("nats-server"))
        .find(|candidate| candidate.is_file())
}

async fn start_broker() -> Option<Broker> {
    let Some(binary) = nats_server() else {
        eprintln!("skipping: nats-server is not on PATH");
        return None;
    };
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(binary)
        .args(["-a", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nats-server");
    let broker = Broker {
        child,
        url: format!("nats://127.0.0.1:{port}"),
    };
    let started = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "nats-server never became ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Some(broker)
}

/// A request ID unique to this run; the format only needs to pass `valid_id`.
fn fresh_request_id() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("h2-{}-{nanos}-{serial}", std::process::id())
}

fn deny(request_id: &str, fingerprint: &str) -> DenyV1 {
    DenyV1 {
        version: VERSION_V1,
        request_id: request_id.into(),
        device_fingerprint: fingerprint.into(),
        signature: None,
    }
}

fn json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// Plays both the attacker and the honest agent for one request on
/// `request_subject`: the junk goes first on every reply subject, then the
/// real receipt and decisions.
async fn answer(
    client: async_nats::Client,
    request_subject: String,
    browser: bool,
    decisions: Vec<Vec<u8>>,
) -> Result<()> {
    let mut requests = client.subscribe(request_subject).await?;
    client.flush().await?;
    let request = requests.next().await.context("request stream closed")?;
    let request_id = String::from_utf8(request.payload.to_vec())?;
    let ack = format!("oshioki.ack.{request_id}");
    let delivery = format!("oshioki.delivery.{request_id}");
    let verdict = format!("oshioki.verdict.{request_id}");
    let junk = [
        b"not json".to_vec(),
        br#"{"type":"future_kind","version":1}"#.to_vec(),
        json(&AliveV1::for_request(
            "00000000-0000-4000-8000-000000000000",
        )),
        json(&DeliveryV1::for_request(
            "00000000-0000-4000-8000-000000000000",
        )),
        json(&DecisionV1::Deny(deny(&request_id, "fp"))),
    ];
    if browser {
        for bytes in &junk {
            client
                .publish(delivery.clone(), bytes.clone().into())
                .await?;
        }
        client
            .publish(delivery, json(&DeliveryV1::for_request(&request_id)).into())
            .await?;
    }
    for bytes in &junk {
        client.publish(ack.clone(), bytes.clone().into()).await?;
    }
    client
        .publish(ack, json(&AliveV1::for_request(&request_id)).into())
        .await?;
    for bytes in decisions {
        client.publish(verdict.clone(), bytes.into()).await?;
    }
    client.flush().await?;
    Ok(())
}

/// Command lane: every forged or malformed receipt and verdict is skipped,
/// the first well-formed decision for this request comes through, later ones
/// stay readable, and the deadline ends the stream as `Expired` -- never as
/// an error the hook would classify as a denial.
#[tokio::test]
async fn injected_receipts_and_verdicts_are_skipped_on_the_command_lane() -> Result<()> {
    let Some(broker) = start_broker().await else {
        return Ok(());
    };
    for browser in [false, true] {
        let request_id = fresh_request_id();
        let peer = async_nats::connect(&broker.url).await?;
        let first = deny(&request_id, "first");
        let second = DecisionV1::ApproveNative(oshioki_protocol::ApproveNativeV1 {
            version: VERSION_V1,
            request_id: request_id.clone(),
            device_fingerprint: "second".into(),
            signature: "c2ln".into(),
        });
        let decisions = vec![
            b"{garbage".to_vec(),
            json(&DecisionV1::Deny(deny(
                "00000000-0000-4000-8000-000000000000",
                "other-request",
            ))),
            json(&AuthDecisionV1::AuthenticateNative(AuthApproveNativeV1 {
                version: AUTH_WIRE_VERSION,
                request_id: request_id.clone(),
                device_fingerprint: "wrong-lane".into(),
                signature: "c2ln".into(),
            })),
            json(&AliveV1::for_request(&request_id)),
            json(&DecisionV1::Deny(first.clone())),
            json(&second),
        ];
        let agent = tokio::spawn(answer(
            peer,
            "oshioki.request.h2-test".into(),
            browser,
            decisions,
        ));
        let transport = NatsTransport::from_client(async_nats::connect(&broker.url).await?);
        let started = tokio::time::Instant::now();
        let mut stream = transport
            .request_decision(
                "h2-test",
                &request_id,
                request_id.as_bytes().to_vec(),
                Duration::from_secs(2),
                browser,
                std::sync::Arc::new(|_| {}),
            )
            .await
            .context("receipt wait must skip injected receipts")?;
        agent.await??;
        assert_eq!(stream.next().await.unwrap()?, DecisionV1::Deny(first));
        assert_eq!(stream.next().await.unwrap()?, second);
        let error = stream.next().await.unwrap().unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<HookTransportFailure>(),
                Some(HookTransportFailure::Expired(_))
            ),
            "{error:#}"
        );
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert!(stream.next().await.is_none());
    }
    Ok(())
}

/// Authentication lane: the same filter, with a command decision as the
/// wrong-lane message.
#[tokio::test]
async fn injected_verdicts_are_skipped_on_the_authentication_lane() -> Result<()> {
    let Some(broker) = start_broker().await else {
        return Ok(());
    };
    let request_id = fresh_request_id();
    let genuine = AuthDecisionV1::AuthenticateNative(AuthApproveNativeV1 {
        version: AUTH_WIRE_VERSION,
        request_id: request_id.clone(),
        device_fingerprint: "genuine".into(),
        signature: "c2ln".into(),
    });
    let decisions = vec![
        json(&DecisionV1::Deny(deny(&request_id, "wrong-lane"))),
        json(&AuthDecisionV1::AuthenticateNative(AuthApproveNativeV1 {
            version: AUTH_WIRE_VERSION,
            request_id: "00000000-0000-4000-8000-000000000000".into(),
            device_fingerprint: "other-request".into(),
            signature: "c2ln".into(),
        })),
        b"[]".to_vec(),
        json(&genuine),
    ];
    let peer = async_nats::connect(&broker.url).await?;
    let agent = tokio::spawn(answer(
        peer,
        "oshioki.auth.h2-test".into(),
        false,
        decisions,
    ));
    let transport = NatsTransport::from_client(async_nats::connect(&broker.url).await?);
    let mut stream = transport
        .request_authentication(
            "h2-test",
            &request_id,
            request_id.as_bytes().to_vec(),
            Duration::from_secs(2),
            false,
            std::sync::Arc::new(|_| {}),
        )
        .await?;
    agent.await??;
    assert_eq!(stream.next().await.unwrap()?, genuine);
    Ok(())
}

/// Only junk ever arrives on the acknowledgement subject: the short receipt
/// wait ends as a daemon outage (password-eligible), not a protocol failure.
#[tokio::test]
async fn an_acknowledgement_subject_full_of_junk_is_a_daemon_outage() -> Result<()> {
    let Some(broker) = start_broker().await else {
        return Ok(());
    };
    let request_id = fresh_request_id();
    let peer = async_nats::connect(&broker.url).await?;
    let spammer = tokio::spawn(async move {
        let mut requests = peer.subscribe("oshioki.request.h2-junk").await?;
        peer.flush().await?;
        let request = requests.next().await.context("request stream closed")?;
        let request_id = String::from_utf8(request.payload.to_vec())?;
        for _ in 0..20 {
            peer.publish(
                format!("oshioki.ack.{request_id}"),
                json(&AliveV1::for_request(
                    "00000000-0000-4000-8000-000000000000",
                ))
                .into(),
            )
            .await?;
        }
        peer.flush().await?;
        Ok::<_, anyhow::Error>(())
    });
    let transport = NatsTransport::from_client(async_nats::connect(&broker.url).await?);
    let Err(error) = transport
        .request_decision(
            "h2-junk",
            &request_id,
            request_id.as_bytes().to_vec(),
            Duration::from_secs(10),
            false,
            std::sync::Arc::new(|_| {}),
        )
        .await
    else {
        panic!("junk acknowledgements must not count as a receipt");
    };
    spammer.await??;
    assert!(
        matches!(
            error.downcast_ref::<HookTransportFailure>(),
            Some(HookTransportFailure::Daemon(_))
        ),
        "{error:#}"
    );
    Ok(())
}
