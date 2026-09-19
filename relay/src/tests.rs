use super::*;

use std::fs;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    _server: Child,
    host: Peer,
    mac: Peer,
    requests: async_nats::Subscriber,
    replies: async_nats::Subscriber,
    traffic: async_nats::Subscriber,
    attempt: Message,
    reply: String,
    directory: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Harness {
    async fn new() -> Self {
        let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = address.local_addr().unwrap().port();
        drop(address);
        let server = Command::new("nats-server")
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("install nats-server to run relay integration tests");
        let client = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(client) = async_nats::connect(format!("nats://127.0.0.1:{port}")).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let host_key = SigningKey::random(&mut rand::rngs::OsRng);
        let mac_key = SigningKey::random(&mut rand::rngs::OsRng);
        let subject = format!("oshioki.browser.v1.{}", uuid::Uuid::new_v4());
        let host = Peer {
            client: client.clone(),
            signing: host_key.clone(),
            verifying: *mac_key.verifying_key(),
            subject: subject.clone(),
        };
        let mac = Peer {
            client: client.clone(),
            signing: mac_key,
            verifying: *host_key.verifying_key(),
            subject: subject.clone(),
        };
        let attempt = Message {
            version: 1,
            attempt: uuid::Uuid::new_v4().to_string(),
            expires: now() + 30,
            action: Action::Probe,
        };
        let reply = format!("{subject}.reply.{}", attempt.attempt);
        let requests = client.subscribe(subject).await.unwrap();
        let replies = client.subscribe(reply.clone()).await.unwrap();
        let traffic = client.subscribe("oshioki.browser.>").await.unwrap();
        client.flush().await.unwrap();
        let directory = PathBuf::from(format!("/tmp/oshioki-relay-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        Self {
            _server: server,
            host,
            mac,
            requests,
            replies,
            traffic,
            attempt,
            reply,
            directory,
        }
    }

    fn programs(&self) -> Programs {
        let browser = self.directory.join("browser");
        std::fs::write(&browser, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ssh = self.directory.join("ssh");
        std::fs::write(&ssh, "#!/bin/sh\nexec /bin/cat\n").unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        Programs { browser, ssh }
    }
}

fn oauth_url(port: u16) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/auth?client_id=32555940559.apps.googleusercontent.com&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A{port}%2F&scope=openid&state=example&code_challenge_method=S256&code_challenge={}",
        encode_base64url(&[7; 32])
    )
}

fn available_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

async fn start(
    host: &Peer,
    replies: &mut async_nats::Subscriber,
    attempt: &Message,
    url: String,
    stale: bool,
) {
    let offer = host.receive(replies, attempt).await.unwrap();
    let Action::Offer { nonce } = offer.action else {
        panic!("expected nonce offer")
    };
    host.send(
        &host.subject,
        attempt,
        Action::Start {
            nonce: if stale { "stale".into() } else { nonce },
            url,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn callback_bytes_stay_off_nats_and_stop_closes_both_listeners() {
    let mut h = Harness::new().await;
    let programs = h.programs();
    let port = available_port();
    let server = serve_attempt(
        &h.mac,
        &h.attempt,
        &h.reply,
        &mut h.requests,
        "pinned-nas",
        &programs,
    );
    let client = async {
        start(&h.host, &mut h.replies, &h.attempt, oauth_url(port), false).await;
        assert!(
            h.host
                .receive(&mut h.replies, &h.attempt)
                .await
                .unwrap()
                .action
                == Action::Ready
        );
        for address in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
            let mut callback = tokio::net::TcpStream::connect(address).await.unwrap();
            callback
                .write_all(b"code=TEST_SECRET_CODE&token=TEST_SECRET_TOKEN")
                .await
                .unwrap();
            callback.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            callback.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"code=TEST_SECRET_CODE&token=TEST_SECRET_TOKEN");
        }
        h.host
            .send(&h.host.subject, &h.attempt, Action::Stop)
            .await
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
    assert!(
        TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
    let mut count = 0;
    while let Ok(Some(frame)) = timeout(Duration::from_millis(20), h.traffic.next()).await {
        let key = if frame.subject.as_str().contains(".reply.") {
            &h.host.verifying
        } else {
            &h.mac.verifying
        };
        let message = verify(&frame.payload, key, now()).unwrap();
        let plaintext = serde_json::to_string(&message).unwrap();
        assert!(!plaintext.contains("TEST_SECRET"));
        count += 1;
    }
    assert_eq!(count, 4); // Offer, Start, Ready, Stop; never the callback.
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn malformed_and_replayed_start_never_open_listeners() {
    for stale in [false, true] {
        let mut h = Harness::new().await;
        let programs = h.programs();
        let port = available_port();
        let url = if stale {
            oauth_url(port)
        } else {
            oauth_url(port).replace("accounts.google.com", "evil.test")
        };
        let server = serve_attempt(
            &h.mac,
            &h.attempt,
            &h.reply,
            &mut h.requests,
            "pinned-nas",
            &programs,
        );
        let client = start(&h.host, &mut h.replies, &h.attempt, url, stale);
        let (result, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn expiry_cancels_active_forward_and_releases_port() {
    let mut h = Harness::new().await;
    let programs = h.programs();
    let port = available_port();
    let server = timeout(
        Duration::from_secs(2),
        serve_attempt(
            &h.mac,
            &h.attempt,
            &h.reply,
            &mut h.requests,
            "pinned-nas",
            &programs,
        ),
    );
    let client = async {
        start(&h.host, &mut h.replies, &h.attempt, oauth_url(port), false).await;
        assert!(
            h.host
                .receive(&mut h.replies, &h.attempt)
                .await
                .unwrap()
                .action
                == Action::Ready
        );
        let mut callback = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        callback.write_all(b"x").await.unwrap();
        let mut byte = [0];
        callback.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);
        assert_eq!(
            timeout(Duration::from_secs(2), callback.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    };
    let (result, ()) = tokio::join!(server, client);
    assert!(result.is_err());
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
    assert!(
        TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn ipv6_collision_does_not_leave_ipv4_listener() {
    let mut h = Harness::new().await;
    let programs = h.programs();
    let occupied = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let server = serve_attempt(
        &h.mac,
        &h.attempt,
        &h.reply,
        &mut h.requests,
        "pinned-nas",
        &programs,
    );
    let client = start(&h.host, &mut h.replies, &h.attempt, oauth_url(port), false);
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    drop(occupied);
    assert!(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn ssh_exit_does_not_wait_for_browser_write_half() {
    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-forward-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let ssh = directory.join("ssh");
    fs::write(&ssh, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let result = timeout(
        Duration::from_secs(1),
        forward(server, "unused-destination".into(), port, ssh),
    )
    .await
    .expect("SSH failure must not wait for an open browser socket")
    .expect_err("failed SSH must fail the forward");
    drop(client);
    assert!(result.to_string().contains("SSH callback forward failed"));
}

#[tokio::test]
async fn ssh_response_is_drained_before_success() {
    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-forward-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let ssh = directory.join("ssh");
    fs::write(
        &ssh,
        "#!/bin/sh\n/bin/dd if=/dev/zero bs=1024 count=256 2>/dev/null\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (mut client_read, mut client_write) = client.into_split();
    client_write.shutdown().await.unwrap();
    let (result, response) = timeout(Duration::from_secs(2), async {
        tokio::join!(
            forward(server, "unused-destination".into(), port, ssh),
            async {
                let mut response = Vec::new();
                client_read.read_to_end(&mut response).await.unwrap();
                response
            }
        )
    })
    .await
    .expect("large callback response must not deadlock SSH cleanup");
    result.unwrap();
    assert_eq!(response.len(), 256 * 1024);
    assert!(response.iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn process_group_terminates_launcher_descendants_before_reaping() {
    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-process-group-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let marker = directory.join("marker");
    let pid_file = directory.join("pid");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("while :; do printf x >> \"$1\"; sleep 0.01; done & echo $! > \"$2\"; wait")
        .arg("sh")
        .arg(&marker)
        .arg(&pid_file);
    let mut group = ProcessGroup::spawn(command).unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if marker.exists() && pid_file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("launcher descendant did not start");
    let before = fs::metadata(&marker).unwrap().len();
    assert!(before > 0);

    group.terminate().await;
    assert!(group.child.id().is_none());
    let after = fs::metadata(&marker).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(after >= before);
    assert_eq!(fs::metadata(&marker).unwrap().len(), after);
}

#[tokio::test]
async fn process_group_anchor_cleans_descendant_after_leader_exit() {
    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-process-group-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let marker = directory.join("marker");
    let pid_file = directory.join("pid");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("while :; do printf x >> \"$1\"; sleep 0.01; done & echo $! > \"$2\"; exit 0")
        .arg("sh")
        .arg(&marker)
        .arg(&pid_file);
    let mut group = ProcessGroup::spawn(command).unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if marker.exists() && pid_file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("launcher descendant did not start");
    group.child.wait().await.unwrap();
    let before = fs::metadata(&marker).unwrap().len();
    group.terminate().await;
    assert!(group.child.id().is_none());
    let after = fs::metadata(&marker).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(after >= before);
    assert_eq!(fs::metadata(&marker).unwrap().len(), after);
}
