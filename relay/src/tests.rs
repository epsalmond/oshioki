use super::*;

use std::{
    collections::BTreeSet,
    fs,
    process::Command as StdCommand,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Arc<Mutex<Option<std::process::Child>>>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn authenticated_nats_url_uses_url_credentials() {
    const USER: &str = "relay-test-user";
    const PASSWORD: &str = "relay-test/password";
    let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = address.local_addr().unwrap().port();
    drop(address);
    let mut server = Command::new("nats-server")
        .args([
            "-a",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--user",
            USER,
            "--pass",
            PASSWORD,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("install nats-server to run relay integration tests");
    let nats_url = format!("nats://{USER}:relay-test%2Fpassword@127.0.0.1:{port}");
    timeout(Duration::from_secs(5), async {
        loop {
            if async_nats::ConnectOptions::with_user_and_password(
                USER.to_owned(),
                PASSWORD.to_owned(),
            )
            .connect(&nats_url)
            .await
            .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authenticated nats-server did not start");

    let directory = PathBuf::from(format!("/tmp/oshioki-relay-auth-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let key_path = directory.join("key");
    fs::write(&key_path, encode_base64url(&key.to_bytes())).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let peer_key = SigningKey::random(&mut rand::rngs::OsRng);
    let config = Config {
        nats_url,
        lane: uuid::Uuid::new_v4().to_string(),
        private_key: key_path,
        peer_public_key: encode_base64url(
            peer_key.verifying_key().to_encoded_point(false).as_bytes(),
        ),
        google_account: None,
        approval_public_key: None,
        approval_identity: None,
        ssh_destination: None,
    };
    let peer = timeout(Duration::from_secs(5), connect(&config))
        .await
        .expect("authenticated relay connection timed out")
        .expect("URL credentials were not accepted by NATS");
    peer.client.flush().await.unwrap();
    drop(peer);
    server.kill().await.unwrap();
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn legacy_successful_gcloud_without_browser_is_rejected() {
    let mut h = Harness::new().await;
    let socket_path = PathBuf::from(format!(
        "/tmp/oshioki-relay-login-test-{}",
        uuid::Uuid::new_v4()
    ));
    let listener = UnixListener::bind(&socket_path).unwrap();
    let mut child = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
    let error = login_attempt(
        &h.mac,
        &h.attempt,
        "fresh-nonce".into(),
        &mut h.replies,
        &listener,
        &mut child,
        false,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("without a browser ceremony"));
    drop(listener);
    let _ = fs::remove_file(socket_path);
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

fn browser_directories() -> BTreeSet<PathBuf> {
    fs::read_dir("/tmp")
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with("oshioki-browser-"))
        })
        .collect()
}

async fn startup_transport_fault_is_bounded(stage: StartupStage) {
    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-startup-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());

    let port = available_port();
    let server = StdCommand::new("nats-server")
        .args(["-a", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("install nats-server to run relay startup tests");
    let server = Arc::new(Mutex::new(Some(server)));
    let _server_guard = ChildGuard(Arc::clone(&server));
    timeout(Duration::from_secs(5), async {
        loop {
            if std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("nats-server did not start");

    let signing = SigningKey::random(&mut rand::rngs::OsRng);
    let peer = SigningKey::random(&mut rand::rngs::OsRng);
    let key_path = directory.join("key");
    fs::write(&key_path, encode_base64url(&signing.to_bytes())).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let config = Config {
        nats_url: format!("nats://127.0.0.1:{port}"),
        lane: uuid::Uuid::new_v4().to_string(),
        private_key: key_path,
        peer_public_key: encode_base64url(peer.verifying_key().to_encoded_point(false).as_bytes()),
        google_account: None,
        approval_public_key: None,
        approval_identity: None,
        ssh_destination: None,
    };
    let triggered = Arc::new(AtomicBool::new(false));
    let triggered_by_hook = Arc::clone(&triggered);
    let server_for_hook = Arc::clone(&server);
    let hooks = StartupHooks {
        fault: Some(Arc::new(move |actual| {
            if actual != stage {
                return;
            }
            triggered_by_hook.store(true, Ordering::SeqCst);
            if let Some(mut server) = server_for_hook.lock().unwrap().take() {
                let _ = server.kill();
                let _ = server.wait();
            }
        })),
    };
    let before = browser_directories();
    let started = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        login_with_lifetime(config, Duration::from_secs(2), hooks),
    )
    .await
    .expect("NATS startup fault was not bounded")
    .expect_err("NATS startup fault unexpectedly succeeded");
    assert!(
        triggered.load(Ordering::SeqCst),
        "fault hook was not reached"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "startup exceeded its two-second lifetime: {result:#}"
    );

    // The timeout happens before the relay creates its private browser socket
    // or process group. Restarting NATS must not resume the cancelled attempt.
    let mut restarted = StdCommand::new("nats-server")
        .args(["-a", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restart nats-server for cancellation check");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = restarted.kill();
    let _ = restarted.wait();
    let after = browser_directories();
    assert_eq!(
        before, after,
        "failed startup left a browser socket directory"
    );
    let _ = server.lock().unwrap().take();
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn subscription_flush_disconnect_is_bounded_before_browser_launch() {
    startup_transport_fault_is_bounded(StartupStage::BeforeSubscriptionFlush).await;
}

#[tokio::test]
#[ignore = "requires nats-server; run scripts/test-browser-relay"]
async fn probe_flush_disconnect_is_bounded_before_browser_launch() {
    startup_transport_fault_is_bounded(StartupStage::BeforeProbeFlush).await;
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
        "test-lane",
        None,
        "pinned-nas",
        &programs,
        None,
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
            "test-lane",
            None,
            "pinned-nas",
            &programs,
            None,
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
            "test-lane",
            None,
            "pinned-nas",
            &programs,
            None,
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
        "test-lane",
        None,
        "pinned-nas",
        &programs,
        None,
    );
    let client = start(&h.host, &mut h.replies, &h.attempt, oauth_url(port), false);
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    drop(occupied);
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(listener) = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
                drop(listener);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the failed dual-stack bind left the IPv4 port occupied");
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

#[tokio::test]
async fn local_mode_approval_and_gcloud_cleanup_are_deterministic() {
    for (name, command) in [
        ("headless", "exit 0"),
        ("browser", "exit 0"),
        ("timeout", "sleep 30"),
    ] {
        let directory = PathBuf::from(format!(
            "/tmp/oshioki-relay-local-{name}-{}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let _cleanup = TempDir(directory.clone());
        let marker = directory.join("started");
        let executable = directory.join("gcloud");
        let browser_spy = directory.join("browser-spy");
        fs::write(
            &browser_spy,
            format!(
                "#!/bin/sh\nprintf '%s' \"$1\" > '{}'\npython3 -c 'import socket,sys,urllib.parse; u=urllib.parse.urlparse(sys.argv[1]); c=socket.create_connection((u.hostname,u.port)); c.sendall(b\"GET /callback HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n\"); c.close()' \"$1\"\n",
                directory.join("browser-url").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&browser_spy, fs::Permissions::from_mode(0o700)).unwrap();
        let browser_launcher = "python3 - \"$BROWSER\" <<'PY'\nimport socket, subprocess, sys\ns = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\nurl = f'http://127.0.0.1:{s.getsockname()[1]}/callback'\nsubprocess.run([sys.argv[1], url], check=True)\nq, _ = s.accept(); q.recv(4096); q.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n'); q.close(); s.close()\nPY";
        let login_body = if name == "browser" {
            browser_launcher
        } else {
            command
        };
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nif [ \"$2\" = print-access-token ]; then printf token; exit 0; fi\ntouch '{}'\n{}\n",
                marker.display(), login_body
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        if name == "timeout" {
            let error = run_local_gcloud_with_timeout(
                "selected@example.com",
                &executable,
                Duration::from_millis(50),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("timed out"));
        } else {
            if name == "browser" {
                run_local_gcloud_with_timeout_and_browser(
                    "selected@example.com",
                    &executable,
                    Duration::from_secs(2),
                    &browser_spy,
                )
                .await
                .unwrap();
            } else {
                run_local_after_approval("selected@example.com", &executable, Ok(()), None)
                    .await
                    .unwrap();
            }
            assert!(marker.exists());
            if name == "browser" {
                let url = fs::read_to_string(directory.join("browser-url")).unwrap();
                assert!(url.starts_with("http://127.0.0.1:"));
                assert!(url.ends_with("/callback"));
            }
        }
    }

    let directory = PathBuf::from(format!(
        "/tmp/oshioki-relay-local-denied-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = TempDir(directory.clone());
    let marker = directory.join("started");
    let executable = directory.join("gcloud");
    fs::write(
        &executable,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        run_local_after_approval(
            "selected@example.com",
            &executable,
            Err(anyhow::anyhow!("denied")),
            None,
        )
        .await
        .is_err()
    );
    assert!(!marker.exists());

    let error = run_local_gcloud_with_timeout("selected@example.com", &executable, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expired before gcloud start"));
    assert!(!marker.exists());
}
