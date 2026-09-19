//! Live NATS check that a stream/consumer created for command approval only
//! is repaired so `oshioki.auth.>` is delivered. Run via
//! `scripts/test-nats-lane-upgrade` (sets `NATS_URL`).

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use async_nats::jetstream::{
    self,
    consumer::{AckPolicy, pull},
    stream,
};
use futures::StreamExt as _;
use oshioki_transport::{
    ServerTransport as _,
    nats::{NatsTransport, REQUEST_CONSUMER, REQUEST_CONSUMER_FILTERS, REQUEST_STREAM},
};

#[tokio::test]
async fn a_legacy_stream_and_consumer_gain_the_authentication_lane() -> Result<()> {
    if std::env::var_os("OSHIOKI_TEST_NATS_LANE").is_none() {
        eprintln!("skipping: set OSHIOKI_TEST_NATS_LANE=1 and NATS_URL for a throwaway broker");
        return Ok(());
    }
    let url = match std::env::var("NATS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipping: set NATS_URL to exercise lane repair against a broker");
            return Ok(());
        }
    };
    let user = std::env::var("NATS_USER").ok();
    let pass = std::env::var("NATS_PASS").ok();
    let mut options = async_nats::ConnectOptions::new();
    if let (Some(user), Some(pass)) = (user, pass) {
        options = options.user_and_password(user, pass);
    }
    let client = options
        .connect(&url)
        .await
        .with_context(|| format!("connect to {url}"))?;
    let jetstream = jetstream::new(client.clone());
    let _ = jetstream.delete_stream(REQUEST_STREAM).await;
    jetstream
        .create_stream(stream::Config {
            name: REQUEST_STREAM.into(),
            subjects: vec!["oshioki.request.>".into()],
            ..Default::default()
        })
        .await
        .context("create legacy command-only stream")?;
    let stream = jetstream.get_stream(REQUEST_STREAM).await?;
    stream
        .create_consumer(pull::Config {
            durable_name: Some(REQUEST_CONSUMER.into()),
            filter_subject: "oshioki.request.>".into(),
            ack_policy: AckPolicy::Explicit,
            ..Default::default()
        })
        .await
        .context("create legacy command-only consumer")?;

    let transport = NatsTransport::from_client(client.clone());
    let mut inbound = transport
        .requests()
        .await
        .context("open repaired consumer")?;

    let stream = jetstream.get_stream(REQUEST_STREAM).await?;
    let subjects = &stream.cached_info().config.subjects;
    for required in REQUEST_CONSUMER_FILTERS {
        anyhow::ensure!(
            subjects.iter().any(|subject| subject == required),
            "stream subjects {subjects:?} missing {required}"
        );
    }
    let info = stream.consumer_info(REQUEST_CONSUMER).await?;
    let filters = if info.config.filter_subjects.is_empty() {
        vec![info.config.filter_subject.clone()]
    } else {
        info.config.filter_subjects.clone()
    };
    for required in REQUEST_CONSUMER_FILTERS {
        anyhow::ensure!(
            filters.iter().any(|subject| subject == required),
            "consumer filters {filters:?} missing {required}"
        );
    }

    jetstream
        .publish("oshioki.auth.compat-host", b"auth-lane".as_slice().into())
        .await
        .context("publish authentication-lane message")?
        .await
        .context("ack authentication-lane publish")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, inbound.next()).await {
            Ok(Some(Ok(batch))) => {
                if batch.iter().any(|message| message.payload == b"auth-lane") {
                    return Ok(());
                }
            }
            Ok(Some(Err(error))) => return Err(error).context("read repaired consumer"),
            Ok(None) => bail!("repaired consumer closed before the authentication message"),
            Err(_) => bail!("authentication-lane message was not delivered within 5s"),
        }
    }
}

#[tokio::test]
async fn a_covering_wildcard_stream_is_left_alone() -> Result<()> {
    if std::env::var_os("OSHIOKI_TEST_NATS_LANE").is_none() {
        eprintln!("skipping: set OSHIOKI_TEST_NATS_LANE=1 and NATS_URL for a throwaway broker");
        return Ok(());
    }
    let url = match std::env::var("NATS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => return Ok(()),
    };
    let user = std::env::var("NATS_USER").ok();
    let pass = std::env::var("NATS_PASS").ok();
    let mut options = async_nats::ConnectOptions::new();
    if let (Some(user), Some(pass)) = (user, pass) {
        options = options.user_and_password(user, pass);
    }
    let client = options.connect(&url).await?;
    let jetstream = jetstream::new(client.clone());
    let _ = jetstream.delete_stream(REQUEST_STREAM).await;
    jetstream
        .create_stream(stream::Config {
            name: REQUEST_STREAM.into(),
            subjects: vec!["oshioki.>".into()],
            ..Default::default()
        })
        .await
        .context("create covering wildcard stream")?;
    let transport = NatsTransport::from_client(client);
    let inbound = transport
        .requests()
        .await
        .context("open consumer against covering wildcard stream")?;
    drop(inbound);
    let subjects = jetstream
        .get_stream(REQUEST_STREAM)
        .await?
        .cached_info()
        .config
        .subjects
        .clone();
    anyhow::ensure!(
        subjects == ["oshioki.>"],
        "covering wildcard was rewritten: {subjects:?}"
    );
    Ok(())
}
