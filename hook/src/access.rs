//! The service invokes Verify with service-owned pins. No hook fallback or
//! requester-supplied boolean can produce its success attestation.
use super::*;
use oshioki_protocol::AliveV1;
use oshioki_protocol::access_v1::{
    ACCESS_ENVELOPE_TYPE, ACCESS_VERSION, AccessDecisionV1, AccessEnvelopeV1,
    parse_access_request_at, verify_access_decision,
};

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Ask an enrolled native device to authorize the exact request on stdin.
    Request {
        #[arg(long)]
        config_dir: PathBuf,
    },
    /// Verify a returned assertion using the broker's enrolled device pins.
    Verify {
        #[arg(long)]
        config_dir: PathBuf,
        /// Only this pinned fingerprint may authorize this principal.
        #[arg(long)]
        approver: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    request_json: String,
    approval: AccessDecisionV1,
}

pub async fn run(command: AccessCommand) -> Result<()> {
    let mut raw = Vec::new();
    io::stdin().take(64 * 1024 + 1).read_to_end(&mut raw)?;
    if raw.len() > 64 * 1024 {
        bail!("access input exceeds 64 KiB");
    }
    match command {
        AccessCommand::Verify {
            config_dir,
            approver,
        } => {
            verify(&raw, &config_dir, &approver)?;
        }
        AccessCommand::Request { config_dir } => {
            let request = parse_access_request_at(&raw, now())?;
            let registry = load_registry_from(&config_dir)?;
            let recipients: Vec<_> = registry
                .devices
                .iter()
                .filter(|d| d.active && d.kind == DeviceKindV1::SecureEnclave)
                .collect();
            if recipients.is_empty() {
                bail!("no active native hardware access approver is pinned");
            }
            let envelope = AccessEnvelopeV1 {
                message_type: ACCESS_ENVELOPE_TYPE.into(),
                version: ACCESS_VERSION,
                request_id: request.request_id.clone(),
                sealed: recipients
                    .into_iter()
                    .map(|d| oshioki_protocol::seal_v1(&raw, d))
                    .collect::<Result<_, _>>()?,
            };
            let bytes = serde_json::to_vec(&envelope)?;
            let transports = transports_from(&config_dir)?;
            let timeout = Duration::from_secs(
                u64::try_from(request.expires_at - now()).context("access request expired")?,
            );
            let approval: AccessDecisionV1 = tokio::time::timeout(timeout, async {
                if let Some(path) = transports.socket {
                    if let Ok(mut socket) = tokio::time::timeout(
                        AGENT_SOCKET_CONNECT_TIMEOUT,
                        UnixStream::connect(path),
                    )
                    .await?
                    {
                        socket
                            .write_all(&oshioki_protocol::socket_v1::encode_frame(&bytes)?)
                            .await?;
                        let ack = read_frame(&mut socket).await?;
                        let ack: AliveV1 = serde_json::from_slice(&ack)?;
                        ack.validate(&request.request_id)?;
                        return serde_json::from_slice(&read_frame(&mut socket).await?)
                            .map_err(Into::into);
                    }
                }
                if transports.nats_url.is_none() {
                    bail!("no access approval transport available");
                }
                let nats = NatsTransport::from_config_dir(&config_dir).await?;
                let decision = nats
                    .request_verdict_bytes(
                        format!("oshioki.access.{}", request.host),
                        &request.request_id,
                        bytes,
                        timeout,
                        false,
                        Arc::new(|_| {}),
                    )
                    .await?;
                serde_json::from_slice(&decision).map_err(Into::into)
            })
            .await
            .context("access ceremony timed out; request denied")??;
            let device = registry
                .devices
                .iter()
                .find(|d| d.fingerprint == approval.fingerprint())
                .context("unrecognized access approver")?;
            verify_access_decision(
                &approval,
                &raw,
                device,
                &load_hook_config_from(&config_dir)?,
                now(),
            )?;
            println!(
                "{}",
                serde_json::to_string(&Submission {
                    request_json: String::from_utf8(raw)?,
                    approval
                })?
            );
        }
    }
    Ok(())
}

fn verify(raw: &[u8], config_dir: &Path, approver: &str) -> Result<()> {
    let submission: Submission = serde_json::from_slice(raw)?;
    let registry = load_registry_from(config_dir)?;
    let device = registry
        .devices
        .iter()
        .find(|d| d.active && d.fingerprint == approver)
        .context("access approver is not in the active service-owned registry")?;
    verify_access_decision(
        &submission.approval,
        submission.request_json.as_bytes(),
        device,
        &load_hook_config_from(config_dir)?,
        now(),
    )?;
    // Exactly one success attestation; never a legacy hook fallback code.
    println!("{{\"type\":\"credential_access_verified\",\"version\":4}}");
    Ok(())
}

async fn read_frame(socket: &mut UnixStream) -> Result<Vec<u8>> {
    let length = socket.read_u32().await?;
    if length > 64 * 1024 {
        bail!("access frame exceeds bound");
    }
    let mut raw = vec![0; length as usize];
    socket.read_exact(&mut raw).await?;
    Ok(raw)
}

use std::sync::Arc;
