//! Native timed access approval over the existing NATS and socket transports.
use super::*;
use oshioki_protocol::access_v1::{AccessDecisionV1, AccessEnvelopeV1, AccessRequestV1};

pub(super) fn dispatch(
    payload: &[u8],
    identity: &Arc<Identity>,
    decider: &Arc<Decider>,
    nats: Option<async_nats::Client>,
    admission: &RequestAdmission,
) {
    let Ok(envelope) = serde_json::from_slice::<AccessEnvelopeV1>(payload) else {
        return;
    };
    let Some(permit) = admission.reserve() else {
        return;
    };
    let (identity, decider) = (Arc::clone(identity), Arc::clone(decider));
    tokio::spawn(async move {
        let result = async {
            let Some((request, raw)) = identity.open_access_request(&envelope)? else {
                return Ok(());
            };
            let Claim::Owner(lease) = permit.claim(
                &format!("access:{}", request.request_id),
                payload_hash(&raw),
            ) else {
                return Ok(());
            };
            let Some(nats) = nats else {
                return Ok(());
            };
            publish_alive(&nats, &request.request_id).await?;
            if let Some(decision) = decide_access(&identity, &decider, &request, &raw).await? {
                nats.publish(
                    format!("oshioki.verdict.{}", request.request_id),
                    serde_json::to_vec(&decision)?.into(),
                )
                .await?;
                nats.flush().await?;
            }
            lease.answered(RequestOutcome::Unanswered);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            warn!(error = %escape_for_terminal(&error.to_string()), "access approval failed closed");
        }
    });
}

pub(super) async fn socket(
    bytes: &[u8],
    identity: &Arc<Identity>,
    decider: &Decider,
    permit: RequestPermit,
    mut writer: tokio::net::unix::OwnedWriteHalf,
) -> Result<()> {
    let envelope: AccessEnvelopeV1 = serde_json::from_slice(bytes)?;
    let Some((request, raw)) = identity.open_access_request(&envelope)? else {
        return Ok(());
    };
    let Claim::Owner(lease) = permit.claim(
        &format!("access:{}", request.request_id),
        payload_hash(&raw),
    ) else {
        return Ok(());
    };
    writer
        .write_all(&oshioki_protocol::socket_v1::encode_frame(
            &serde_json::to_vec(&AliveV1::for_request(&request.request_id))?,
        )?)
        .await?;
    writer.flush().await?;
    if let Some(decision) = decide_access(identity, decider, &request, &raw).await? {
        writer
            .write_all(&oshioki_protocol::socket_v1::encode_frame(
                &serde_json::to_vec(&decision)?,
            )?)
            .await?;
    }
    lease.answered(RequestOutcome::Unanswered);
    Ok(())
}

async fn decide_access(
    identity: &Arc<Identity>,
    decider: &Decider,
    request: &AccessRequestV1,
    raw: &[u8],
) -> Result<Option<AccessDecisionV1>> {
    let summary = format!(
        "Allow credential access for {} seconds\n  vault: {}\n  service: {}\n  requester: {} on {}\n  broker: {}\n  purpose: {}",
        request.duration_seconds,
        escape_for_terminal(&request.vault),
        escape_for_terminal(&request.service),
        escape_for_terminal(&request.principal),
        escape_for_terminal(&request.host),
        escape_for_terminal(&request.audience),
        escape_for_terminal(&request.purpose)
    );
    match decider {
        Decider::Auto(_) => Ok(None),
        Decider::Prompt(prompter) => {
            if prompter
                .ask_authentication(&request.request_id, &summary, request.expires_at)
                .await?
                .is_none()
            {
                return Ok(None);
            }
            Ok(Some(identity.approve_access(raw, &summary)?))
        }
        #[cfg(target_os = "macos")]
        Decider::TouchId(prompt) => {
            use oshioki_agent::touchid::{AttemptError, Outcome};
            let (identity, raw) = (Arc::clone(identity), raw.to_vec());
            let sign = move || {
                identity.approve_access(&raw, &summary).map_err(|error| {
                    if matches!(
                        error.downcast_ref::<oshioki_enclave::SignError>(),
                        Some(oshioki_enclave::SignError::Canceled)
                    ) {
                        AttemptError::Canceled
                    } else {
                        AttemptError::Failed(error)
                    }
                })
            };
            match prompt
                .ask(&request.request_id, request.expires_at, sign)
                .await?
            {
                Outcome::Approved(decision) => Ok(Some(decision)),
                Outcome::Denied | Outcome::Expired => Ok(None),
            }
        }
    }
}
