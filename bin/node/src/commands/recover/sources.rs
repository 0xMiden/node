//! Bounded retries for finite validator backup subscriptions.
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::clients::ValidatorClient;
use miden_node_proto::generated::miden::validator::v1::{BlockSubscriptionRequest, StatusRequest};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use url::Url;

use super::{ProtocolConfigStreamState, RecoveredBlock, decode_entry};

const ATTEMPTS: usize = 3;
const TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF: Duration = Duration::from_millis(200);

pub(super) async fn discover(
    validators: Vec<(Url, ValidatorClient)>,
) -> anyhow::Result<(Vec<(Url, ValidatorClient, u32)>, Vec<(Url, anyhow::Error)>)> {
    let mut statuses = tokio::task::JoinSet::new();
    for (url, mut client) in validators {
        statuses.spawn(async move {
            let tip = tip(&mut client).await;
            (url, client, tip)
        });
    }
    let mut available = Vec::new();
    let mut unknown = Vec::new();
    while let Some(status) = statuses.join_next().await {
        let (url, client, tip) = status?;
        match tip {
            Ok(tip) => available.push((url, client, tip)),
            Err(error) => unknown.push((url, error)),
        }
    }
    Ok((available, unknown))
}

async fn tip(client: &mut ValidatorClient) -> anyhow::Result<u32> {
    for attempt in 1.. {
        let result = timeout(TIMEOUT, client.status(StatusRequest {}))
            .await
            .context("validator status timed out")
            .and_then(|r| Ok(r?.into_inner().chain_tip));
        match result {
            Err(_) if attempt < ATTEMPTS => sleep(BACKOFF).await,
            result => return result,
        }
    }
    unreachable!()
}

/// Resumes each interrupted stream at the first unread height with a fresh config baseline.
pub(super) async fn read(
    mut client: ValidatorClient,
    url: Url,
    start: u32,
    tip: u32,
    tx: mpsc::Sender<anyhow::Result<RecoveredBlock>>,
) {
    let mut stream = None;
    let mut config = ProtocolConfigStreamState::default();
    for height in start..=tip {
        for attempt in 1.. {
            let result = async {
                if stream.is_none() {
                    let opened = client
                        .block_subscription(BlockSubscriptionRequest { block_from: height })
                        .await?;
                    stream = Some(opened.into_inner());
                    config = ProtocolConfigStreamState::default();
                }
                let event =
                    stream.as_mut().unwrap().message().await?.context("premature backup EOF")?;
                anyhow::ensure!(event.committed_chain_tip >= tip, "backup tip regressed");
                let item = decode_entry(event, Some(&url))?;
                config.accept(
                    item.block.header().protocol_config_commitment(),
                    item.protocol_config.is_some(),
                )?;
                anyhow::ensure!(
                    item.block.header().block_num().as_u32() == height,
                    "unexpected backup height"
                );
                anyhow::Ok(item)
            };
            match timeout(TIMEOUT, result).await.context("backup read timed out").and_then(|r| r) {
                Ok(item) => {
                    if tx.send(Ok(item)).await.is_err() {
                        return;
                    }
                    break;
                },
                Err(_) if attempt < ATTEMPTS => {
                    stream = None;
                    sleep(BACKOFF).await;
                },
                Err(error) => {
                    let _ = tx
                        .send(Err(
                            error.context(format!("backup {url} incomplete from height {height}"))
                        ))
                        .await;
                    return;
                },
            }
        }
    }
}
