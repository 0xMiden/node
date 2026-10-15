use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::validator::SignBlockResponse;
use miden_node_proto::{BlockProofRequest, DecodeMessage, DecodeMessageExt};
use miden_node_store::{GenesisState, State};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockInputs, BlockNumber, ProposedBlock, SignedBlock};
use tokio::net::TcpListener;
use url::Url;

use super::super::{coalesce_signatures, inputs, recover_from_validators};
use super::support::*;

#[tokio::test]
async fn validator_serves_bound_listener() -> anyhow::Result<()> {
    let key = super::SigningKey::new();
    let genesis = miden_node_store::GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        super::validator_config(std::slice::from_ref(&key)),
        miden_node_utils::fee::test_protocol_config(),
    );
    let validator = start_validator(
        key,
        genesis.into_block()?.inner().clone(),
        miden_node_utils::fee::test_protocol_config(),
    )
    .await?;
    let result = validator
        .client()
        .status(miden_node_proto::generated::miden::validator::v1::StatusRequest {})
        .await;
    validator.stop().await?;
    assert_eq!(result?.into_inner().chain_tip, 0);
    Ok(())
}

/// Losing every original input file must leave validator backups sufficient to prove and replicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failover_recovers_inputs_and_proves_without_original_store() -> anyhow::Result<()> {
    for already_committed in [true, false] {
        failover(already_committed)
            .await
            .with_context(|| format!("failover with already_committed={already_committed}"))?;
    }
    Ok(())
}

async fn failover(already_committed: bool) -> anyhow::Result<()> {
    let keys = super::signers(2);
    let config = miden_node_utils::fee::test_protocol_config();
    let genesis = GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        super::validator_config(&keys),
        config.clone(),
    )
    .into_block()?;
    let mut validators = Vec::new();
    let result = async {
        for key in &keys {
            validators
                .push(start_validator(key.clone(), genesis.inner().clone(), config.clone()).await?);
        }
        let parent = genesis.inner().header().clone();
        let block_inputs = BlockInputs::new(
            parent.clone(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        );
        let (header, body) =
            ProposedBlock::new_at(block_inputs.clone(), vec![], 1)?.into_header_and_body()?;
        let request = BlockProofRequest {
            tx_batches: OrderedBatches::new(vec![]),
            block_header: header.clone(),
            block_inputs,
        };
        let mut signatures = Vec::new();
        for validator in &validators {
            let signing: miden_node_proto::generated::miden::validator::v1::SignBlockRequest =
                miden_node_proto::SignBlockRequest {
                    tx_batches: request.tx_batches.clone(),
                    block_header: header.clone(),
                    block_inputs: request.block_inputs.clone(),
                    protocol_config: None,
                }
                .into();
            let response: SignBlockResponse = validator
                .client()
                .sign_block(signing)
                .await?
                .into_inner()
                .decode_and_build_unchecked()?;
            signatures.push(response.signature);
        }
        let block = SignedBlock::new_unchecked(
            header,
            body,
            coalesce_signatures(
                signatures,
                request.block_header.commitment(),
                parent.validator_config(),
            )?,
        );
        let original = tempfile::tempdir()?;
        State::bootstrap(
            miden_node_store::genesis::GenesisBlock::new(
                genesis.inner().clone(),
                genesis.protocol_config().clone(),
            )?,
            original.path(),
        )
        .await?;
        let (state, mut writer, proof_writer, task) = load_store(original.path()).await?;
        let applied = writer
            .apply_block_with_proving_inputs(
                request.tx_batches.clone(),
                request.block_inputs.clone(),
                block.clone(),
            )
            .await;
        drop(proof_writer);
        writer.stop(task).await;
        drop(state);
        applied?;
        original.close()?;
        drop(request);

        if !already_committed {
            for (index, key) in keys.iter().enumerate() {
                let validator = validators.remove(index);
                let reopened = reopen_validator(key.clone(), validator.stop().await?).await?;
                validators.insert(index, reopened);
            }
        }
        let standby = tempfile::tempdir()?;
        State::bootstrap(
            miden_node_store::genesis::GenesisBlock::new(
                genesis.inner().clone(),
                genesis.protocol_config().clone(),
            )?,
            standby.path(),
        )
        .await?;
        let (state, mut writer, proof_writer, task) = load_store(standby.path()).await?;
        let recovered = async {
            if already_committed {
                writer.apply_block(block.clone(), None).await?;
            }
            ensure!(state.committed_tip() == BlockNumber::from(u32::from(already_committed)));
            ensure!(state.load_proving_inputs(1.into()).await?.is_none());
            ensure!(state.proven_tip() == BlockNumber::GENESIS);
            tokio::time::timeout(
                Duration::from_secs(30),
                recover_from_validators(
                    &state,
                    &mut writer,
                    validators.iter().map(|v| (v.url.clone(), v.client())).collect(),
                    CancellationToken::new(),
                ),
            )
            .await??;
            ensure!(state.committed_tip() == BlockNumber::from(1u32));
            ensure!(state.proven_tip() == BlockNumber::GENESIS);
            inputs::load_valid_local_inputs(&state, &block)
                .await?
                .context("missing recovered inputs")?
                .validate_against(&block)?;
            ensure!(!standby.path().join("fee-collector.mac").exists());
            anyhow::Ok(())
        }
        .await;
        drop(proof_writer);
        writer.stop(task).await;
        drop(state);
        recovered?;

        // Reopening proves that the prover depends only on durable recovered material.
        let (state, writer, mut proof_writer, task) = load_store(standby.path()).await?;
        let proved = miden_node_block_producer::prove_pending_blocks(
            &state,
            &mut proof_writer,
            None,
            CancellationToken::new(),
        )
        .await;
        let proof = state.load_proof(1.into()).await;
        let proven = state.proven_tip();
        drop(proof_writer);
        writer.stop(task).await;
        drop(state);
        proved?;
        ensure!(proven == BlockNumber::from(1u32));
        let proof = proof?.context("missing generated proof")?;
        replicate(
            &standby,
            miden_node_store::genesis::GenesisBlock::new(
                genesis.inner().clone(),
                genesis.protocol_config().clone(),
            )?,
            &block,
            proof,
        )
        .await?;
        anyhow::Ok(())
    }
    .await;
    let mut cleanup = Ok(());
    for validator in validators {
        let stopped = validator.stop().await.map(|_| ());
        cleanup = cleanup.and(stopped);
    }
    result.and(cleanup)
}

async fn replicate(
    directory: &tempfile::TempDir,
    genesis: miden_node_store::genesis::GenesisBlock,
    block: &SignedBlock,
    proof: Vec<u8>,
) -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let mut upstream_task = None;
    let mut downstream_task = None;
    let mut upstream_writer = None;
    let mut downstream_writer = None;
    let mut downstream_directory = None;
    let result = async {
        let (upstream, writer, proof_writer, task) = load_store(directory.path()).await?;
        upstream_writer = Some(task);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_url = Url::parse(&format!("http://{}", listener.local_addr()?))?;
        let client = |url: Url| {
            Builder::new(url)
                .without_tls()
                .with_timeout(Duration::from_secs(5))
                .without_metadata_version()
                .without_metadata_genesis()
                .without_otel_context_injection()
                .connect_lazy::<RpcClient>()
        };
        // The recovered node has lost its source. A self-source would recursively forward Status,
        // preventing an ordinary downstream node from completing its initial status query.
        let offline_source = TcpListener::bind("127.0.0.1:0").await?;
        let source_rpc =
            Builder::new(Url::parse(&format!("http://{}", offline_source.local_addr()?))?)
                .without_tls()
                .with_timeout(Duration::from_millis(100))
                .without_metadata_version()
                .without_metadata_genesis()
                .without_otel_context_injection()
                .connect_lazy::<RpcClient>();
        let rpc = miden_node_rpc::Rpc {
            listener,
            state: Arc::clone(&upstream),
            mode: miden_node_rpc::RpcMode::full_node(source_rpc, 0, None, writer, proof_writer),
            ntx_builder: None,
            grpc_options: Default::default(),
            network_tx_auth: None,
        };
        upstream_task = Some(tokio::spawn(rpc.serve(shutdown.clone())));
        let mut upstream_client = client(upstream_url.clone());
        downstream_directory = Some(tempfile::tempdir()?);
        let downstream_dir = downstream_directory.as_ref().unwrap();
        State::bootstrap(genesis, downstream_dir.path()).await?;
        let (downstream, writer, proof_writer, task) = load_store(downstream_dir.path()).await?;
        downstream_writer = Some(task);
        let rpc = miden_node_rpc::Rpc {
            listener: TcpListener::bind("127.0.0.1:0").await?,
            state: Arc::clone(&downstream),
            mode: miden_node_rpc::RpcMode::full_node(
                client(upstream_url),
                0,
                None,
                writer,
                proof_writer,
            ),
            ntx_builder: None,
            grpc_options: Default::default(),
            network_tx_auth: None,
        };
        downstream_task = Some(tokio::spawn(rpc.serve(shutdown.clone())));
        use tokio_stream::StreamExt;
        let mut blocks = upstream_client
            .block_subscription(
                miden_node_proto::generated::miden::node::v1::BlockSubscriptionRequest {
                    block_from: 1,
                },
            )
            .await
            .context("opening recovered RPC block subscription")?
            .into_inner();
        tokio::time::timeout(Duration::from_secs(5), blocks.next())
            .await
            .context("waiting for recovered RPC block")?
            .context("recovered block stream ended")?
            .context("recovered RPC block stream failed")?;
        drop(blocks);
        let mut proofs = upstream_client
            .proof_subscription(
                miden_node_proto::generated::miden::node::v1::ProofSubscriptionRequest {
                    block_from: 1,
                },
            )
            .await
            .context("opening recovered RPC proof subscription")?
            .into_inner();
        let served = tokio::time::timeout(Duration::from_secs(5), proofs.next())
            .await
            .context("waiting for recovered RPC proof")?
            .context("recovered proof stream ended")?
            .context("recovered RPC proof stream failed")?
            .decode_fields()?;
        ensure!(served.block_num == 1);
        ensure!(served.proof.to_bytes() == proof);
        drop(proofs);
        tokio::time::timeout(
            Duration::from_secs(60),
            downstream
                .subscribe_proven_tip()
                .wait_for(|tip| *tip == BlockNumber::from(1u32)),
        )
        .await
        .with_context(|| {
            format!(
                "waiting for downstream proof: committed={}, proven={}",
                downstream.committed_tip(),
                downstream.proven_tip()
            )
        })??;
        let (header, _) = downstream.view().get_block_header(Some(1.into()), false).await?;
        ensure!(header.as_ref() == Some(block.header()));
        ensure!(downstream.load_proof(1.into()).await? == Some(proof));
        anyhow::Ok(())
    }
    .await;
    shutdown.cancel();
    let mut cleanup = Ok(());
    for task in [upstream_task, downstream_task].into_iter().flatten() {
        let joined = join_server(task).await.and_then(|result| result);
        cleanup = cleanup.and(joined);
    }
    // Writers finish outstanding writes after their RPC owners release the senders.
    for task in [upstream_writer, downstream_writer].into_iter().flatten() {
        let joined = task.await.map_err(anyhow::Error::from);
        cleanup = cleanup.and(joined);
    }
    result.and(cleanup)
}

/// Inject only transport failures; all signatures and input data come from real signing services.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_recovery_preserves_prefix_and_releases_streams() -> anyhow::Result<()> {
    use tokio::sync::Notify;
    let key = super::SigningKey::new();
    let config = miden_node_utils::fee::test_protocol_config();
    let genesis = GenesisState::new(
        vec![],
        miden_node_utils::fee::test_fee_params(),
        0,
        super::validator_config(std::slice::from_ref(&key)),
        config.clone(),
    )
    .into_block()?;
    let validator = start_validator(key, genesis.inner().clone(), config).await?;
    let result = async {
        let mut parent = genesis.inner().header().clone();
        let mut chain = miden_protocol::transaction::PartialBlockchain::default();
        let mut blocks = Vec::new();
        let mut last_request = None;
        for _ in 0..2 {
            let inputs = BlockInputs::new(
                parent.clone(),
                chain.clone(),
                Default::default(),
                Default::default(),
                Default::default(),
            );
            let (header, body) =
                ProposedBlock::new_at(inputs.clone(), vec![], parent.timestamp() + 1)?
                    .into_header_and_body()?;
            let request: miden_node_proto::generated::miden::validator::v1::SignBlockRequest =
                miden_node_proto::SignBlockRequest {
                    tx_batches: OrderedBatches::new(vec![]),
                    block_header: header.clone(),
                    block_inputs: inputs,
                    protocol_config: None,
                }
                .into();
            let response: SignBlockResponse = validator
                .client()
                .sign_block(request.clone())
                .await?
                .into_inner()
                .decode_and_build_unchecked()?;
            let signatures = coalesce_signatures(
                vec![response.signature],
                header.commitment(),
                parent.validator_config(),
            )?;
            blocks.push(SignedBlock::new_unchecked(header.clone(), body, signatures));
            chain.add_block(&parent, false);
            parent = header;
            last_request = Some(request);
        }
        let directory = tempfile::tempdir()?;
        State::bootstrap(
            miden_node_store::genesis::GenesisBlock::new(
                genesis.inner().clone(),
                genesis.protocol_config().clone(),
            )?,
            directory.path(),
        )
        .await?;
        let (state, mut writer, proof_writer, task) = load_store(directory.path()).await?;
        let tested = async {
            let release = Arc::new(Notify::new());
            let proxy =
                start_proxy(validator.client(), Fault::InterruptAfterFirst(release.clone()))
                    .await?;
            let outcome = async {
                let clients = vec![(proxy.url.clone(), proxy.client())];
                let recover =
                    recover_from_validators(&state, &mut writer, clients, CancellationToken::new());
                let interrupt = async {
                    tokio::time::timeout(
                        Duration::from_secs(10),
                        state
                            .subscribe_committed_tip()
                            .wait_for(|tip| *tip == BlockNumber::from(1u32)),
                    )
                    .await??;
                    release.notify_one();
                    anyhow::Ok(())
                };
                let (result, trigger) = tokio::time::timeout(Duration::from_secs(30), async {
                    tokio::join!(recover, interrupt)
                })
                .await?;
                trigger?;
                ensure!(result.is_err());
                ensure!(state.committed_tip() == BlockNumber::from(1u32));
                inputs::load_valid_local_inputs(&state, &blocks[0])
                    .await?
                    .context("lost recovered prefix")?;
                anyhow::Ok(())
            }
            .await;
            proxy.stop().await?;
            outcome?;
            tokio::time::timeout(
                Duration::from_secs(30),
                recover_from_validators(
                    &state,
                    &mut writer,
                    vec![(validator.url.clone(), validator.client())],
                    CancellationToken::new(),
                ),
            )
            .await??;
            ensure!(state.committed_tip() == BlockNumber::from(2u32));
            inputs::load_valid_local_inputs(&state, &blocks[1])
                .await?
                .context("retry lost inputs")?;
            // A completed rerun is a no-op and leaves proofs pending.
            tokio::time::timeout(
                Duration::from_secs(30),
                recover_from_validators(
                    &state,
                    &mut writer,
                    vec![(validator.url.clone(), validator.client())],
                    CancellationToken::new(),
                ),
            )
            .await??;
            ensure!(state.proven_tip() == BlockNumber::GENESIS);
            anyhow::Ok(())
        }
        .await;
        drop(proof_writer);
        writer.stop(task).await;
        tested?;
        drop(state);

        for refuse_setup in [false, true] {
            let target = tempfile::tempdir()?;
            State::bootstrap(
                miden_node_store::genesis::GenesisBlock::new(
                    genesis.inner().clone(),
                    genesis.protocol_config().clone(),
                )?,
                target.path(),
            )
            .await?;
            let (state, mut writer, proof_writer, task) = load_store(target.path()).await?;
            let release = Arc::new(Notify::new());
            let proxy = start_proxy(validator.client(), Fault::Hold(release.clone())).await?;
            let refuse = Arc::new(Notify::new());
            let mut refusing = None;
            let shutdown = CancellationToken::new();
            let tested = async {
                refusing =
                    Some(start_proxy(validator.client(), Fault::Refuse(refuse.clone())).await?);
                let refusing = refusing.as_ref().unwrap();
                let mut clients = vec![(proxy.url.clone(), proxy.client())];
                if refuse_setup {
                    clients.push((refusing.url.clone(), refusing.client()));
                }
                let recover =
                    recover_from_validators(&state, &mut writer, clients, shutdown.clone());
                let cancel = async {
                    tokio::time::timeout(Duration::from_secs(10), proxy.opened.notified()).await?;
                    // A pending drop notification confirms the transport stream is still held.
                    ensure!(
                        tokio::time::timeout(Duration::ZERO, proxy.dropped.notified())
                            .await
                            .is_err()
                    );
                    if refuse_setup {
                        refuse.notify_one();
                    } else {
                        shutdown.cancel();
                    }
                    anyhow::Ok(())
                };
                let (result, trigger) = tokio::time::timeout(Duration::from_secs(30), async {
                    tokio::join!(recover, cancel)
                })
                .await?;
                trigger?;
                ensure!(result.is_err());
                tokio::time::timeout(Duration::from_secs(10), proxy.dropped.notified()).await?;
                release.notify_one();
                // The remote server observes stream cancellation asynchronously. A retained backup
                // lock must still fail this bounded check; service tests check its local lifetime.
                tokio::time::timeout(Duration::from_secs(10), async {
                    let mut retry = tokio::time::interval(Duration::from_millis(10));
                    loop {
                        retry.tick().await;
                        match validator.client().sign_block(last_request.clone().unwrap()).await {
                            Err(error) if error.code() == tonic::Code::ResourceExhausted => {},
                            result => return result,
                        }
                    }
                })
                .await
                .with_context(|| {
                    format!(
                        "backup lock remained held after stream drop (refuse_setup={refuse_setup})"
                    )
                })?
                .with_context(|| {
                    format!("signing after stream drop (refuse_setup={refuse_setup})")
                })?;
                anyhow::Ok(())
            }
            .await;
            shutdown.cancel();
            release.notify_one();
            let stopped = proxy.stop().await;
            let refused = if let Some(refusing) = refusing {
                refusing.stop().await
            } else {
                Ok(())
            };
            drop(proof_writer);
            writer.stop(task).await;
            tested.and(stopped).and(refused)?;
        }
        // Restore-only handler execution must not contact an otherwise valid unreachable prover.
        let unreachable = TcpListener::bind("127.0.0.1:0").await?;
        let prover_url = format!("http://{}", unreachable.local_addr()?);
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "miden-node",
            "recover",
            "--data-directory",
            directory.path().to_str().unwrap(),
            "--validator.url",
            validator.url.as_str(),
            "--block-prover.url",
            &prover_url,
        ])?;
        let crate::commands::Command::Recover(command) = cli.command else {
            unreachable!()
        };
        command.handle(CancellationToken::new()).await?;
        ensure!(tokio::time::timeout(Duration::ZERO, unreachable.accept()).await.is_err());
        anyhow::Ok(())
    }
    .await;
    validator.stop().await?;
    result
}

/// The shared client must receive backups larger than tonic's default decode allowance. Synthetic
/// proof bytes isolate transport capacity without claiming domain validity.
#[tokio::test]
async fn shared_validator_client_receives_large_backup() -> anyhow::Result<()> {
    use miden_node_proto::generated::block_proving;
    use miden_node_proto::generated::miden::validator::v1 as wire;
    use miden_node_proto::prost::Message;
    let mut batch = miden_objects::proto::transaction::ProvenBatch::default();
    batch.proof = Some(miden_objects::proto::primitives::ExecutionProof {
        encoded: vec![7; 5 * 1024 * 1024],
    });
    let response = wire::BlockSubscriptionResponse {
        proving_inputs: Some(block_proving::BlockProofRequest {
            batches: vec![batch],
            ..Default::default()
        }),
        ..Default::default()
    };
    ensure!(response.encoded_len() > 4 * 1024 * 1024);
    let upstream = Builder::new(Url::parse("http://127.0.0.1:1")?)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy();
    let proxy = start_proxy(upstream, Fault::Synthetic(Box::new(response.clone()))).await?;
    let result = async {
        let mut stream = proxy
            .client()
            .block_subscription(wire::BlockSubscriptionRequest { block_from: 0 })
            .await?
            .into_inner();
        ensure!(stream.message().await? == Some(response));
        anyhow::Ok(())
    }
    .await;
    let stopped = proxy.stop().await;
    result?;
    stopped
}
