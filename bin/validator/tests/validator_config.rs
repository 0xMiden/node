use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use miden_node_store::GenesisState;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::block::ValidatorConfig;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey;
use miden_validator::{
    EncodedGoldenOperatorKey,
    LocalX25519TransactionInputDecrypter,
    PrivateRecordSealer,
    ValidatorAdminServer,
    ValidatorServer,
    ValidatorSigner,
    db,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

async fn admin_server(
    path: &Path,
    signer: SigningKey,
    validator_config: ValidatorConfig,
    address: SocketAddr,
) -> anyhow::Result<ValidatorAdminServer> {
    let (genesis, protocol) =
        GenesisState::new(vec![], test_fee_params(), 0, validator_config, test_protocol_config())
            .into_block()?
            .into_parts();
    db::bootstrap(path.into(), miden_node_db::default_connection_pool_size(), genesis, protocol)
        .await?;
    let operator = EncodedGoldenOperatorKey::from_bytes(include_bytes!(
        "../../../scripts/testdata/insecure-storage-key/validator-1/storage-key.bundle"
    ))?
    .decode()?;
    let validator = ValidatorServer {
        address,
        grpc_options: GrpcOptions::default(),
        signer: ValidatorSigner::new_local(signer),
        decrypter: Arc::new(LocalX25519TransactionInputDecrypter::new(KeyExchangeKey::new())),
        private_record_sealer: PrivateRecordSealer::from_operator_key(&operator),
        db: db::load(path.into()).await?,
        signing_lock: Arc::default(),
    };
    Ok(ValidatorAdminServer::new(address, operator, &validator))
}

fn run(url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_miden-validator"))
        .arg("validator-config")
        .args(args)
        .env("VALIDATOR_ADMIN_URL", url)
        .output()
        .unwrap()
}

fn success(output: Output) -> Vec<u8> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_inspect_and_cancel_a_change() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/", listener.local_addr()?);
    let signer = SigningKey::new();
    let other = SigningKey::new().public_key();
    let stale = json!({"keys": [signer.public_key().to_string()], "quorum": 1});
    let validator_config = ValidatorConfig::new(vec![signer.public_key(), other], 2)?;
    let keys = validator_config.keys().iter().map(ToString::to_string).collect::<Vec<_>>();
    let active = json!({"keys": keys, "quorum": 2});
    let mut next_keys = keys;
    next_keys.push(SigningKey::new().public_key().to_string());
    next_keys.sort();
    let pending = json!({"keys": next_keys, "quorum": 3});
    let server = admin_server(
        &directory.path().join("validator.sqlite3"),
        signer,
        validator_config,
        listener.local_addr()?,
    )
    .await?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let status = || serde_json::from_slice::<Value>(&success(run(&url, &["status"])));

    let mut change = status()?;
    assert_eq!(change, json!({"active": active, "pending": null}));
    let file = directory.path().join("change.json");
    let filename = file.to_str().unwrap();
    let register = || run(&url, &["register", filename]);
    let cancel = || run("http://127.0.0.1:0", &["cancel", filename, "--admin-url", &url]);
    change["pending"] = pending;
    fs_err::write(&file, serde_json::to_vec(&change)?)?;
    success(register());
    assert_eq!(status()?, change);

    let mut stale_change = change.clone();
    stale_change["active"] = stale;
    fs_err::write(&file, serde_json::to_vec(&stale_change)?)?;
    for conflict in [register(), cancel()] {
        assert!(!conflict.status.success());
        let message = String::from_utf8(conflict.stderr)?;
        assert!(message.contains("409 Conflict"), "{message}");
        assert!(message.contains("`active` does not match"), "{message}");
    }

    stale_change["pending"] = active.clone();
    fs_err::write(&file, serde_json::to_vec(&stale_change)?)?;
    let conflict = cancel();
    assert!(!conflict.status.success());
    let message = String::from_utf8(conflict.stderr)?;
    assert!(message.contains("already active"), "{message}");
    assert_eq!(status()?, change);

    fs_err::write(&file, serde_json::to_vec(&change)?)?;
    success(cancel());
    assert_eq!(status()?, json!({"active": active, "pending": null}));
    shutdown.cancel();
    task.await??;
    Ok(())
}
