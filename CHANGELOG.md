# Changelog

## v0.13.5 (TBD)

- OpenTelemetry traces are now flushed before program termination on panic ([#1643](https://github.com/0xMiden/miden-node/pull/1643)).
- Added support for the note transport layer in the network monitor ([#1660](https://github.com/0xMiden/miden-node/pull/1660)).

## v0.13.4 (2026-02-04)

- Fixed network monitor displaying explorer URL as a "null" hyperlink when unset ([#1617](https://github.com/0xMiden/miden-node/pull/1617)).
- Fixed empty storage maps not being inserted into `storage_entries` table when inserting storage delta ([#1642](https://github.com/0xMiden/miden-node/pull/1642)).

## v0.13.3 (2026-01-29)

- Fixed network monitor faucet test failing to parse `/get_metadata` response due to field type mismatches ([#1612](https://github.com/0xMiden/miden-node/pull/1612)).

## v0.13.2 (2026-01-27)

- Network transaction builder no longer creates conflicting transactions by consuming the same notes twice ([#1597](https://github.com/0xMiden/miden-node/issues/1597)).

## v0.13.1 (2026-01-27)

### Enhancements

- Bootstrap's genesis configuration file now allows eliding `wallet` and `fungible_faucet` fields ([#1590](https://github.com/0xMiden/miden-node/pull/1590)).
- Updated miden-base dependencies to version 0.13.3 ([#1601](https://github.com/0xMiden/miden-node/pull/1601)).

### Fixes

- Bootstrap's genesis configuration file is now optional again ([#1590](https://github.com/0xMiden/miden-node/pull/1590)).
- Network transaction builder fails if output notes are created ([#1599](https://github.com/0xMiden/miden-node/pull/1599)).
- Fixed the copy button in the network monitor ([#1600](https://github.com/0xMiden/miden-node/pull/1600)).
- Network transaction builder now loads foreign account code into the MAST store when consuming network notes ([#1598](https://github.com/0xMiden/miden-node/pull/1598)).

## v0.13.0 (2026-01-23)

### Enhancements

- Added block validation endpoint to validator and integrated with block producer ([#1382](https://github.com/0xMiden/miden-node/pull/1381)).
- Added support for timeouts in the WASM remote prover clients ([#1383](https://github.com/0xMiden/miden-node/pull/1383)).
- Added mempool statistics to the block producer status in the `miden-network-monitor` binary ([#1392](https://github.com/0xMiden/miden-node/pull/1392)).
- Added `GetLimits` endpoint to the RPC server ([#1410](https://github.com/0xMiden/miden-node/pull/1410)).
- Added chain tip to the block producer status ([#1419](https://github.com/0xMiden/miden-node/pull/1419)).
- Added success rate to the `miden-network-monitor` binary ([#1420](https://github.com/0xMiden/miden-node/pull/1420)).
- The mempool's transaction capacity is now configurable ([#1433](https://github.com/0xMiden/miden-node/pull/1433)).
- Added pagination to `GetNetworkAccountIds` store endpoint ([#1452](https://github.com/0xMiden/miden-node/pull/1452)).
- Integrated NTX Builder with validator via `SubmitProvenTransaction` RPC ([#1453](https://github.com/0xMiden/miden-node/pull/1453)).
- Integrated RPC stack with Validator component for transaction validation ([#1457](https://github.com/0xMiden/miden-node/pull/1457)).
- Added partial storage map queries to RPC ([#1428](https://github.com/0xMiden/miden-node/pull/1428)).
- Added explorer status to the `miden-network-monitor` binary ([#1450](https://github.com/0xMiden/miden-node/pull/1450)).
- Added validated transactions check to block validation logic in Validator ([#1460](https://github.com/0xMiden/miden-node/pull/1460)).
- Added gRPC-Web probe support to the `miden-network-monitor` binary ([#1484](https://github.com/0xMiden/miden-node/pull/1484)).
- Added DB schema change check ([#1268](https://github.com/0xMiden/miden-node/pull/1485)).
- Added foreign account support to validator ([#1493](https://github.com/0xMiden/miden-node/pull/1493)).
- Decoupled ntx-builder from block-producer startup by loading network accounts asynchronously via a background task ([#1495](https://github.com/0xMiden/miden-node/pull/1495)).
- Improved DB query performance for account queries ([#1496](https://github.com/0xMiden/miden-node/pull/1496)).
- The network monitor now marks the chain as unhealthy if it fails to create new blocks ([#1512](https://github.com/0xMiden/miden-node/pull/1512)).
- Limited number of storage map keys in `GetAccount` requests ([#1517](https://github.com/0xMiden/miden-node/pull/1517)).
- Block producer now detects if it is desync'd from the store's chain tip and aborts ([#1520](https://github.com/0xMiden/miden-node/pull/1520)).
- Added support for foreign accounts to `NtxDataStore` and add `GetAccount` endpoint to NTX Builder gRPC store client ([#1521](https://github.com/0xMiden/miden-node/pull/1521)).
- Pined tool versions in CI ([#1523](https://github.com/0xMiden/miden-node/pull/1523)).
- Added `GetVaultAssetWitnesses` and `GetStorageMapWitness` RPC endpoints to store ([#1529](https://github.com/0xMiden/miden-node/pull/1529)).
- Added check to ensure tree store state is in sync with database storage ([#1532](https://github.com/0xMiden/miden-node/issues/1534)).

### Changes

- Improved tracing in `miden-network-monitor` binary ([#1366](https://github.com/0xMiden/miden-node/pull/1366)).
- Added support for caching mempool statistics in the block producer server ([#1388](https://github.com/0xMiden/miden-node/pull/1388)).
- Renamed card's names in the `miden-network-monitor` binary ([#1441](https://github.com/0xMiden/miden-node/pull/1441)).
- [BREAKING] Removed `GetAccountDetails` RPC endpoint. Use `GetAccount` instead ([#1185](https://github.com/0xMiden/miden-node/issues/1185)).
- [BREAKING] Renamed `SyncTransactions` response fields ([#1357](https://github.com/0xMiden/miden-node/pull/1357)).
- Normalized response size in endpoints to 4 MB ([#1357](https://github.com/0xMiden/miden-node/pull/1357)).
- [BREAKING] Renamed `ProxyWorkerStatus::address` to `ProxyWorkerStatus::name` ([#1348](https://github.com/0xMiden/miden-node/pull/1348)).
- Added `SyncTransactions` stress test to `miden-node-stress-test` binary ([#1294](https://github.com/0xMiden/miden-node/pull/1294)).
- Removed `trait AccountTreeStorage` ([#1352](https://github.com/0xMiden/miden-node/issues/1352)).
- [BREAKING] `SubmitProvenTransaction` now **requires** that the network's genesis commitment is set in the request's `ACCEPT` header ([#1298](https://github.com/0xMiden/miden-node/pull/1298), [#1436](https://github.com/0xMiden/miden-node/pull/1436)).
- Added `S` generic to `NullifierTree` to allow usage with `LargeSmt`s ([#1353](https://github.com/0xMiden/miden-node/issues/1353)).
- Refactored account table and introduce tracking forest ([#1394](https://github.com/0xMiden/miden-node/pull/1394)).
- [BREAKING] Re-organized RPC protobuf schema to be independent of internal schema ([#1401](https://github.com/0xMiden/miden-node/pull/1401)).
- Removed internal errors from the `miden-network-monitor` ([#1424](https://github.com/0xMiden/miden-node/pull/1424)).
- [BREAKING] Added block signing capabilities to Validator component and updated gensis bootstrap to sign blocks with configured signer ([#1426](https://github.com/0xMiden/miden-node/pull/1426)).
- Track network transactions latency in `miden-network-monitor` ([#1430](https://github.com/0xMiden/miden-node/pull/1430)).
- Reduced default block interval from `5s` to `2s` ([#1438](https://github.com/0xMiden/miden-node/pull/1438)).
- Increased retained account tree history from 33 to 100 blocks to account for the reduced block interval ([#1438](https://github.com/0xMiden/miden-node/pull/1438)).
- Increased the maximum query limit for the store ([#1443](https://github.com/0xMiden/miden-node/pull/1443)).
- [BREAKING] Migrated to version `v0.20` of the VM ([#1476](https://github.com/0xMiden/miden-node/pull/1476)).
- [BREAKING] Change account in database representation ([#1481](https://github.com/0xMiden/miden-node/pull/1481)).
- Remove the cyclic database optimization ([#1497](https://github.com/0xMiden/miden-node/pull/1497)).
- Fix race condition at DB shutdown in tests ([#1503](https://github.com/0xMiden/miden-node/pull/1503)).
- [BREAKING] Updated to new miden-base protocol: removed `aux` and `execution_hint` from `NoteMetadata`, removed `NoteExecutionMode`, and `NoteMetadata::new()` is now infallible ([#1526](https://github.com/0xMiden/miden-node/pull/1526)).
- [BREAKING] Network note queries now use full account ID instead of 30-bit prefix ([#1572](https://github.com/0xMiden/miden-node/pull/1572)).
- [BREAKING] Renamed `SyncStorageMaps` RPC endpoint to `SyncAccountStorageMaps` for consistency ([#1581](https://github.com/0xMiden/miden-node/pull/1581)).
- Removed git information from node's `--version` CLI as it was often incorrect ([#1576](https://github.com/0xMiden/miden-node/pull/1576)).
- [BREAKING] Renamed `GetNetworkAccountDetailsByPrefix` endpoint to `GetNetworkAccountDetailsById` which now accepts full account ID instead of 30-bit prefix ([#1580](https://github.com/0xMiden/miden-node/pull/1580)).
- Ensure store terminates on nullifier tree or account tree root vs header mismatch (#[#1569](https://github.com/0xMiden/miden-node/pull/1569)).

### Fixes

- RPC client now correctly sets `genesis` value in `ACCEPT` header if `version` is unspecified ([#1370](https://github.com/0xMiden/miden-node/pull/1370)).
- Pin protobuf (`protox`) dependencies to avoid breaking changes in transitive dependency ([#1403](https://github.com/0xMiden/miden-node/pull/1403)).
- Fixed no-std compatibility for remote prover clients ([#1407](https://github.com/0xMiden/miden-node/pull/1407)).
- Fixed `AccountProofRequest` to retrieve the latest known state in case specified block number (or chain tip) does not contain account updates ([#1422](https://github.com/0xMiden/miden-node/issues/1422)).
- Fixed missing asset setup for full account initialization ([#1461](https://github.com/0xMiden/miden-node/pull/1461)).
- Fixed `GetNetworkAccountIds` pagination to return the chain tip ([#1489](https://github.com/0xMiden/miden-node/pull/1489)).
- Fixed the network monitor counter account to use the storage slot name ([#1501](https://github.com/0xMiden/miden-node/pull/1501)).
- gRPC traces now correctly connect to the method implementation ([1553](https://github.com/0xMiden/miden-node/pull/1553)).
- Fixed ntx-builder crash on node restart after network transaction by adding missing `is_latest` filter to network account query ([#1578](https://github.com/0xMiden/miden-node/pull/1578)).

## v0.12.8 (2026-01-15)

### Enhancements

- Enable traces within database closures ([#1511](https://github.com/0xMiden/miden-node/pull/1511)).

## v0.12.7 (2026-01-15)

### Enhancements

- Emit database table size metrics ([#1511](https://github.com/0xMiden/miden-node/pull/1511)).
- Improved telemetry in the network transaction builder ([#1508](https://github.com/0xMiden/miden-node/pull/1508)).
- Improved telemetry in the store's `apply_block` ([#1508](https://github.com/0xMiden/miden-node/pull/1508)).

### Fixes

- Network transaction builder now marks notes from any error as failed ([#1508](https://github.com/0xMiden/miden-node/pull/1508)).
- Network transaction builder now adheres to note limit set by protocol ([#1508](https://github.com/0xMiden/miden-node/pull/1508)).
- Race condition resolved in the store's `apply_block` ([#1508](https://github.com/0xMiden/miden-node/pull/1508)).
  - This presented as a database locked error and in rare cases a desync between the mempool and store. 

## v0.12.6 (2026-01-12)

### Enhancements

- Added Faucet metadata to the `miden-network-monitor` binary ([#1373](https://github.com/0xMiden/miden-node/pull/1373)).
- Improve telemetry in the store ([#1504](https://github.com/0xMiden/miden-node/pull/1504)).

### Fixes

- Block producer crash caused by pass through transactions ([#1396](https://github.com/0xMiden/miden-node/pull/1396)).

## v0.12.5 (2025-11-27)

- Actually update `miden-base` dependencies ([#1384](https://github.com/0xMiden/miden-node/pull/1384)).

## v0.12.4 (2025-11-27)

- Split counter increment and tracking services in `miden-network-monitor` binary ([#1362](https://github.com/0xMiden/miden-node/pull/1362)).
- Updated the counter account from the `miden-network-monitor` to start at 0 ([#1367](https://github.com/0xMiden/miden-node/pull/1367)).
- Updated  `miden-base` dependencies to fix ECDSA issues ([#1382](https://github.com/0xMiden/miden-node/pull/1382)).

## v0.12.3 (2025-11-15)

- Added configurable timeout support to `RemoteBatchProver`, `RemoteBlockProver`, and `RemoteTransactionProver` clients ([#1365](https://github.com/0xMiden/miden-node/pull/1365)).
- Added configurable timeout support to `miden-network-monitor` binary ([#1365](https://github.com/0xMiden/miden-node/pull/1365)).

## v0.12.2 (2025-11-12)

- Fixed `PoW` challenge solving in `miden-network-monitor` binary ([#1363](https://github.com/0xMiden/miden-node/pull/1363)).

## v0.12.1 (2025-11-08)

- Added support for network transaction service in `miden-network-monitor` binary ([#1295](https://github.com/0xMiden/miden-node/pull/1295)).
- Improves `.env` file example in for the `miden-network-monitor` binary ([#1345](https://github.com/0xMiden/miden-node/pull/1345)).

## v0.12.0 (2025-11-06)

### Changes

- [BREAKING] Updated MSRV to 1.90.
- [BREAKING] Refactored `CheckNullifiersByPrefix` endpoint adding pagination ([#1191](https://github.com/0xMiden/miden-node/pull/1191)).
- [BREAKING] Renamed `CheckNullifiersByPrefix` endpoint to `SyncNullifiers` ([#1191](https://github.com/0xMiden/miden-node/pull/1191)).
- Added `GetNoteScriptByRoot` gRPC endpoint for retrieving a note script by its root ([#1196](https://github.com/0xMiden/miden-node/pull/1196)).
- [BREAKING] Added `block_range` and `pagination_info` fields to paginated gRPC endpoints ([#1205](https://github.com/0xMiden/miden-node/pull/1205)).
- Implemented usage of `tonic` error codes for gRPC errors ([#1208](https://github.com/0xMiden/miden-node/pull/1208)).
- [BREAKING] Replaced `GetAccountProofs` with `GetAccountProof` in the public store API (#[1211](https://github.com/0xMiden/miden-node/pull/1211)).
- Implemented storage map `DataStore` function ([#1226](https://github.com/0xMiden/miden-node/pull/1226)).
- [BREAKING] Refactored the mempool to use a single DAG across transactions and batches ([#1234](https://github.com/0xMiden/miden-node/pull/1234)).
- [BREAKING] Renamed `RemoteProverProxy` to `RemoteProverClient` ([#1236](https://github.com/0xMiden/miden-node/pull/1236)).
- Added pagination to `SyncNotes` endpoint ([#1257](https://github.com/0xMiden/miden-node/pull/1257)).
- Added application level error in gRPC endpoints ([#1266](https://github.com/0xMiden/miden-node/pull/1266)).
- Added `deploy-account` command to `miden-network-monitor` binary ([#1276](https://github.com/0xMiden/miden-node/pull/1276)).
- [BREAKING] Response type nuances of `GetAccountProof` in the public store API (#[1277](https://github.com/0xMiden/miden-node/pull/1277)).
- Add optional `TransactionInputs` field to `SubmitProvenTransaction` endpoint for transaction re-execution (#[1278](https://github.com/0xMiden/miden-node/pull/1278)).
- Added `validator` crate with initial protobuf, gRPC server, and sub-command (#[1293](https://github.com/0xMiden/miden-node/pull/1293)).
- [BREAKING] Added `AccountTreeWithHistory` and integrate historical queries into `GetAccountProof` ([#1292](https://github.com/0xMiden/miden-node/pull/1292)).
- [BREAKING] Added `rocksdb` feature to enable rocksdb backends of `LargeSmt` ([#1326](https://github.com/0xMiden/miden-node/pull/1326)).
- [BREAKING] Handle past/historical `AccountProof` requests ([#1333](https://github.com/0xMiden/miden-node/pull/1333)).
- Implement `DataStore::get_note_script()` for `NtxDataStore` (#[1332](https://github.com/0xMiden/miden-node/pull/1332)).
- Started validating notes by their commitment instead of ID before entering the mempool ([#1338](https://github.com/0xMiden/miden-node/pull/1338)).

## v0.11.3 (2025-11-04)

- Reduced note retries to 1 ([#1308](https://github.com/0xMiden/miden-node/pull/1308)).
- Address network transaction builder (NTX) invariant breaking for unavailable accounts ([#1312](https://github.com/0xMiden/miden-node/pull/1312)).
- Tweaked HTTP configurations on the pingora proxy server ([#1281](https://github.com/0xMiden/miden-node/pull/1281)).
- Added the counter increment task to `miden-network-monitor` binary ([#1295](https://github.com/0xMiden/miden-node/pull/1295)).

## v0.11.2 (2025-09-10)

- Added support for keepalive requests against base path `/` of RPC server ([#1212](https://github.com/0xMiden/miden-node/pull/1212)).
- [BREAKING] Replace `GetAccountProofs` with `GetAccountProof` in the public store API ([#1211](https://github.com/0xMiden/miden-node/pull/1211)).
- [BREAKING] Optimize `GetAccountProof` for small accounts ([#1185](https://github.com/0xMiden/miden-node/pull/1185)).

## v0.11.1 (2025-09-08)

- Removed decorators from scripts when submitting transactions and batches, and inserting notes into the DB ([#1194](https://github.com/
0xMiden/miden-node/pull/1194)).
- Refresh `miden-base` dependencies.
- Added `SyncTransactions` gRPC endpoint for retrieving transactions for specific accounts within a block range ([#1224](https://github.com/0xMiden/miden-node/pull/1224)).
- Added `miden-network-monitor` binary for monitoring the Miden network ([#1217](https://github.com/0xMiden/miden-node/pull/1217)).

## v0.11.0 (2025-08-28)

### Enhancements

- Added environment variable support for batch and block size CLI arguments ([#1081](https://github.com/0xMiden/miden-node/pull/1081)).
- RPC accept header now supports specifying the genesis commitment in addition to the RPC version. This lets clients ensure they are on the right network ([#1084](https://github.com/0xMiden/miden-node/pull/1084)).
- A transaction's account delta is now checked against its commitments in `SubmitProvenTransaction` endpoint ([#1093](https://github.com/0xMiden/miden-node/pull/1093)).
- Added check for Account Id prefix uniqueness when transactions to create accounts are submitted to the mempool ([#1094](https://github.com/0xMiden/miden-node/pull/1094)).
- Added benchmark CLI sub-command for the `miden-store` component to measure the state load time ([#1154](https://github.com/0xMiden/miden-node/pull/1154)).
- Retry failed network notes with exponential backoff instead of immediately ([#1116](https://github.com/0xMiden/miden-node/pull/1116))
- Network notes are now dropped after failing 30 times ([#1116](https://github.com/0xMiden/miden-node/pull/1116))
- gRPC server timeout is now configurable (defaults to `10s`) ([#1133](https://github.com/0xMiden/miden-node/pull/1133))
- [BREAKING] Refactored protobuf messages ([#1045](https://github.com/0xMiden/miden-node/pull/#1045)).
- Added `SyncStorageMaps` gRPC endpoint for retrieving account storage maps ([#1140](https://github.com/0xMiden/miden-node/pull/1140), [#1132](https://github.com/0xMiden/miden-node/pull/1132)).
- Added `SyncAccountVault` gRPC endpoints for retrieving account assets ([#1176](https://github.com/0xMiden/miden-node/pull/1176)).
- Refactored Network Transaction Builder to manage dedicated tasks for every network account in the chain ([#1219](https://github.com/0xMiden/miden-node/pull/1219)).

### Changes

- [BREAKING] Updated MSRV to 1.88.
- [BREAKING] De-duplicate storage of code in DB (no-migration) ([#1083](https://github.com/0xMiden/miden-node/issue/#1083)).
- [BREAKING] RPC accept header format changed from `application/miden.vnd+grpc.<version>` to `application/vnd.miden; version=<version>` ([#1084](https://github.com/0xMiden/miden-node/pull/1084)).
- [BREAKING] Integrated `FeeParameters` into block headers. ([#1122](https://github.com/0xMiden/miden-node/pull/1122)).
- [BREAKING] Genesis configuration now supports fees ([#1157](https://github.com/0xMiden/miden-node/pull/1157)).
  - Configure `NativeFaucet`, which determines the native asset used to pay fees
  - Configure the base verification fee
  - Note: fees are not yet activated, and this has no impact beyond setting these values in the block headers
- [BREAKING] Remove public store API `GetAccountStateDelta` ([#1162](https://github.com/0xMiden/miden-node/pull/1162)).
- Removed `faucet` binary ([#1172](https://github.com/0xMiden/miden-node/pull/1172)).
- Add `genesis_commitment` in `Status` response ([#1181](https://github.com/0xMiden/miden-node/pull/1181)).

### Fixes

- [BREAKING] Integrated proxy status endpoint into main proxy service, removing separate status port.
- RPC requests with wildcard (`*/*`) media-type are not longer rejected ([#1084](https://github.com/0xMiden/miden-node/pull/1084)).
- Stress-test CLI account now properly sets the storage mode and increment nonce in transactions ([#1113](https://github.com/0xMiden/miden-node/pull/1113)).
- [BREAKING] Update `notes` table schema to have a nullable `consumed_block_num` ([#1100](https://github.com/0xMiden/miden-node/pull/1100)).
- Network Transaction Builder now correctly discards non-single-target network notes instead of panicking ([#1166](https://github.com/0xMiden/miden-node/pull/1166)).

### Removed

- Moved the `miden-faucet` binary to the [`miden-faucet` repository](https://github.com/0xmiden/miden-faucet) ([#1179](https://github.com/0xMiden/miden-node/pull/1179)).

## v0.10.1 (2025-07-14)

### Fixes

- Network accounts are no longer disabled after one transaction ([#1086](https://github.com/0xMiden/miden-node/pull/1086)).

## v0.10.0 (2025-07-10)

### Enhancements

- Added `miden-proving-service` and `miden-proving-service-client` crates (#926).
- Added support for gRPC server side reflection to all components (#949).
- Added support for TLS to `miden-proving-service-client` (#968).
- Added support for TLS to faucet's connection to node RPC (#976).
- Replaced integer-based duration args with human-readable duration strings (#998 & #1014).
- [BREAKING] Refactor the `miden-proving-service` proxy status service to use gRPC instead of HTTP (#953).
- Genesis state is now configurable during bootstrapping (#1000)
- Added configurable network id for the faucet (#1016).
- Network transaction builder now tracks inflight txs instead of only committed ones (#1051).
- Add open-telemetry trace layers to `miden-remote-prover` and `miden-remote-prover-proxy` (#1061).
- Add open-telemetry stats for the mempool (#1073).
- Add open-telemetry stats for the network transaction builder state (#1073).

### Changes

- Faucet `PoW` difficulty is now configurable (#924).
- Separated the store API into three separate services (#932).
- Added a faucet Dockerfile (#933).
- Exposed `miden-proving-service` as a library (#956).
- [BREAKING] Update `RemoteProverError::ConnectionFailed` variant to contain `Error` instead of `String` (#968).
- [BREAKING] Replace faucet TOML configuration file with flags and env vars (#976).
- [BREAKING] Replace faucet Init command with CreateApiKeys command (#976).
- [BREAKING] Consolidate default account filepath for bundled bootstrap and faucet start commands to `account.mac` (#976).
- [BREAKING] Remove default value account filepath for faucet commands and rename --output-path to --output (#976).
- [BREAKING] Enforce `PoW` on all faucet API key-authenticated requests (#974).
- Compressed faucet background image (#985).
- Remove faucet rate limiter by IP and API Key, this has been superseded by PoW (#1011).
- Transaction limit per batch is now configurable (default 8) (#1015).
- Batch limit per block is now configurable (default 8) (#1015).
- Faucet challenge expiration time is now configurable (#1017).
- Removed system monitor from node binary (#1019).
- [BREAKING] Renamed `open_telemetry` to `enable_otel` in all node's commands (#1019).
- [BREAKING] Rename `miden-proving-service` to `miden-remote-prover` (#1004).
- [BREAKING] Rename `miden-proving-service-client` to `miden-remote-prover-client` (#1004).
- [BREAKING] Rename `RemoteProverError` to `RemoteProverClientError` (#1004).
- [BREAKING] Rename `ProvingServiceError` to `RemoteProverError` (#1004).
- [BREAKING] Renamed `Note` to `CommittedNote`, and `NetworkNote` to `Note` in the proto messages (#1022).
- [BREAKING] Limits of store queries per query parameter enforced (#1028).
- Support gRPC server reflection `v1alpha` (#1036).
- Migrate from `rusqlite` to `diesel` as a database abstraction (#921)

### Fixes

- Faucet considers decimals when minting token amounts (#962).

## v0.9.2 (2025-06-12)

- Refresh Cargo.lock file.

## v0.9.1 (2025-06-10)

- Refresh Cargo.lock file (#944).

## v0.9.0 (2025-05-30)

### Enhancements

- Enabled running RPC component in `read-only` mode (#802).
- Added gRPC `/status` endpoint on all components (#817).
- Block producer now emits network note information (#833).
- Introduced Network Transaction Builder (#840).
- Added way of executing and proving network transactions (#841).
- [BREAKING] Add HTTP ACCEPT header layer to RPC server to enforce semver requirements against client connections (#844).

### Changes

- [BREAKING] Simplified node bootstrapping (#776).
  - Database is now created during bootstrap process instead of on first startup.
  - Data directory is no longer created but is instead expected to exist.
  - The genesis block can no longer be configured which also removes the `store dump-genesis` command.
- [BREAKING] Use `AccountTree` and update account witness proto definitions (#783).
- [BREAKING] Update name of `ChainMmr` to `PartialBlockchain` (#807).
- Added `--enable-otel` and `MIDEN_FAUCET_ENABLE_OTEL` flag to faucet (#834).
- Faucet now supports the usage of a remote transaction prover (#830).
- Added a required Proof-of-Work in the faucet to request tokens (#831).
- Added an optional API key request parameter to skip PoW in faucet (#839).
- Proof-of-Work difficulty is now adjusted based on the number of concurrent requests (#865).
- Added options for configuring NTB in `bundled` command (#884).
- [BREAKING] Updated MSRV to 1.87.

### Fixes

- Prevents duplicated note IDs (#842).

## v0.8.2 (2025-05-04)

### Enhancements

- gRPC error messages now include more context (#819).
- Faucet now detects and recovers from state desync (#819).
- Faucet implementation is now more robust (#819).
- Faucet now supports TLS connection to the node RPC (#819).

### Fixes

- Faucet times out during high load (#819).

## v0.8.0 (2025-03-26)

### Enhancements

- Implemented database optimization routine (#721).

### Fixes

- Faucet webpage is missing `background.png` and `favicon.ico` (#672).

### Enhancements

- Add an optional open-telemetry trace exporter (#659, #690).
- Support tracing across gRPC boundaries using remote tracing context (#669).
- Instrument the block-producer's block building process (#676).
- Use `LocalBlockProver` for block building (#709).
- Initial developer and operator guides covering monitoring (#699).
- Instrument the block-producer's batch building process (#738).
- Optimized database by adding missing indexes (#728).
- Added support for `Content-type` header in `get_tokens` endpoint of the faucet (#754).
- Block frequency is now configurable (#750).

### Changes

- [BREAKING] `Endpoint` configuration simplified to a single string (#654).
- Added stress test binary with seed-store command (#657).
- [BREAKING] `CheckNullifiersByPrefix` now takes a starting block number (#707).
- [BREAKING] Removed nullifiers from `SyncState` endpoint (#708).
- [BREAKING] Update `GetBlockInputs` RPC (#709).
- [BREAKING] Added `batch_prover_url` to block producer configuration (#701).
- [BREAKING] Added `block_prover_url` to block producer configuration (#719).
- [BREAKING] Removed `miden-rpc-proto` and introduced `miden-node-proto-build` (#723).
- [BREAKING] Updated to Rust Edition 2024 (#727).
- [BREAKING] MSRV bumped to 1.85 (#727).
- [BREAKING] Replaced `toml` configuration with CLI (#732).
- [BREAKING] Renamed multiple `xxx_hash` to `xxx_commitment` in RPC API (#757).

### Enhancements

- Prove transaction batches using Rust batch prover reference implementation (#659).

## v0.7.2 (2025-01-29)

### Fixes

- Faucet webpage rejects valid account IDs (#655).

## v0.7.1 (2025-01-28)

### Fixes

- Faucet webpage fails to load styling (index.css) and script (index.js) (#647).

### Changes

- [BREAKING] Default faucet endpoint is now public instead of localhost (#647).

## v0.7.0 (2025-01-23)

### Enhancements

- Support Https in endpoint configuration (#556).
- Upgrade `block-producer` from FIFO queue to mempool dependency graph (#562).
- Support transaction expiration (#582).
- Improved RPC endpoints doc comments (#620).

### Changes

- Standardized protobuf type aliases (#609).
- [BREAKING] Added support for new two `Felt` account ID (#591).
- [BREAKING] Inverted `TransactionInputs.missing_unauthenticated_notes` to `found_missing_notes` (#509).
- [BREAKING] Remove store's `ListXXX` endpoints which were intended for test purposes (#608).
- [BREAKING] Added support for storage maps on `GetAccountProofs` endpoint (#598).
- [BREAKING] Removed the `testing` feature (#619).
- [BREAKING] Renamed modules to singular (#636).

## v0.6.0 (2024-11-05)

### Enhancements

- Added `GetAccountProofs` endpoint (#506).

### Changes

- [BREAKING] Added `kernel_root` to block header's protobuf message definitions (#496).
- [BREAKING] Renamed `off-chain` and `on-chain` to `private` and `public` respectively for the account storage modes (#489).
- Optimized state synchronizations by removing unnecessary fetching and parsing of note details (#462).
- [BREAKING] Changed `GetAccountDetailsResponse` field to `details` (#481).
- Improve `--version` by adding build metadata (#495).
- [BREAKING] Introduced additional limits for note/account number (#503).
- [BREAKING] Removed support for basic wallets in genesis creation (#510).
- Migrated faucet from actix-web to axum (#511).
- Changed the `BlockWitness` to pass the inputs to the VM using only advice provider (#516).
- [BREAKING] Improved store API errors (return "not found" instead of "internal error" status if requested account(s) not found) (#518).
- Added `AccountCode` as part of `GetAccountProofs` endpoint response (#521).
- [BREAKING] Migrated to v0.11 version of Miden VM (#528).
- Reduce cloning in the store's `apply_block` (#532).
- [BREAKING] Changed faucet storage type in the genesis to public. Using faucet from the genesis for faucet web app. Added support for faucet restarting without blockchain restarting (#517).
- [BREAKING] Improved `ApplyBlockError` in the store (#535).
- [BREAKING] Updated minimum Rust version to 1.82.

## 0.5.1 (2024-09-12)

### Enhancements

- Node component server startup is now coherent instead of requiring an arbitrary sleep amount (#488).

## 0.5.0 (2024-08-27)

### Enhancements

- [BREAKING] Configuration files with unknown properties are now rejected (#401).
- [BREAKING] Removed redundant node configuration properties (#401).
- Support multiple inflight transactions on the same account (#407).
- Now accounts for genesis are optional. Accounts directory will be overwritten, if `--force` flag is set (#420).
- Added `GetAccountStateDelta` endpoint (#418).
- Added `CheckNullifiersByPrefix` endpoint (#419).
- Added `GetNoteAuthenticationInfo` endpoint (#421).
- Added `SyncNotes` endpoint (#424).
- Added `execution_hint` field to the `Notes` table (#441).

### Changes

- Improve type safety of the transaction inputs nullifier mapping (#406).
- Embed the faucet's static website resources (#411).
- CI check for proto file consistency (#412).
- Added warning on CI for `CHANGELOG.md` (#413).
- Implemented caching of SQL statements (#427).
- Updates to `miden-vm` dependency to v0.10 and `winterfell` dependency to v0.9 (#457).
- [BREAKING] Updated minimum Rust version to 1.80 (#457).

### Fixes

- `miden-node-proto`'s build script always triggers (#412).

## 0.4.0 (2024-07-04)

### Features

- Changed sync endpoint to return a list of committed transactions (#377).
- Added `aux` column to notes table (#384).
- Changed state sync endpoint to return a list of `TransactionSummary` objects instead of just transaction IDs (#386).
- Added support for unauthenticated transaction notes (#390).

### Enhancements

- Standardized CI and Makefile across Miden repositories (#367)
- Removed client dependency from faucet (#368).
- Fixed faucet note script so that it uses the `aux` input (#387).
- Added crate to distribute node RPC protobuf files (#391).
- Add `init` command for node and faucet (#392).

## 0.3.0 (2024-05-15)

- Added option to mint public notes in the faucet (#339).
- Renamed `note_hash` into `note_id` in the database (#336)
- Changed `version` and `timestamp` fields in `Block` message to `u32` (#337).
- [BREAKING] Implemented `NoteMetadata` protobuf message (#338).
- Added `GetBlockByNumber` endpoint (#340).
- Added block authentication data to the `GetBlockHeaderByNumber` RPC (#345).
- Enabled support for HTTP/1.1 requests for the RPC component (#352).

## 0.2.1 (2024-04-27)

- Combined node components into a single binary (#323).

## 0.2.0 (2024-04-11)

- Implemented Docker-based node deployment (#257).
- Improved build process (#267, #272, #278).
- Implemented Nullifier tree wrapper (#275).
- [BREAKING] Added support for public accounts (#287, #293, #294).
- [BREAKING] Added support for public notes (#300, #310).
- Added `GetNotesById` endpoint (#298).
- Implemented amd64 debian packager (#312).

## 0.1.0 (2024-03-11)

- Initial release.
