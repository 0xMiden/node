---
sidebar_position: 0
---

# Introduction

Welcome to the Miden node documentation.

This book provides two separate guides aimed at node operators and developers looking to contribute to the node
respectively. Each guide is standalone, but developers should also read through the operator guide as it provides some
additional context.

At present, the Miden node is the central hub responsible for receiving user transactions and forming them into new
blocks for a Miden network. As Miden decentralizes, the node will morph into the official reference implementation(s) of
the various components required by a fully p2p network.

Each Miden network therefore has exactly one node receiving transactions and creating blocks. The node provides a gRPC
interface for users, dApps, wallets and other clients to submit transactions and query the state.

## Feedback

Please report any issues, ask questions or leave feedback in the node repository
[here](https://github.com/0xMiden/node/issues/new/choose).

This includes outdated, misleading, incorrect or just plain confusing information :)
