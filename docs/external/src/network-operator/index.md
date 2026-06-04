---
title: "Network Operator Guide"
sidebar_position: 0
---

# Network Operator Guide

This guide is for network operators running the centralized services for a Miden network. This includes the sequencer
and trusted internal services such as the network transaction builder, remote provers, and network monitor.

The validator is covered because the sequencer depends on it for block validation and signing. On official networks, the
validator is operated by a separate entity from the network operator.

It may also be useful if you want to understand how Miden network infrastructure is currently architected and how it
works.

If you want to develop against a disposable local network, use [Local Network Development](/local-network-development).
If you want to run a non-sequencing node for an existing network, use the [Full Node Guide](/full-node/).

Start with [Overview](/network-operator/overview) for the service roles and an example deployment, then use
[Installation](/network-operator/installation) to select the matching binaries or images.
