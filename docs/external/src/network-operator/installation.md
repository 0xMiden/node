---
title: "Installation"
sidebar_position: 2
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Installation

Use the same release tag, crate version, or Git revision for every component in a network deployment. Mixing component
versions can leave services with incompatible RPC, storage, or protocol expectations.

## Install Template

<Tabs groupId="network-operator-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

Install a released binary from crates.io. Replace `<component>` with one of the component names below.

```bash
cargo install <component> --version <version> --locked
```

Or install directly from a repository revision:

```bash
cargo install <component> --git https://github.com/0xMiden/node.git --rev <revision> --locked
```

Check the installed binary:

```bash
<component> --help
```

  </TabItem>
  <TabItem value="docker" label="Docker image">

Pull a published image:

```bash
docker pull ghcr.io/0xmiden/<component>:<release-tag>
```

Check the image:

```bash
docker run --rm ghcr.io/0xmiden/<component>:<release-tag> <component> --help
```

  </TabItem>
</Tabs>

## Component Names

- `miden-node`
- `miden-validator`
- `miden-ntx-builder`
- `miden-remote-prover`
- `miden-network-monitor`

You can also build images locally from a repository checkout:

```bash
make docker-build
```

Use `DOCKER_PLATFORM=linux/amd64` or `DOCKER_PLATFORM=linux/arm64` to build a specific local image platform.

<!-- markdownlint-enable MD033 MD041 -->
