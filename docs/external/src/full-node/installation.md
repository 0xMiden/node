---
title: "Installation"
sidebar_position: 1
---

<!-- markdownlint-disable MD033 MD041 -->

import Tabs from "@theme/Tabs"; import TabItem from "@theme/TabItem";

# Installation

The Miden node can be installed as a native binary, or as a Docker image.

<Tabs groupId="full-node-runtime" defaultValue="native">
  <TabItem value="native" label="Native binary">

Install the latest node binary from crates.io:

```sh
cargo install miden-node --locked
```

Or install a specific version:

```sh
cargo install miden-node --version <version> --locked
```

Check the installed binary:

```sh
miden-node --help
```

You can also install directly from a repository revision when you need an unreleased version:

```sh
cargo install miden-node --git https://github.com/0xMiden/node.git --rev <revision> --locked
```

Create a data directory for node state:

```sh
mkdir -p full-node-data
```

  </TabItem>
  <TabItem value="docker" label="Docker image">

Pull the published image:

```sh
docker pull ghcr.io/0xmiden/miden-node:<release-tag>
```

Check the image:

```sh
docker run --rm ghcr.io/0xmiden/miden-node:<release-tag> miden-node --help
```

Create a Docker volume for node state:

```sh
docker volume create miden-full-node-data
```

  </TabItem>
</Tabs>

<!-- markdownlint-enable MD033 MD041 -->
