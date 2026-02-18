---
sidebar_position: 3
---

# Installation

We provide Debian packages for official releases for the node software. Alternatively, it also can be installed from source on most systems using the Rust package manager `cargo`.

## Debian package

Official Debian packages are available under our [releases](https://github.com/0xMiden/miden-node/releases) page.
Both `amd64` and `arm64` packages are available.

Note that the packages include a `systemd` service which is disabled by default.

To install, download the desired releases `.deb` package and checksum files. Install using

```sh
sudo dpkg -i $package_name.deb
```

You can (and should) verify the checksum prior to installation using a SHA256 utility. This differs from platform to platform, but on most linux distros:

```sh
sha256sum --check $checksum_file.deb.checksum
```

can be used so long as the checksum file and the package file are in the same folder.

## Install using `cargo`

Install Rust version **1.89** or greater using the official Rust installation
[instructions](https://www.rust-lang.org/tools/install).

Depending on the platform, you may need to install additional libraries. For example, on Ubuntu 22.04 the following
command ensures that all required libraries are installed.

```sh
sudo apt install llvm clang bindgen pkg-config libssl-dev libsqlite3-dev
```

On macOS, ensure the Xcode Command Line Tools are installed:

```sh
xcode-select --install
```

If you still see `'cstdint' file not found` errors after installing the Command Line Tools (common after a macOS upgrade), try setting the SDK root explicitly:

```sh
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
```

Install the latest node binary:

```sh
cargo install miden-node --locked
```

This will install the latest official version of the node. You can install a specific version `x.y.z` using

```sh
cargo install miden-node --locked --version x.y.z
```

You can also use `cargo` to compile the node from the source code if for some reason you need a specific git revision.
Note that since these aren't official releases we cannot provide much support for any issues you run into, so consider
this for advanced use only. The incantation is a little different as you'll be targeting our repo instead:

```sh
# Install from a specific branch
cargo install --locked --git https://github.com/0xMiden/miden-node miden-node --branch <branch>

# Install a specific tag
cargo install --locked --git https://github.com/0xMiden/miden-node miden-node --tag <tag>

# Install a specific git revision
cargo install --locked --git https://github.com/0xMiden/miden-node miden-node --rev <git-sha>
```

More information on the various `cargo install` options can be found
[here](https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options).

## Updating

:::warning
We currently have no backwards compatibility guarantees. This means updating your node is destructive - your
existing chain will not work with the new version. This will change as our protocol and database schema mature and
settle.
:::

Updating the node to a new version is as simply as re-running the install process and repeating the [bootstrapping](./usage#bootstrapping) instructions.
