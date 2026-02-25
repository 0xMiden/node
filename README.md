# Miden node

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/miden-node/blob/main/LICENSE)
[![test](https://github.com/0xMiden/miden-node/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/miden-node/actions/workflows/test.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.89+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![crates.io](https://img.shields.io/crates/v/miden-node)](https://crates.io/crates/miden-node)

Welcome to the Miden node implementation :) This software is used to operate a Miden ZK-rollup network by
receiving transactions and sequencing them into blocks.

Access to the network is provided via a gRPC interface which can be found [here](./proto/README.md).

> [!NOTE]
> The Miden node is still under heavy development and the project can be considered to be in an _alpha_ stage.
> Many features are yet to be implemented and there are a number of limitations which we will lift in the near future.
>
> At this point we are developing the Miden node for a centralized operator. As such, the work does not yet include
> components such as P2P networking and consensus. These will be added in the future.

## Documentation

Documentation, tutorials and guides for the current Miden version (aka testnet) can be found
[here](https://0xMiden.github.io/miden-docs/), including an operator manual and gRPC reference guide. This is
your one-stop-shop for all things Miden.

For node operators living on the development edge, we also host the latest unreleased documentation
[here](https://0xMiden.github.io/miden-node/index.html).

The documentation in the `docs/external` folder is built using Docusaurus and is automatically absorbed into the main [miden-docs](https://github.com/0xMiden/miden-docs) repository for the main documentation website. Changes to the `next` branch trigger an automated deployment workflow. The docs folder requires npm packages to be installed before building.

## Contributing

Developer documentation and onboarding guide is available
[here](https://0xMiden.github.io/miden-node/developer/index.html).

At minimum, please see our [contributing](https://github.com/0xMiden/.github?tab=contributing-ov-file) guidelines and our [makefile](Makefile) for example workflows
e.g. run the testsuite using

```sh
make test
```

In particular, please note that we do _not_ accept [low-effort contributions](https://github.com/0xMiden/.github?tab=contributing-ov-file#contribution-quality) or AI generated code. For typos and documentation errors please open an issue instead. 

> [!IMPORTANT]
> PRs will be closed unless you have been assigned an issue by a maintainer.

## License

This project is [MIT licensed](./LICENSE).
