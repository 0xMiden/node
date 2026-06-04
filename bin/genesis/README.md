# Miden genesis

`miden-genesis` is a development tool for generating canonical Miden genesis accounts and genesis configuration. It is
part of the Miden node repository but is not published as a crates.io package.

## Role

The tool creates account artifacts used to prepare a network genesis configuration, including AggLayer bridge and GER
manager accounts. It is useful when preparing genesis inputs for the validator bootstrap workflow.

The validator remains responsible for constructing and signing the actual genesis block.

## Operation

Use the binary help output for the current command and configuration surface. The help output is the source of truth for
flags and environment variables.

For full node bootstrap context and documentation links, see the
[primary README](https://github.com/0xMiden/node#readme).

## License

This project is [MIT licensed](../../LICENSE).
