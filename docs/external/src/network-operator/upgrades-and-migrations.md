---
title: "Upgrades and Migrations"
sidebar_position: 9
---

# Upgrades and Migrations

Live network upgrades are not supported yet. At the moment, official network upgrades still reset the network rather
than preserving and migrating live network state across protocol versions.

Operators should still understand the service lifecycle because stateful services must initialize local storage once and
may need storage migrations after upgrading to a newer version.

## Lifecycle Commands

Stateful services follow the same general lifecycle:

```bash
<binary> bootstrap --data-directory <data-directory> ...
<binary> migrate   --data-directory <data-directory>
<binary> <mode-or-start> --data-directory <data-directory> ...
```

`bootstrap` is a one-time initialization step for an empty data directory. It anchors the service to a trusted genesis
block. See [Bootstrap and Genesis](/network-operator/bootstrap-and-genesis) for the network bootstrap flow.

`migrate` applies storage migrations required by the installed binary. Run it after upgrading a stateful service binary
and before starting that service with the upgraded version. It cannot be run on an empty data directory; bootstrap must
have completed first.

## Stateful Services

The stateful services are:

- sequencer nodes
- full nodes
- validators
- network transaction builders

Remote provers and the network monitor do not participate in the genesis bootstrap flow. Upgrade them by replacing the
binary or image and restarting the service with the desired configuration.

## Migration Notes

Stop a service before running migrations. Live migrations are not supported.

Backwards migrations are not supported. If a data directory is older than the minimum supported schema version for the
target binary, migrate forward in stages with older compatible binaries first.

Take backups before running migrations against production data directories.
