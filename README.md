# RSDHCP

## Introduction

This is a re-imagining of [pyDHCP](https://github.com/ChrisPortman/pydhcp) developed in Rust
specifically to integrate with [Netbox](https://docs.netbox.dev/en/stable/) via the [netbox-dhcp](https://github.com/ChrisPortman/netbox-dhcp)
plugin for DHCP lease information.

## Building

```console
cd rschcp/
cargo build --release
```

The built binary will be found at `target/release/rsdhcp`.

## Usage

### Pre-Requisites

In Netbox, you need to create the following:

* A user that will be used by *rsdhcp* to access the netbox API.
* A permission that allows View|Add|Change|Delete on *netbox_dhcp | DHCP Lease* and is assigned to
  the above user.
* A write enabled API token for the above user.

### Configuration

`rsdhcp` requires a configuration file that looks like:

```yaml
---
server:
  listen: "0.0.0.0"

backend:
  backend_name: netbox
  base_url: http://localhost:8080
  auth_token: 215e4324a3a621a5ea1619d6c08c6d3b90bf19c9
```

The `base_url` is the base URL at which Netbox is hosted and `auth_token` is the API Token created
in Netbox as described above.

### Running

```console
rsdhcp -c /path/to/config.yaml
```

## Development

This project contains 2 crates:

* `rsdhcp`: The main application code.
* `rsdhcp_macros`: Proc macros that generate code to assist with DHCP option codes and being able to
  go from numeric code to `DhcpOption` with contained data and back again.


### Backends

This project is primarily concerned with integrating with Netbox.  However the DHCP storage backend
is extendible and also includes a *memory* backend, which is purely for testing purposes.  It is
feasible that additional production grade backends be implemented.  A trait is defined that backends
need to implement.
