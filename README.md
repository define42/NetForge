# NetForge

NetForge is a Linux-only Go program that builds and manages VLAN-backed network namespaces, applies nftables policy inside each namespace, and starts a sandboxed plugin child inside every managed namespace. It also exposes a small host dashboard and a per-namespace HTTP service for inspection and testing.

NetForge is designed as appliance software. It is expected to be the only application-level software managing the server's network structure and named namespaces, and it enforces only the topology and namespaces it controls.

## What It Does

- creates named network namespaces
- creates VLAN subinterfaces on a parent NIC and moves them into those namespaces
- configures IP, MAC, gateway, and namespace-local nftables rules
- starts a go-plugin child inside each namespace
- hardens the plugin child with user/mount/pid namespaces, `pivot_root`, dropped capabilities, seccomp, and cgroup v2 placement
- exposes a host dashboard and per-namespace HTTP endpoints

## Requirements

- Linux
- root privileges
- Go toolchain
- nftables support
- network namespace support
- user namespace, mount namespace, pid namespace, and seccomp support
- unified cgroup v2 support

## Security Warning

NetForge is destructive by design.

- It runs as root.
- It should be treated as appliance software and is expected to be the only higher-level system on the server managing named namespaces and the VLAN-backed network layout.
- On startup, it treats the config as authoritative.
- It enforces the configured namespace and network structure and does not accept unrelated named namespaces or parallel namespace management outside its control.
- It removes all named namespaces it finds under `/run/netns`, then recreates only the configured namespaces.
- This includes namespaces NetForge did not create.
- Manual changes inside a configured namespace are not preserved.
- Namespace-local firewall changes are not preserved either; NetForge rewrites the managed firewall state.
- The runtime base is security-sensitive. NetForge always uses `/var/lib/netforge`, and it must remain root-owned and `0700`.

Do not run this on a host where unrelated named namespaces must survive.

## Build

```bash
make build
```

Or:

```bash
CGO_ENABLED=0 go build -o netforge
```

## Test

```bash
make test
```

This runs:

```bash
sudo go test -cover
```

Many integration paths require Linux and root. `go test ./...` is useful for fast iteration, but it does not cover the full namespace lifecycle.

Build the NetForge binary with `CGO_ENABLED=0`. The plugin sandbox intentionally blocks broad `clone3`/process creation paths, so shipping a cgo-enabled binary can break thread startup inside the sandbox.

## Run

```bash
make run
```

Or:

```bash
sudo ./netforge
```

## Configuration

The host process reads these environment variables:

- `PARENT_NIC`: parent interface used to create VLAN subinterfaces. Default: `enp0s31f6`
- `HOST_HTTP_ADDR`: host dashboard address. Default: `127.0.0.1:8090`
- `NS_CONFIG_JSON`: JSON array of namespace configs. If unset, built-in demo defaults are used

NetForge always uses `/var/lib/netforge` as its runtime base.

Example:

```bash
export PARENT_NIC=eth0
export HOST_HTTP_ADDR=127.0.0.1:8090
export NS_CONFIG_JSON='[
  {
    "name": "ns1",
    "vlan_id": 100,
    "if_name": "eth0.100",
    "ip_cidr": "10.10.100.2/24",
    "mac": "02:00:00:00:10:02",
    "gateway": "10.10.100.1",
    "listen_port": 8080,
    "open_ports": [8080],
    "allow_icmp": true
  },
  {
    "name": "ns2",
    "vlan_id": 200,
    "if_name": "eth0.200",
    "ip_cidr": "10.20.0.2/24",
    "mac": "02:00:00:00:20:02",
    "gateway": "",
    "listen_port": 8081,
    "open_ports": [8081],
    "allow_icmp": false
  }
]'

sudo ./netforge
```

If `open_ports` is omitted or `null`, NetForge defaults it to `[listen_port]`. If `open_ports` is an explicit empty array, no TCP ports are opened.

## Default Behavior

If `NS_CONFIG_JSON` is unset, NetForge uses two built-in demo namespaces:

- `ns1` on VLAN `1`
- `ns2` on VLAN `2`

Both are created on the selected parent NIC.

## Dashboard

The host dashboard defaults to:

```text
http://127.0.0.1:8090
```

The dashboard is split into focused pages:

- `/`: namespace overview, ARP table data, and NIC statistics
- `/probes`: ping, TCP port, and SFTP directory checks
- `/sftp-jobs`: scheduled SFTP sync job management
- `/configs`: effective host parameters and namespace config values

Keep it on loopback unless you intentionally add authentication, TLS, or a trusted reverse proxy in front of it.

## Code Layout

- `main.go`: host orchestration, namespace setup, firewall configuration, plugin lifecycle, dashboard
- `sandbox_linux.go`: plugin sandbox bootstrap and seccomp
- `cgroup_linux.go`: plugin cgroup v2 management
- `*_test.go`: unit and Linux integration coverage

## Notes For Contributors

See [`AGENT.md`](./AGENT.md) for repo-specific implementation and security guidance.
