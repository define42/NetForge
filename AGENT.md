# AGENT.md

## Overview

NetForge is a Linux-only Go program that:

- creates and reconciles named network namespaces
- creates VLAN-backed interfaces and moves them into those namespaces
- applies nftables firewall policy inside each namespace
- starts a HashiCorp go-plugin child inside each namespace
- hardens that child with user/mount/pid namespaces, `pivot_root`, dropped capabilities, seccomp, and cgroup v2 placement
- exposes a small host dashboard plus per-namespace HTTP servers

The whole project currently lives in `main.go` plus a few Linux-only support files:

- `sandbox_linux.go`: plugin sandbox bootstrap and seccomp
- `cgroup_linux.go`: cgroup v2 management for plugin children
- `main_linux_test.go`: integration and behavior tests
- `sandbox_linux_test.go`, `cgroup_linux_test.go`, `firewall_linux_test.go`, `reconcile_linux_test.go`: focused Linux tests

## Build And Test

- Build: `make build` or `go build -o netforge`
- Run tests: `make test`
- Run the app: `make run`

Important constraints:

- The real integration paths require Linux and root.
- `make test` runs `sudo go test -cover`.
- `go test ./...` is still useful for fast non-root iteration, but it does not exercise all namespace and firewall behavior.

## Runtime Configuration

The host process uses these environment variables:

- `PARENT_NIC`: parent interface for VLAN subinterfaces, default `enp0s31f6`
- `PLUGIN_RUNTIME_BASE`: runtime directory, default `/tmp/netforge`
- `HOST_HTTP_ADDR`: host dashboard bind address, default `127.0.0.1:8090`
- `NS_CONFIG_JSON`: full namespace configuration list; if unset, built-in defaults are used

Internal plugin/sandbox environment variables are implementation details and should not be turned into user-facing config unless that is an explicit feature change.

## Security Warnings

- NetForge runs as root and performs destructive host network changes.
- On startup, NetForge currently assumes ownership of all named network namespaces visible under `/run/netns`.
- Any named namespace on the host that is not represented in the active NetForge config will be removed, even if NetForge did not create it.
- Any named namespace that is represented in the active NetForge config is also deleted and recreated from scratch on startup.
- Manual changes inside a configured namespace are not preserved. If the live namespace state differs from the NetForge config, NetForge will recreate the namespace rather than trying to preserve out-of-band edits.
- Custom nftables rules or tables added inside a configured namespace should be assumed ephemeral unless they are explicitly modeled by NetForge.
- Do not run NetForge on a host where unrelated named network namespaces must survive unless that behavior is intentionally changed first.

## Architecture Notes

### Namespace lifecycle

`runHost()` treats config as authoritative. Startup currently:

1. validates config and the parent NIC
2. removes all named namespaces it finds under `/run/netns` plus stale runtime directories
3. recreates configured namespaces from scratch
4. starts one plugin child per namespace

Operationally, that means:

- namespaces not defined by NetForge are removed
- namespaces defined by NetForge are recreated every startup
- manual drift inside a defined namespace is discarded in favor of config
- manual firewall changes inside a defined namespace are also discarded

If you change namespace reconciliation, preserve fail-closed behavior. Partial startup should not leave stale namespaces, leaked host links, half-configured runtime state, or an ambiguity about which namespaces NetForge owns.

### Firewall model

`configureNamespaceFirewall()` manages the `inet` table named `netforge` and the base chain named `input`.

For managed namespaces, this firewall state is authoritative. Out-of-band rule changes inside that managed table, and any namespace-local firewall state that depends on the namespace surviving untouched, should not be considered persistent.

Rules currently allow:

- `ct state established,related`
- optional ICMP + ICMPv6
- optional single TCP destination port

The base chain policy is `drop`. Firewall updates must stay fail-closed: do not introduce any update path that temporarily leaves the namespace without its drop-policy firewall.

### Plugin sandbox

The plugin child is not a normal subprocess. It is started after entering the target network namespace and then further isolated with:

- user, mount, and pid namespaces
- `pivot_root`
- dropped capabilities
- seccomp
- cgroup v2 placement

When touching plugin startup, keep host/plugin Unix socket translation and the sandbox bootstrap sequence intact.

## Coding Guidance

- Prefer small helpers around state discovery and mutation for kernel-facing code.
- Keep Linux operations fail-closed. If a step cannot be applied safely, return an error rather than running with weaker isolation or weaker filtering.
- Be careful with multi-step namespace, mount, firewall, and cgroup changes. A “works eventually” sequence is not good enough if it creates an unsafe intermediate state.
- Do not add non-Linux support unless that is the explicit task; the package is intentionally `//go:build linux`.
- Do not commit the built `netforge` binary.

## Testing Guidance

When changing these areas, add or update root integration coverage:

- namespace reconciliation and teardown
- nftables firewall replacement behavior
- sandbox bootstrap and failpoints
- cgroup placement and cleanup
- plugin startup inside a namespace

Prefer tests that verify final kernel-visible state through netlink, `/proc`, nftables inspection, or real HTTP reachability from inside the namespace.
