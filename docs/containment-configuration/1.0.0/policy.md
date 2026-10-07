# MXC Containment Policy Spec v1.0.0

> **Audience:** MXC consumers

`1.0.0` is the current **stable** containment policy contract. High-level
[Rust](../../api-reference/rust/v1/README.md),
[.NET](../../api-reference/dotnet/v1/README.md), and
[Node](../../api-reference/node/v1/README.md) V1 SDK APIs select this contract
without a caller-supplied version. Its published
[schema](../../../schemas/stable/mxc-config.schema.1.0.0.json) is immutable.

## Policy behavior

| Section | Policy and configuration |
|---|---|
| `filesystem` | `readwritePaths`, `readonlyPaths`, and `deniedPaths` specify path grants and denials. Omitted grants do not provide access. |
| `network.egress` | `default` (`allow` or `deny`) and direct `allow`/`deny` rules with IP/CIDR destinations and optional protocol/port selectors. Deny wins over allow; the omitted default is deny. |
| `network.ingress` | `default` controls private-network inbound traffic; `hostLoopback` controls bidirectional host-loopback traffic. Both independently deny by default. |
| `runtimeConfig.networkProxy` | Runtime HTTP/S proxy setting. Non-WSLC backends require deny-default egress and no direct rules. WSLC requires bridged networking (all three directional defaults `allow`) and uses the proxy cooperatively; it cannot enforce proxy-only egress. See the [WSLC network guide](../../backends/wslc/wsl-container-getting-started.md#network-proxy-cooperative-unprivileged). |
| `ui` | `disable`, `clipboard`, and `injection` default to disabled UI, no clipboard, and no input injection; only rely on these restrictions where the selected backend enforces them. |
| `fallback.allowDaclMutation` | Consents to the host-DACL filesystem fallback; defaults to `true`. |
| `lifecycle` | `destroyOnExit` and `preservePolicy` govern cleanup. |
| `process` | Optional `cwd`, `env`, `inheritDefaultEnv`, and `timeout` (milliseconds). Omitted `env` uses the backend default; supplied `env` replaces it unless inheritance is enabled. |

Backend-specific fields, for example `processContainer.filesystem.enumeratePaths`
or `wslc.image`, go in the corresponding backend section. Schema acceptance
does not guarantee that the host can enforce a request: unsupported policy is
rejected. See the [schema guide](../../schema.md) and backend guides for
platform-specific capabilities, defaults, and constraints.

## State-aware policy

This version supports IsolationSession and WSLC lifecycle operations.
IsolationSession cannot enforce network restrictions: one-shot and provision
requests must explicitly allow egress, ingress, and host loopback, without
rules or a proxy. See the
[container lifecycle API](../../development/architecture/container-lifecycle.md)
for phase-specific policy support.

## Changes from 0.9.0-alpha

The [0.9 contract](../0.9.0/policy.md) and 1.0 contract share their canonical
field and value spellings and their one-shot, IsolationSession, and WSLC
request families. Version 1.0 **removes** the legacy `appcontainer` and
`macos_sandbox` containment aliases and the `appContainer` and
`macos_sandbox` backend-section aliases. Use `processcontainer` /
`processContainer` and `seatbelt` instead. Older legacy network fields remain
unsupported. The `vm`, `microvm`, `hyperlight`, and Windows Sandbox request
surfaces are **not** part of the 1.0 contract; setting an experimental flag
does not make them valid.

## Raw JSON authoring

Raw one-shot requests require `"version": "1.0.0"` and a non-empty
`process.commandLine`. Omitted `containment` selects the abstract `process`
intent: `processcontainer` on Windows, `bubblewrap` on Linux, and `seatbelt`
on macOS. The closed selections are `process`, `processcontainer`, `lxc`,
`bubblewrap`, `seatbelt`, `isolation_session`, and `wslc`. Only the matching
backend section is permitted.

```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": { "commandLine": "cmd.exe /c echo hello" },
  "filesystem": { "readonlyPaths": ["C:\\inputs"] },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

`phase` selects a closed `provision`, `start`, `exec`, `stop`, or
`deprovision` root rather than a one-shot request. Provision specifies
`containment`; later phases use the returned `sandboxId`. Exec also
requires `process`.
