# MXC Containment Policy Spec v0.9.0-alpha

> **Audience:** MXC consumers

`0.9.0-alpha` is the oldest **supported** configuration contract. Its
published [schema](../../../schemas/stable/mxc-config.schema.0.9.0-alpha.json)
is immutable. High-level [V1 SDK authoring](../README.md#authoring-a-policy)
targets `1.0.0`; use raw configuration to select this exact historical
contract.

## Policy behavior

| Section | Policy and configuration |
|---|---|
| `filesystem` | `readwritePaths`, `readonlyPaths`, and `deniedPaths` grant or deny paths. An omitted grant does not provide access. |
| `network.egress` | `default` is `deny` when omitted. `allow` and `deny` rules match destination IP/CIDR (`to[].cidr`, optional `except`) and optional protocol/port ranges; explicit deny wins. DNS hostnames are not rules. |
| `network.ingress` | `default` controls private-network inbound traffic; `hostLoopback` controls host-loopback connectivity in both directions. Both deny when omitted, independently of one another. |
| `runtimeConfig.networkProxy` | Runtime HTTP/S proxy endpoint, not a network rule. Non-WSLC backends require deny-default egress without direct allow/deny rules. WSLC requires bridged networking (all three directional defaults `allow`) and uses the proxy cooperatively; it cannot enforce proxy-only egress. See the [WSLC network guide](../../backends/wslc/wsl-container-getting-started.md#network-proxy-cooperative-unprivileged). |
| `ui` | `disable`, `clipboard` (`none`, `read`, `write`, or `all`), and `injection`. Enforcement depends on the selected backend; do not assume that omitting `ui` locks down a backend that does not implement it. |
| `fallback.allowDaclMutation` | Allows Windows host-DACL mutation as a filesystem fallback; defaults to `true`. Set to `false` to refuse this fallback. |
| `lifecycle` | `destroyOnExit` and `preservePolicy` control cleanup and retained policy. |
| `process` | `cwd`, `env` (`KEY=VALUE` entries), `inheritDefaultEnv`, and `timeout` (milliseconds). Omitted `env` uses the backend default; supplied `env`, even `[]`, replaces it unless `inheritDefaultEnv` is true. |

Backend-specific settings belong under their matching section, such as
`processContainer`, `wslc`, `lxc`, or `seatbelt`. In particular,
`processContainer.filesystem.enumeratePaths` requires a BaseContainer host
with the necessary PSEC support; it is not a portable filesystem grant.
Unsupported policy or unavailable host enforcement is rejected rather than
silently weakened. See the [schema guide](../../schema.md) and the relevant
backend guide for defaults and enforcement limits.

## State-aware policy

This contract supports IsolationSession and WSLC lifecycle operations.
IsolationSession cannot restrict networking: one-shot and provision requests
must explicitly allow egress, ingress, and host loopback. Omitting `network`,
supplying an empty object, or adding network rules or a proxy is rejected.
For phase-specific policy support, see the
[container lifecycle API](../../development/architecture/container-lifecycle.md).

## Moving to 1.0.0

Use [the 1.0.0 contract](../1.0.0/policy.md) for stable raw config and new
high-level SDK authoring. Rename the historical containment aliases and
backend sections before changing `version`; changing the version string alone
does not migrate an invalid request.

## Raw JSON authoring

Raw one-shot requests require `"version": "0.9.0-alpha"` and a non-empty
`process.commandLine`. Omitted `containment` selects the abstract `process`
intent: `processcontainer` on Windows, `bubblewrap` on Linux, and `seatbelt`
on macOS. Supported selections are `process`, `processcontainer`, `lxc`,
`bubblewrap`, `seatbelt`, `isolation_session`, and `wslc`. This contract also
accepts the historical `appcontainer` and `macos_sandbox` containment aliases
and `appContainer` and `macos_sandbox` backend-section spellings; use the
canonical names for new requests. Only the section for the selected backend
may be supplied.

Legacy `network.defaultPolicy`, `allowLocalNetwork`, `allowedHosts`,
`blockedHosts`, `enforcementMode`, and `network.proxy` are not accepted.

```json
{
  "version": "0.9.0-alpha",
  "containment": "processcontainer",
  "process": { "commandLine": "cmd.exe /c echo hello" },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

`phase` selects the closed `provision`, `start`, `exec`, `stop`, and
`deprovision` roots instead of a one-shot request. Provision supplies
`containment`; later phases use the returned `sandboxId`. Exec requires a
`process` with a non-empty `commandLine`. An IsolationSession provision
request must describe its unrestricted network posture:

```json
{
  "version": "0.9.0-alpha",
  "phase": "provision",
  "containment": "isolation_session",
  "network": {
    "egress": { "default": "allow" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  }
}
```
