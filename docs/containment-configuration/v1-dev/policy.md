# MXC Containment Policy (V1 development: 1.1.0-alpha)

> **Audience:** MXC consumers and developers

`1.1.0-alpha` is a **mutable development** policy contract, not a published
1.1.0 release. It retains the restrictions of the stable
[1.0.0 policy](../1.0.0/policy.md) and adds development-only backend surfaces.
The [V1 SDKs](../README.md#authoring-a-policy) still target published `1.0.0`;
use raw configuration for features available only in this contract.

## Shared policy

The development contract retains the canonical [1.0.0 policy](../1.0.0/policy.md):
one-shot requests require a non-empty `process.commandLine`; the common
`filesystem`, directional `network`, `runtimeConfig.networkProxy`, `ui`,
`fallback`, `lifecycle`, and `process` fields keep their meanings. Neither
this version nor an experimental flag restores retired network fields or the
`appcontainer`, `appContainer`, and `macos_sandbox` aliases.
As in 1.0.0, omitted `containment` selects the host-native `process` backend,
and WSLC requires bridged networking for its cooperative proxy rather than
deny-default egress. Backend validation still rejects policy that the chosen
backend cannot enforce.

## Development-only request surfaces

| Surface | What the exact contract accepts |
|---|---|
| One-shot `vm` | Abstract VM intent. Resolves to `windows_sandbox` on Windows; no VM backend is implemented for other hosts. |
| One-shot `windows_sandbox` | Explicit Windows Sandbox selection; optional `windowsSandbox` compatibility settings. See its [backend policy limits](../../backends/windows-sandbox/windows-sandbox.md#policy-support). |
| One-shot `microvm` | NanVix MicroVM selection. See the [NanVix guide](../../backends/nanvix/nanvix.md) for enforceable policy. |
| One-shot `hyperlight` | Hyperlight selection with optional `hyperlight.runtime` guest choice. See its [backend guide](../../backends/hyperlight/hyperlight-backend.md) for supported policy. |
| `windows_sandbox` state-aware | Closed `provision`, `start`, `exec`, `stop`, and `deprovision` lifecycle roots; filesystem policy is supplied at provision and is immutable thereafter. |
| `test` | Development-only placeholder used to exercise feature plumbing, not a production policy. |

The published IsolationSession and WSLC lifecycle operations remain available,
subject to their phase-specific policy checks. For lifecycle semantics, see
the [container lifecycle API](../../development/architecture/container-lifecycle.md).

**Contract acceptance is not execution authorization.** Selecting MicroVM,
Hyperlight, or Windows Sandbox (including the `vm` intent on Windows) requires
the runtime `--experimental` option (or the equivalent raw API option). On
other hosts, `vm` has no implemented backend. The option does not make an
unsupported backend policy valid, and using the development version alone
does not authorize experimental execution. See
[versioning](../../development/architecture/versioning.md#experimental-flag).

## Raw JSON authoring

Raw requests must declare `"version": "1.1.0-alpha"` and match the mutable
[development schema](../../../schemas/dev/mxc-config.schema.1.1.0-alpha.json).
Its accepted shape can change before publication; the current SDK V1 target
remains `1.0.0`. For example, one-shot Windows Sandbox execution:

```json
{
  "version": "1.1.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "powershell -NoProfile -Command \"Write-Output 'hello'\"",
    "timeout": 60000
  }
}
```

Windows Sandbox state-aware provision can supply a filesystem grant:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "windows_sandbox",
  "filesystem": { "readonlyPaths": ["C:\\inputs"] }
}
```

Later phases use the returned `sandboxId`; `exec` also supplies `process`.
