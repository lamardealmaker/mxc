# Containment policy by schema version

> **Audience:** MXC consumers

These pages explain the filesystem, network, UI, and execution policies
available in each supported configuration contract. A policy expresses
restrictions; the selected backend must be able to enforce them or reject
the request. For platform-specific limits, see the [backend guides](../backends/)
and [schema guide](../schema.md).

| Contract | Status | Documentation |
|---|---|---|
| `0.9.0-alpha` | Published; minimum supported | [Policy](0.9.0/policy.md) |
| `1.0.0` | Published; current stable | [Policy](1.0.0/policy.md) |
| `1.1.0-alpha` | Mutable V1 development contract | [Policy](v1-dev/policy.md) |

An old schema file remaining in `schemas/stable/` does not mean its contract
is still accepted. The current parser supports only the three contracts above.
The `v1-dev/` directory follows the current V1 development contract; its
exact `version` is `1.1.0-alpha` today. A published `1.1.0` would have its
own versioned directory.

## Authoring a policy

For typed authoring, use the [Rust](../api-reference/rust/v1/README.md),
[.NET](../api-reference/dotnet/v1/README.md), or
[Node](../api-reference/node/v1/README.md) V1 SDK reference. These APIs select
the published `1.0.0` contract for you; callers do not supply a schema
version.

Raw JSON callers declare the exact `version` of a supported contract.
The development `1.1.0-alpha` contract is mutable and available through
raw configuration, not high-level V1 authoring. The
[versioning guide](../development/architecture/versioning.md) distinguishes
schema contracts, SDK versions, and host capabilities.
