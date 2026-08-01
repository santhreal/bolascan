# bolascan

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
![crates.io](https://img.shields.io/crates/v/bolascan)
![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

## What it does

`bolascan` is an IDOR / BOLA (Broken Object Level Authorization) scanner for
REST APIs.  It consumes an [`appmap`](../../runtime/appmap) that records
endpoint shapes and role credentials, builds a cross-role probe matrix, replays
requests through a caller-supplied transport, and emits structured
[`secfinding::Finding`](../../scanner/secfinding) values  -  one per detected
authorization bypass.

Detection heuristics:

- Compares prober-role responses to owner-role responses via
  [`respdiff`](../../scanner/respdiff) and appmap meaningful diff.
- Assigns confidence based on response similarity, body size ratio, and presence
  of privacy-sensitive JSON fields (`email`, `ssn`, `password`, `secret`,
  `token`, `api_key`).
- Uses embedded Tier-B ID-pattern rules (`tier_b/id_patterns.toml`) to
  recognize and mutate sequential integers, UUIDs, MongoDB ObjectIds, Snowflake
  IDs, base64-encoded integers, slugs, and JWT-shaped tokens.

## Quick start

### CLI

```bash
cargo run -p bolascan --bin bolascan-cli -- scan \
  --target https://api.example.com \
  --roles roles.toml \
  --out findings.json
```

`roles.toml` example:

```toml
[[roles]]
name = "user_a"
cookies = { session = "aaa" }

[[roles]]
name = "user_b"
cookies = { session = "bbb" }

[[endpoints]]
method = "GET"
path = "/api/users/{id}"
```

### Library

```rust
use appmap::{AppMap, RoleAuth};
use bolascan::{BolaScan, ScanConfig};

let findings = BolaScan::new().scan_with_replay(
    &appmap,
    &roles,
    &ScanConfig::new("https://target"),
    |role, probe| {
        // issue probe.url as role, return (status_code, body_bytes)
        (200, b"{}".to_vec())
    },
)?;
```

### Tests

```bash
cargo test -p bolascan
```

## When to use / When not

**Use** when:

- You have two or more application roles (e.g. `user_a` / `user_b`) and want to
  verify that role A cannot access role B's resources.
- You want structured `secfinding::Finding` output (severity, CWE-639, evidence
  chain) suitable for downstream aggregation.
- You need ID-mutation strategies (increment, UUID swap, ObjectId nibble flip)
  without writing custom probe logic.

**Do not use** when:

- Your target has no role separation (single-tenant apps without access
  control).
- You need GraphQL or JSON-RPC coverage  -  v0.1 only supports REST.
- You need real HTTP transport  -  the library requires a caller-supplied replay
  closure; use the CLI or wrap with your own HTTP client.

## Compared to alternatives

| Tool | BOLA detection | Structured findings | No outbound deps | Replay hook |
|------|---------------|---------------------|-----------------|------------|
| bolascan | yes | yes (`secfinding`) | yes | yes |
| Autorize (Burp ext.) | yes | no | no (Burp) | no |
| AuthMatrix (Burp ext.) | yes | no | no (Burp) | no |
| OWASP ZAP IDOR scanner | partial | no (alerts) | no (Java) | no |

bolascan is transport-agnostic: you supply the HTTP call, it supplies the
detection logic and finding model.

## How it fits in Santh

```
appmap (runtime)
     |  role matrix + replay
     v
bolascan (this crate)
     |  secfinding::Finding
     v
secfinding (scanner)  --->  aggregation / reporting pipeline
```

`bolascan` sits in the offensive layer of the Santh scanner stack.  It receives
an `AppMap` from the runtime layer, runs cross-role probes via a caller-supplied
transport, and hands `Finding` values to the scanner layer.  It has no opinion
about how requests are sent or how findings are reported.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `tier-b-toml` | yes | Embedded `tier_b/id_patterns.toml` mutation strategies |

## Contributing

1. Add a `[[pattern]]` block to `tier_b/id_patterns.toml` to teach new ID
   shapes  -  no Rust changes required.
2. For detection changes, add tests under `tests/` before touching `src/`.
3. Run `cargo +nightly test -p bolascan` and confirm all tests pass.
4. Run `santh-conform check libs/offensive/bolascan` and address any `fail`
   findings before opening a PR.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.
