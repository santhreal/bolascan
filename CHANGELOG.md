# Changelog

## [0.2.2] - 2026-08-07

### Fixed
- Updated Cargo.toml authors to `Santh <64453045+santhreal@users.noreply.github.com>`.
- `privacy_fields_in_body` in content comparison now recursively scans nested JSON objects and JSON arrays of objects for privacy keys.
- `IdPatternRules::from_toml` now fails closed returning an `Err` if the parsed pattern ruleset is empty.
- `mutate_id_in_url` now preserves URL fragments (`#frag`) when mutating query parameters, and query extraction strips trailing fragments before checking parameter values.
- `IdPatternRules::mutate_token` explicitly warns on unknown mutation strategies instead of silently falling back.

## 0.2.1 - 2026-08-02

### Fixed
- A server answering an unauthorized cross-role request with HTTP 200 plus the login page (an auth bounce instead of 302/401) no longer counts as a confirmed IDOR. The login-form discriminator (`type=password` markup plus a login or sign-in marker) now returns unverified with zero confidence instead of "confirmed IDOR with PII" at 0.9.
- README library quick-start rewritten as a complete runnable example and wired as a doctest.

## 0.2.0 - 2026-07-31

### Changed (breaking)

- `IdPatternRules::embedded` now returns `Result<Self, String>` instead of panicking on a malformed embedded asset (a deny-level `clippy::panic` violation; a scanner host must not crash on a data-file invariant). `plan_rest_probes` and `plan_cross_role_matrix` return `Result<_, BolaScanError>` and map a rules-load failure to `BolaScanError::TierB`. Fail-closed semantics are preserved: the alternative silent empty ruleset would plan zero mutation probes with no operator signal.

### Fixed

- Compile breaks from sibling API drift: `FindingBuilder::tag` now takes `Into<Arc<str>>` (pass `&str`, not `&String`); `appmap::ParameterClassifier::embedded` and `AppMapBuilder::build` are now fallible/synchronous (`Result`, no `.await`).

## 0.1.0 - 2026-05-25

### Added

- New `bolascan` crate at `libs/offensive/bolascan` (MASTER_PLAN phase 05 substrate).
- `bolascan::detector` - ID extraction, mutation, cross-role comparison (lifted from karyx `idor.rs`).
- `bolascan::probe::rest` - REST probe planning + role-pair matrix via appmap.
- `bolascan::verify::content_compare` - respdiff + appmap meaningful-diff verification.
- `tier_b/id_patterns.toml` - enumerable ID shape patterns and mutation strategies.
- `bolascan-cli` - `scan --roles roles.toml --target URL`.
- 20+ unit and property tests (ID mutation invariants).
- karyx thin re-export shim over `bolascan::detector`.

### Notes

- v0.1 is offline/substrate: CLI uses synthetic replay; live HTTP via scanclient deferred.
- GraphQL/JSON-RPC probes, side-effect verify, secbench adapter - phase follow-ups.
