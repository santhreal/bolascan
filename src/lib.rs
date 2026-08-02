//! IDOR / BOLA scanner consuming [`appmap`] for replay/matrix; emits [`secfinding::Finding`] only.
//!
//! Lift source: karyx `web/karyx/crates/engine/src/idor.rs` -> [`detector`].
//! See `MASTER_PLAN/05_bolascan.md`.
//!
//! ## Safe defaults
//!
//! **Input size:** No hard cap is enforced on individual response body bytes fed
//! to [`compare_responses`] / [`compare_cross_role`].  `body_excerpt` truncates
//! evidence stored in a `Finding` at 512 bytes.  Callers are responsible for
//! capping replay bodies before passing them in.
//!
//! **Recursion depth:** `extract_ids_recursive` recurses over serde_json values.
//! Depth is bounded by the JSON tree depth of the input body; no explicit limit
//! is enforced.  Pathologically deep JSON (thousands of levels) could exhaust the
//! call stack; this is the caller's responsibility to avoid.
//!
//! **Outbound network:** This crate makes no outbound network calls.  All HTTP
//! traffic is driven entirely by the caller-supplied `replay` closure passed to
//! [`BolaScan::scan_with_replay`].
//!
//! **Process spawning:** This crate does not spawn child processes.
//!
//! **Filesystem writes:** This crate does not write to the filesystem.  The CLI
//! binary (`bolascan-cli`) writes findings to a caller-specified `--out` path;
//! the library itself performs no filesystem I/O.
//!
//! **Credential exposure:** Role credentials (session cookies, bearer tokens)
//! supplied via [`appmap::RoleAuth`] are stored in memory for the duration of a
//! scan and are included in the `RestProbe` values passed to the `replay`
//! closure.  They are never logged or serialised to disk by this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

mod detector;
mod error;
mod probe;
mod tier_b;
mod verify;

pub use detector::{
    compare_responses, extract_json_ids, extract_resource_ids, is_id_param_name, is_resource_id,
    mutate_id_in_url, mutate_json_id, BolaScan, IdParam, IdorTarget, ScanConfig,
};
pub use error::BolaScanError;
pub use probe::{
    execute_matrix, plan_cross_role_matrix, plan_rest_probes, MatrixObservation, RestProbe,
};
pub use tier_b::{IdPattern, IdPatternRules};
pub use verify::{compare_cross_role, compare_with_appmap, ContentCompareResult};

// The README's Rust examples are collected as doctests, so the quick-start
// can never drift from the API (contract rung: README compiles and runs).
#[doc = include_str!("../README.md")]
mod readme_doctests {}
