//! Finding verification (content diff, side effects - v0.1: content compare only).

pub mod content_compare;

pub use content_compare::{compare_cross_role, compare_with_appmap, ContentCompareResult};
