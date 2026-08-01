//! Probe planners (REST, GraphQL, JSON-RPC - v0.1: REST only).

pub mod rest;

pub use rest::{
    execute_matrix, plan_cross_role_matrix, plan_rest_probes, MatrixObservation, RestProbe,
};
