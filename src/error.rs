use thiserror::Error;

#[derive(Debug, Error)]
pub enum BolaScanError {
    #[error("appmap model is empty")]
    EmptyAppMap,
    #[error("need at least two roles for cross-user IDOR testing")]
    InsufficientRoles,
    #[error("roles file: {0}")]
    RolesFile(String),
    #[error("tier-b config: {0}")]
    TierB(String),
    #[error("finding validation: {0}")]
    FindingValidation(String),
}
