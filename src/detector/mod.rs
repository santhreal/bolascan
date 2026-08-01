//! IDOR / BOLA detection - lifted from karyx `idor.rs`.

mod id_param;

pub use id_param::{
    compare_responses, extract_json_ids, extract_resource_ids, is_id_param_name, is_resource_id,
    mutate_id_in_url, mutate_json_id, IdParam, IdorTarget,
};

use appmap::{AppMap, EndpointId, HttpResponse, RoleAuth};
use secfinding::AccessOutcome as BolaAccessOutcome;
use secfinding::{Evidence, Finding, FindingKind, Severity};

use crate::error::BolaScanError;
use crate::probe::{execute_matrix, plan_cross_role_matrix, MatrixObservation};
use crate::verify::{compare_cross_role, compare_with_appmap};

/// Scan configuration for offline matrix runs and CLI export.
#[derive(Clone, Debug, Default)]
pub struct ScanConfig {
    /// Target label stamped on every emitted [`Finding`](secfinding::Finding).
    pub target: String,
    /// Prefix for rule tags (default `bolascan/`).
    pub rule_id_prefix: String,
}

impl ScanConfig {
    /// Build config for a target URL or hostname with the default rule-id prefix.
    #[must_use]
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            rule_id_prefix: "bolascan/".to_string(),
        }
    }
}

/// IDOR / BOLA scanner entry point (stateless v0.1 handle).
#[derive(Clone, Debug, Default)]
pub struct BolaScan;

impl BolaScan {
    /// Construct the default scanner instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run detection against a pre-built appmap + roles; emits only `secfinding::Finding`.
    pub fn scan_offline(
        &self,
        appmap: &AppMap,
        roles: &[RoleAuth],
        config: &ScanConfig,
        observations: &[MatrixObservation],
    ) -> Result<Vec<Finding>, BolaScanError> {
        if appmap.endpoints().is_empty() {
            return Err(BolaScanError::EmptyAppMap);
        }
        if roles.len() < 2 {
            return Err(BolaScanError::InsufficientRoles);
        }

        let mut findings = Vec::new();
        for obs in observations {
            let endpoint = endpoint_for_probe(appmap, &obs.probe.url);
            let owner_resp = HttpResponse::new(
                obs.owner_status,
                Vec::<(&str, &str)>::new(),
                &obs.owner_body,
            );
            let prober_resp = HttpResponse::new(
                obs.prober_status,
                Vec::<(&str, &str)>::new(),
                &obs.prober_body,
            );

            let compare = if let Some(ep) = &endpoint {
                compare_with_appmap(appmap, ep, &owner_resp, &prober_resp)
            } else {
                compare_cross_role(
                    obs.owner_status,
                    &obs.owner_body,
                    obs.prober_status,
                    &obs.prober_body,
                )
            };

            if !compare.idor_detected {
                continue;
            }

            let resource_id = obs
                .probe
                .original_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let resource_kind = obs.probe.url.clone();

            let rule_tag = format!(
                "{}{}/idor/cross-role",
                config.rule_id_prefix,
                obs.probe.method.as_str().to_ascii_lowercase()
            );

            let access_outcome = map_access_outcome(obs.prober_status, &compare);

            let finding = Finding::builder(
                "bolascan",
                &config.target,
                severity_from_confidence(compare.confidence),
            )
            .title("Insecure direct object reference (IDOR)")
            .detail(&compare.description)
            .kind(FindingKind::AccessControl)
            .confidence(compare.confidence)
            .cwe("CWE-639")
            .tag("idor")
            .tag("bola")
            .tag(rule_tag.as_str())
            .evidence(Evidence::HttpRequest {
                method: obs.probe.method.as_str().into(),
                url: obs.probe.url.clone().into(),
                headers: Vec::new(),
                body: None,
            })
            .evidence(Evidence::BolaProbe {
                owner_role: obs.owner.role.as_str().into(),
                prober_role: obs.prober.role.as_str().into(),
                resource_kind: resource_kind.into(),
                resource_id_token: resource_id.into(),
                access_outcome,
                leaked_privacy_fields: compare
                    .leaked_privacy_fields
                    .iter()
                    .map(|s| std::sync::Arc::from(s.as_str()))
                    .collect(),
            })
            .evidence(Evidence::HttpResponse {
                status: obs.prober_status,
                headers: Vec::new(),
                body_excerpt: body_excerpt(&obs.prober_body),
            })
            .build()
            .map_err(|e| BolaScanError::FindingValidation(e.to_string()))?;

            findings.push(finding);
        }

        Ok(findings)
    }

    /// Plan matrix via appmap + replay hook, then scan.
    pub fn scan_with_replay<F>(
        &self,
        appmap: &AppMap,
        roles: &[RoleAuth],
        config: &ScanConfig,
        replay: F,
    ) -> Result<Vec<Finding>, BolaScanError>
    where
        F: Fn(&RoleAuth, &crate::probe::RestProbe) -> (u16, Vec<u8>),
    {
        let pairs = plan_cross_role_matrix(appmap, roles, &config.target)?;
        let observations = execute_matrix(&pairs, replay);
        self.scan_offline(appmap, roles, config, &observations)
    }
}

fn endpoint_for_probe(appmap: &AppMap, url: &str) -> Option<EndpointId> {
    let path = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or(url);
    // Strip any query/fragment before matching the path against templates.
    let path = path.split(['?', '#']).next().unwrap_or(path);
    // Precise segment-wise template match. Return None when nothing matches
    // rather than an ARBITRARY endpoint: the caller correctly falls back to a
    // cross-role comparison on None, so the old `.or_else(next())` both
    // misattributed the finding to a random endpoint AND forced the wrong
    // (appmap) comparison path.
    appmap
        .endpoints()
        .iter()
        .find(|(_, ep)| path_matches_template(path, &ep.path_template))
        .map(|(id, _)| id.clone())
}

/// Match a concrete request path against a route template segment-by-segment.
///
/// A `{param}` template segment matches exactly one non-empty path segment; every
/// other segment must be byte-equal, and the segment counts must be identical.
/// So `/users/{id}` matches `/users/5` but NOT `/users/5/posts` (extra segment),
/// `/superusers/5` (literal mismatch, unlike the old substring `.contains`), or
/// `/users` (missing segment). An all-`{param}`/empty template no longer matches
/// every path.
fn path_matches_template(path: &str, template: &str) -> bool {
    let mut path_segs = path.split('/').filter(|s| !s.is_empty());
    let mut tmpl_segs = template.split('/').filter(|s| !s.is_empty());
    loop {
        match (path_segs.next(), tmpl_segs.next()) {
            (Some(p), Some(t)) => {
                let is_param = t.starts_with('{') && t.ends_with('}');
                if !is_param && p != t {
                    return false;
                }
            }
            (None, None) => return true,
            // Segment-count mismatch: not the same route.
            _ => return false,
        }
    }
}

fn severity_from_confidence(confidence: f64) -> Severity {
    if confidence >= 0.9 {
        Severity::High
    } else if confidence >= 0.7 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn map_access_outcome(
    status: u16,
    compare: &crate::verify::ContentCompareResult,
) -> BolaAccessOutcome {
    if compare.idor_detected && status == 200 && !compare.leaked_privacy_fields.is_empty() {
        BolaAccessOutcome::SuccessWithData
    } else if compare.idor_detected && status == 200 {
        BolaAccessOutcome::SuccessEmpty
    } else if status == 401 || status == 403 {
        BolaAccessOutcome::Denied
    } else if status == 404 {
        BolaAccessOutcome::NotFound
    } else {
        BolaAccessOutcome::Other
    }
}

fn body_excerpt(body: &[u8]) -> Option<std::sync::Arc<str>> {
    const MAX: usize = 512;
    if body.is_empty() {
        return None;
    }
    let slice = if body.len() > MAX { &body[..MAX] } else { body };
    std::str::from_utf8(slice)
        .ok()
        .map(|s| std::sync::Arc::from(s))
}

#[cfg(test)]
mod path_match_tests {
    use super::path_matches_template;

    #[test]
    fn param_segment_matches_any_single_value() {
        assert!(path_matches_template("/users/5", "/users/{id}"));
        assert!(path_matches_template("/users/abc-123", "/users/{id}"));
    }

    #[test]
    fn literal_segments_must_match_exactly_not_as_substring() {
        // The old `.contains("users/")` wrongly matched this; segment matching does not.
        assert!(!path_matches_template("/superusers/5", "/users/{id}"));
    }

    #[test]
    fn segment_count_must_match() {
        assert!(!path_matches_template("/users/5/posts", "/users/{id}"));
        assert!(!path_matches_template("/users", "/users/{id}"));
    }

    #[test]
    fn empty_or_all_param_template_does_not_match_everything() {
        // Old prefix logic made an empty prefix match every path.
        assert!(!path_matches_template("/anything/here", "/"));
        assert!(path_matches_template("/42", "/{id}"));
        assert!(!path_matches_template("/a/b", "/{id}"));
    }

    #[test]
    fn multi_param_template_matches_positionally() {
        assert!(path_matches_template("/users/7/posts/9", "/users/{uid}/posts/{pid}"));
        assert!(!path_matches_template("/users/7/comments/9", "/users/{uid}/posts/{pid}"));
    }
}
