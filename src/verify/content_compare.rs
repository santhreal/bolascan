//! Semantic response comparison via `respdiff` + appmap meaningful diff.

use appmap::{AppMap, DiffReport, EndpointId, HttpResponse};
use respdiff::{compare_responses, ResponseDiff, ResponseSnapshot};

/// Outcome of cross-role content verification.
#[derive(Clone, Debug, PartialEq)]
pub struct ContentCompareResult {
    pub idor_detected: bool,
    pub confidence: f64,
    pub description: String,
    pub respdiff: ResponseDiff,
    pub meaningful: Option<DiffReport>,
    pub leaked_privacy_fields: Vec<String>,
}

/// Compare owner vs prober responses using respdiff, then refine with IDOR heuristics.
#[must_use]
pub fn compare_cross_role(
    owner_status: u16,
    owner_body: &[u8],
    prober_status: u16,
    prober_body: &[u8],
) -> ContentCompareResult {
    let snap_owner = ResponseSnapshot::new(owner_status, Vec::<(&str, &str)>::new(), owner_body);
    let snap_prober = ResponseSnapshot::new(prober_status, Vec::<(&str, &str)>::new(), prober_body);
    let respdiff_report = compare_responses(&snap_owner, &snap_prober);

    let (idor_detected, confidence, description) =
        crate::detector::compare_responses(owner_status, owner_body, prober_status, prober_body);

    let leaked_privacy_fields = privacy_fields_in_body(prober_body);

    ContentCompareResult {
        idor_detected,
        confidence,
        description,
        respdiff: respdiff_report,
        meaningful: None,
        leaked_privacy_fields,
    }
}

/// Compare with appmap volatile stripping + meaningful diff when a model is available.
#[must_use]
pub fn compare_with_appmap(
    appmap: &AppMap,
    endpoint: &EndpointId,
    owner: &HttpResponse,
    prober: &HttpResponse,
) -> ContentCompareResult {
    let meaningful = appmap.meaningful_diff(owner, prober, endpoint);
    let mut base = compare_cross_role(owner.status, &owner.body, prober.status, &prober.body);
    base.meaningful = Some(meaningful.clone());

    if !meaningful.privacy_bound_divergences.is_empty() && prober.status == 200 {
        base.idor_detected = true;
        base.confidence = base.confidence.max(0.85);
        base.description = format!(
            "{}; privacy fields diverged: {}",
            base.description,
            meaningful.privacy_bound_divergences.join(", ")
        );
        for k in &meaningful.privacy_bound_divergences {
            if !base.leaked_privacy_fields.contains(k) {
                base.leaked_privacy_fields.push(k.clone());
            }
        }
    }

    base
}

fn privacy_fields_in_body(body: &[u8]) -> Vec<String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(body) else {
        return Vec::new();
    };
    map.keys()
        .filter(|k| {
            let lower = k.to_ascii_lowercase();
            lower.contains("email")
                || lower.contains("ssn")
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("api_key")
        })
        .cloned()
        .collect()
}
