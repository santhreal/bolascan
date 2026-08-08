//! REST-shaped probe planning from an [`appmap::AppMap`].

use crate::detector::{extract_resource_ids, mutate_id_in_url, IdParam};
use crate::tier_b::IdPatternRules;
use appmap::{AppMap, Endpoint, Method, ParameterKind, RoleAuth};

/// One REST probe: URL + method + which role fires it + optional mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestProbe {
    pub url: String,
    pub method: Method,
    pub role: RoleAuth,
    pub id_param: Option<IdParam>,
    pub original_id: Option<String>,
    pub mutated_id: Option<String>,
}

/// Plan cross-role REST probes for endpoints that expose resource IDs.
///
/// Returns [`BolaScanError::TierB`] when the embedded ID-pattern rules fail
/// to load: continuing with zero patterns would plan no mutations and the
/// scan would silently cover nothing.
pub fn plan_rest_probes(
    appmap: &AppMap,
    roles: &[RoleAuth],
    base_url: &str,
) -> Result<Vec<RestProbe>, crate::BolaScanError> {
    let rules = IdPatternRules::embedded().map_err(crate::BolaScanError::TierB)?;
    let base = base_url.trim_end_matches('/');
    let mut probes = Vec::new();

    for (_, endpoint) in appmap.endpoints().iter() {
        if !endpoint_has_id_param(endpoint) {
            continue;
        }
        let template_url = template_to_url(base, endpoint);
        let ids = extract_resource_ids(&template_url);
        if ids.is_empty() {
            continue;
        }

        for role in roles {
            for (id_param, original_id) in &ids {
                let mut probe = RestProbe {
                    url: template_url.clone(),
                    method: endpoint.method,
                    role: role.clone(),
                    id_param: Some(id_param.clone()),
                    original_id: Some(original_id.clone()),
                    mutated_id: None,
                };

                if let Some(pat) = rules.classify_token(original_id) {
                    let mutated = rules.mutate_token(original_id, pat);
                    probe.mutated_id = Some(mutated.clone());
                    probe.url = mutate_id_in_url(&probe.url, id_param, &mutated);
                }

                probes.push(probe);
            }
        }
    }

    Ok(probes)
}

/// Pairwise owner/prober matrix probes: role A's resource fetched as role B.
///
/// Returns [`BolaScanError::TierB`] when the embedded ID-pattern rules fail
/// to load (see [`plan_rest_probes`]).
pub fn plan_cross_role_matrix(
    appmap: &AppMap,
    roles: &[RoleAuth],
    base_url: &str,
) -> Result<Vec<(RoleAuth, RoleAuth, RestProbe)>, crate::BolaScanError> {
    let mut pairs = Vec::new();
    let base_probes = plan_rest_probes(appmap, roles, base_url)?;
    for owner in roles {
        for prober in roles {
            if owner.role == prober.role {
                continue;
            }
            for probe in &base_probes {
                if probe.role.role != owner.role {
                    continue;
                }
                let mut cross = probe.clone();
                cross.role = prober.clone();
                pairs.push((owner.clone(), prober.clone(), cross));
            }
        }
    }
    Ok(pairs)
}

fn endpoint_has_id_param(endpoint: &Endpoint) -> bool {
    endpoint.parameters.iter().any(|p| {
        matches!(
            p.kind,
            ParameterKind::Id
                | ParameterKind::Enumerable
                | ParameterKind::OpaqueId
                | ParameterKind::OwnershipBound
        )
    }) || endpoint.path_template.contains('{')
}

fn template_to_url(base: &str, endpoint: &Endpoint) -> String {
    let mut path = endpoint.path_template.clone();
    for param in &endpoint.parameters {
        let placeholder = format!("{{{}}}", param.name);
        let sample = param.sample_value.as_deref().unwrap_or("42");
        path = path.replace(&placeholder, sample);
    }
    while let Some(start) = path.find('{') {
        if let Some(end) = path[start..].find('}') {
            let end_idx = start + end;
            path.replace_range(start..=end_idx, "42");
        } else {
            break;
        }
    }
    format!("{base}{path}")
}

/// Execute matrix probes with a caller-provided replay function.
pub fn execute_matrix<F>(
    pairs: &[(RoleAuth, RoleAuth, RestProbe)],
    replay: F,
) -> Vec<MatrixObservation>
where
    F: Fn(&RoleAuth, &RestProbe) -> (u16, Vec<u8>),
{
    let mut observations = Vec::new();
    for (owner, prober, probe) in pairs {
        let owner_probe = RestProbe {
            role: owner.clone(),
            ..probe.clone()
        };
        let (owner_status, owner_body) = replay(owner, &owner_probe);
        let (prober_status, prober_body) = replay(prober, probe);
        observations.push(MatrixObservation {
            owner: owner.clone(),
            prober: prober.clone(),
            probe: probe.clone(),
            owner_status,
            owner_body,
            prober_status,
            prober_body,
        });
    }
    observations
}

/// Raw observation from a role-pair matrix cell.
#[derive(Clone, Debug)]
pub struct MatrixObservation {
    pub owner: RoleAuth,
    pub prober: RoleAuth,
    pub probe: RestProbe,
    pub owner_status: u16,
    pub owner_body: Vec<u8>,
    pub prober_status: u16,
    pub prober_body: Vec<u8>,
}
