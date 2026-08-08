use appmap::{AppMap, Endpoint, Method, ParameterClassifier, RoleAuth};
use bolascan::plan_cross_role_matrix;

#[tokio::test]
async fn matrix_pairs_exclude_same_role() {
    let classifier = ParameterClassifier::embedded().expect("embedded classifier");
    let map = AppMap::builder()
        .with_roles(vec![
            RoleAuth::new("a").with_cookie("s", "1"),
            RoleAuth::new("b").with_cookie("s", "2"),
        ])
        .endpoint(
            Endpoint::new(Method::Get, "/api/users/{id}")
                .with_parameter(classifier.classify("id", Some("42"))),
        )
        .build()
        .unwrap();

    let roles = map.roles().to_vec();
    let pairs = plan_cross_role_matrix(&map, &roles, "https://api.example.com")
        .expect("matrix planning must succeed with embedded rules");
    assert!(!pairs.is_empty());
    for (owner, prober, _) in &pairs {
        assert_ne!(owner.role, prober.role);
    }
}

#[test]
fn template_to_url_unlisted_placeholder_replaced_with_sample() {
    use appmap::{AppMap, Endpoint, Method, RoleAuth};
    use bolascan::plan_rest_probes;

    let mut builder = AppMap::builder().with_roles(vec![RoleAuth::new("admin")]);
    // Endpoint has path template with {org_id} and {user_id}, but no explicit parameters registered.
    builder = builder.endpoint(Endpoint::new(Method::Get, "/api/orgs/{org_id}/users/{user_id}"));
    let appmap = builder.build().unwrap();
    let roles = vec![RoleAuth::new("admin")];

    let probes = plan_rest_probes(&appmap, &roles, "https://api.example.com").unwrap();
    assert!(!probes.is_empty());
    // Unlisted placeholders must be replaced cleanly with "42", which is then mutated to "43" by Tier-B
    assert!(probes[0].url.contains("/api/orgs/43/users/42"));
}
