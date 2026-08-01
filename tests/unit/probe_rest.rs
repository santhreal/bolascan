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
