use appmap::{AppMap, Endpoint, Method, ParameterClassifier, RoleAuth};
use bolascan::{BolaScan, MatrixObservation, ScanConfig};
use secfinding::FindingKind;

#[tokio::test]
async fn emits_secfinding_only() {
    let classifier = ParameterClassifier::embedded().expect("embedded classifier");
    let map = AppMap::builder()
        .with_roles(vec![
            RoleAuth::new("owner").with_cookie("s", "1"),
            RoleAuth::new("prober").with_cookie("s", "2"),
        ])
        .endpoint(
            Endpoint::new(Method::Get, "/api/users/{id}")
                .with_parameter(classifier.classify("id", Some("1"))),
        )
        .build()
        .unwrap();

    let body = br#"{"email":"victim@example.com","name":"Victim","balance":9999,"padding":"xxxxxxxxxxxxxxxxxxxxxxxx"}"#.to_vec();

    let obs = MatrixObservation {
        owner: map.roles()[0].clone(),
        prober: map.roles()[1].clone(),
        probe: bolascan::RestProbe {
            url: "https://api.example.com/api/users/1".to_string(),
            method: Method::Get,
            role: map.roles()[1].clone(),
            id_param: None,
            original_id: Some("1".to_string()),
            mutated_id: None,
        },
        owner_status: 200,
        owner_body: body.clone(),
        prober_status: 200,
        prober_body: body,
    };

    let findings = BolaScan::new()
        .scan_offline(
            &map,
            map.roles(),
            &ScanConfig::new("https://api.example.com"),
            &[obs],
        )
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind(), FindingKind::AccessControl);
}
