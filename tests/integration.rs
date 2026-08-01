//! Integration tests: end-to-end paths through BolaScan with simulated replay.
//!
//! Each test drives the full `scan_with_replay` or `scan_offline` pipeline and
//! asserts on the emitted `secfinding::Finding` values, covering the happy path
//! and key error branches.

use appmap::{AppMap, Endpoint, Method, ParameterClassifier, RoleAuth};
use bolascan::{BolaScan, BolaScanError, MatrixObservation, RestProbe, ScanConfig};
use secfinding::FindingKind;

// --- helpers -----------------------------------------------------------------

async fn two_role_appmap_with_id_endpoint() -> AppMap {
    let classifier = ParameterClassifier::embedded().expect("embedded classifier");
    AppMap::builder()
        .with_roles(vec![
            RoleAuth::new("owner").with_cookie("session", "owner-tok"),
            RoleAuth::new("prober").with_cookie("session", "prober-tok"),
        ])
        .endpoint(
            Endpoint::new(Method::Get, "/api/users/{id}")
                .with_parameter(classifier.classify("id", Some("1"))),
        )
        .build()
        .unwrap()
}

// --- scan_offline: error paths -----------------------------------------------

#[tokio::test]
async fn scan_offline_empty_appmap_returns_error() {
    let classifier = ParameterClassifier::embedded().expect("embedded classifier");
    let empty_map = AppMap::builder()
        .with_roles(vec![
            RoleAuth::new("a").with_cookie("s", "1"),
            RoleAuth::new("b").with_cookie("s", "2"),
        ])
        .build()
        .unwrap();

    let result = BolaScan::new().scan_offline(
        &empty_map,
        empty_map.roles(),
        &ScanConfig::new("https://example.com"),
        &[],
    );
    assert!(matches!(result, Err(BolaScanError::EmptyAppMap)));
    let _ = classifier; // silence unused warning
}

#[tokio::test]
async fn scan_offline_single_role_returns_error() {
    let classifier = ParameterClassifier::embedded().expect("embedded classifier");
    let single_role_map = AppMap::builder()
        .with_roles(vec![RoleAuth::new("only").with_cookie("s", "1")])
        .endpoint(
            Endpoint::new(Method::Get, "/api/users/{id}")
                .with_parameter(classifier.classify("id", Some("1"))),
        )
        .build()
        .unwrap();

    let result = BolaScan::new().scan_offline(
        &single_role_map,
        single_role_map.roles(),
        &ScanConfig::new("https://example.com"),
        &[],
    );
    assert!(matches!(result, Err(BolaScanError::InsufficientRoles)));
}

// --- scan_offline: no-IDOR observation ----------------------------------------

#[tokio::test]
async fn scan_offline_denied_prober_emits_no_findings() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    let obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: "https://api.example.com/api/users/1".to_string(),
            method: Method::Get,
            role: roles[1].clone(),
            id_param: None,
            original_id: Some("1".to_string()),
            mutated_id: None,
        },
        owner_status: 200,
        owner_body: br#"{"email":"victim@example.com","name":"Victim"}"#.to_vec(),
        prober_status: 403,
        prober_body: b"Forbidden".to_vec(),
    };

    let findings = BolaScan::new()
        .scan_offline(&appmap, &roles, &config, &[obs])
        .unwrap();
    assert!(
        findings.is_empty(),
        "403 response must not produce an IDOR finding"
    );
}

#[tokio::test]
async fn scan_offline_404_prober_emits_no_findings() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    let obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: "https://api.example.com/api/users/1".to_string(),
            method: Method::Get,
            role: roles[1].clone(),
            id_param: None,
            original_id: Some("1".to_string()),
            mutated_id: None,
        },
        owner_status: 200,
        owner_body: br#"{"email":"victim@example.com","name":"Victim","balance":9000,"extra":"xxxxxxxxxxxxxxxx"}"#.to_vec(),
        prober_status: 404,
        prober_body: b"Not Found".to_vec(),
    };

    let findings = BolaScan::new()
        .scan_offline(&appmap, &roles, &config, &[obs])
        .unwrap();
    assert!(
        findings.is_empty(),
        "404 response must not produce an IDOR finding"
    );
}

// --- scan_offline: IDOR detection --------------------------------------------

#[tokio::test]
async fn scan_offline_identical_pii_bodies_emits_finding() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    // Body large enough (>50 bytes) with PII keywords
    let body =
        br#"{"email":"victim@example.com","name":"Victim User","balance":9999,"account":"ACC001"}"#
            .to_vec();

    let obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: "https://api.example.com/api/users/1".to_string(),
            method: Method::Get,
            role: roles[1].clone(),
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
        .scan_offline(&appmap, &roles, &config, &[obs])
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind(), FindingKind::AccessControl);
}

#[tokio::test]
async fn scan_offline_finding_has_correct_target() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let target = "https://my-target.example.com";
    let config = ScanConfig::new(target);

    let body = br#"{"email":"v@example.com","name":"Victim","balance":1,"account":"ACC1","extra":"padpadpadpadpad"}"#.to_vec();

    let obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: format!("{target}/api/users/1"),
            method: Method::Get,
            role: roles[1].clone(),
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
        .scan_offline(&appmap, &roles, &config, &[obs])
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].target().contains("my-target.example.com"),
        "finding target must match config target"
    );
}

// --- scan_offline: empty observations ----------------------------------------

#[tokio::test]
async fn scan_offline_empty_observations_emits_no_findings() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    let findings = BolaScan::new()
        .scan_offline(&appmap, &roles, &config, &[])
        .unwrap();
    assert!(findings.is_empty());
}

// --- scan_offline: multiple observations, only IDOR ones become findings ------

#[tokio::test]
async fn scan_offline_mixed_observations_only_idor_findings() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    let idor_body = br#"{"email":"x@y.com","name":"X","balance":1,"account":"ACC","extra":"xxxxxxxxxxxxxxxxx"}"#.to_vec();

    let safe_obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: "https://api.example.com/api/users/2".to_string(),
            method: Method::Get,
            role: roles[1].clone(),
            id_param: None,
            original_id: Some("2".to_string()),
            mutated_id: None,
        },
        owner_status: 200,
        owner_body: idor_body.clone(),
        prober_status: 403,
        prober_body: b"Forbidden".to_vec(),
    };

    let idor_obs = MatrixObservation {
        owner: roles[0].clone(),
        prober: roles[1].clone(),
        probe: RestProbe {
            url: "https://api.example.com/api/users/1".to_string(),
            method: Method::Get,
            role: roles[1].clone(),
            id_param: None,
            original_id: Some("1".to_string()),
            mutated_id: None,
        },
        owner_status: 200,
        owner_body: idor_body.clone(),
        prober_status: 200,
        prober_body: idor_body,
    };

    let findings = BolaScan::new()
        .scan_offline(&appmap, &roles, &config, &[safe_obs, idor_obs])
        .unwrap();

    assert_eq!(
        findings.len(),
        1,
        "only the IDOR observation should produce a finding"
    );
}

// --- scan_with_replay: full pipeline -----------------------------------------

#[tokio::test]
async fn scan_with_replay_all_403_no_findings() {
    // When every replay call returns 403, no role pair can show an IDOR.
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    let findings = BolaScan::new()
        .scan_with_replay(&appmap, &roles, &config, |_role, _probe| {
            (403, b"Forbidden".to_vec())
        })
        .unwrap();

    assert!(
        findings.is_empty(),
        "universal 403 -> no IDOR findings expected, got {} findings",
        findings.len()
    );
}

#[tokio::test]
async fn scan_with_replay_detects_idor_when_same_body_returned() {
    let appmap = two_role_appmap_with_id_endpoint().await;
    let roles = appmap.roles().to_vec();
    let config = ScanConfig::new("https://api.example.com");

    // Both roles get the exact same large PII body
    let body =
        br#"{"email":"victim@example.com","name":"Victim","balance":9999,"account":"ACC001"}"#;

    let findings = BolaScan::new()
        .scan_with_replay(&appmap, &roles, &config, |_role, _probe| {
            (200, body.to_vec())
        })
        .unwrap();

    assert!(
        !findings.is_empty(),
        "identical PII body for both roles must trigger at least one IDOR finding"
    );
    for f in &findings {
        assert_eq!(f.kind(), FindingKind::AccessControl);
    }
}
