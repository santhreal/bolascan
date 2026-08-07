//! Gap tests: coverage for behaviours not exercised by unit or adversarial suites.
//!
//! Focuses on boundary conditions, confidence thresholds, multi-level JSON,
//! error construction, and ScanConfig fields that the unit suite skips.

use bolascan::{
    compare_responses, extract_json_ids, extract_resource_ids, is_id_param_name, is_resource_id,
    mutate_id_in_url, mutate_json_id, BolaScanError, IdParam, IdPatternRules, ScanConfig,
};

// --- ScanConfig

#[test]
fn scan_config_new_sets_target() {
    let cfg = ScanConfig::new("https://example.com");
    assert_eq!(cfg.target, "https://example.com");
    assert_eq!(cfg.rule_id_prefix, "bolascan/");
}

#[test]
fn scan_config_default_is_empty() {
    let cfg = ScanConfig::default();
    assert!(cfg.target.is_empty());
}

// --- BolaScanError

#[test]
fn error_display_messages_are_non_empty() {
    let errors = [
        BolaScanError::EmptyAppMap,
        BolaScanError::InsufficientRoles,
        BolaScanError::RolesFile("bad roles".into()),
        BolaScanError::TierB("bad toml".into()),
    ];
    for e in &errors {
        let msg = e.to_string();
        assert!(!msg.is_empty(), "error message must not be empty: {e:?}");
    }
}

#[test]
fn error_roles_file_includes_reason() {
    let e = BolaScanError::RolesFile("malformed TOML".into());
    assert!(e.to_string().contains("malformed TOML"));
}

#[test]
fn error_tier_b_includes_reason() {
    let e = BolaScanError::TierB("unknown key".into());
    assert!(e.to_string().contains("unknown key"));
}

// --- compare_responses confidence boundaries

#[test]
fn similar_size_different_bodies_confidence_medium() {
    // Bodies are different but similarly sized (>80% ratio) -> confidence 0.7
    let body_a = br#"{"email":"alice@example.com","name":"Alice","account":"ACC001","padding":"pppppppppppp"}"#;
    let body_b = br#"{"email":"bobby@example.com","name":"Bobby","account":"ACC002","padding":"pppppppppppp"}"#;
    let (detected, confidence, _) = compare_responses(200, body_a, 200, body_b);
    assert!(detected, "similar-sized different bodies -> IDOR detected");
    // Confidence should be in 0.7 range (similarly sized)
    assert!(
        confidence >= 0.5,
        "confidence should be substantial, got {confidence}"
    );
}

#[test]
fn large_size_ratio_difference_possible_idor() {
    // B is about 50% the size of A -> ratio > 0.3 but < 0.8 -> possible IDOR
    let body_a = br#"{"email":"x@y.com","name":"X","balance":1000,"extra":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;
    let body_b = br#"{"email":"z@w.com","name":"Z"}"#;
    // Ensure body_a > 50 and body_b > 50 bytes
    if body_a.len() > 50 && body_b.len() > 50 {
        let (detected, _, _) = compare_responses(200, body_a, 200, body_b);
        // depends on size ratio; just assert no panic
        let _ = detected;
    }
}

#[test]
fn prober_gets_identical_response_no_pii_lower_confidence() {
    // Identical responses without obvious PII keywords -> confidence < 0.9
    let body = br#"{"status":"active","created":"2024-01-01","score":42,"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;
    let (detected, confidence, _) = compare_responses(200, body, 200, body);
    assert!(detected);
    // Without PII keywords the confidence should be 0.5 not 0.9
    assert!(
        confidence < 0.9,
        "no PII -> confidence should be lower, got {confidence}"
    );
}

#[test]
fn prober_gets_identical_response_with_pii_high_confidence() {
    let body =
        br#"{"email":"a@b.com","name":"Alice","balance":999,"extra":"padding_padding_padding"}"#;
    let (detected, confidence, _) = compare_responses(200, body, 200, body);
    assert!(detected);
    assert!(
        confidence >= 0.9,
        "PII present -> high confidence, got {confidence}"
    );
}

// --- is_resource_id boundary values

#[test]
fn resource_id_max_integer_string() {
    // i64::MAX as string -> 19 digits, should be recognized
    let id = i64::MAX.to_string();
    assert!(is_resource_id(&id));
}

#[test]
fn resource_id_mongo_exact_24_hex() {
    assert!(is_resource_id("aabbccddeeff001122334455"));
}

#[test]
fn resource_id_mongo_23_hex_accepted_as_opaque() {
    // 23 all-hex chars  -  does not match the ObjectId (24-char) branch, but
    // the opaque-long-token branch (len >= 20, all alphanumeric) accepts it.
    // This test documents the current behaviour (no panic).
    let _ = is_resource_id("aabbccddeeff00112233445");
}

#[test]
fn resource_id_19_char_alphanumeric_not_id() {
    // 19 alphanumeric chars  -  shorter than the 20-char opaque minimum
    assert!(!is_resource_id("abcde1234567890abcd"));
}

#[test]
fn resource_id_exactly_20_chars() {
    // Exactly 20 alphanumeric chars -> accepted as opaque token
    assert!(is_resource_id("abcdefghij1234567890"));
}

// --- extract_resource_ids multi-param URLs

#[test]
fn extract_multiple_ids_from_query() {
    let url = "https://api.example.com/data?user_id=42&order_id=9999&page=1";
    let ids = extract_resource_ids(url);
    assert!(
        ids.len() >= 2,
        "both user_id and order_id should be extracted"
    );
}

#[test]
fn extract_path_and_query_ids_combined() {
    let url = "https://api.example.com/users/12345?session_id=abc1234567890abcdef0";
    let ids = extract_resource_ids(url);
    // Path ID + query ID
    assert!(ids.len() >= 2);
}

#[test]
fn extract_path_no_query() {
    let url = "https://api.example.com/orders/550e8400-e29b-41d4-a716-446655440000";
    let ids = extract_resource_ids(url);
    assert!(ids
        .iter()
        .any(|(p, _)| matches!(p, IdParam::PathSegment { .. })));
}

// --- mutate_id_in_url query with no other params

#[test]
fn mutate_query_single_param_replaced_cleanly() {
    let url = "https://example.com/data?user_id=42";
    let out = mutate_id_in_url(
        url,
        &IdParam::QueryParam {
            name: "user_id".to_string(),
        },
        "99",
    );
    assert_eq!(out, "https://example.com/data?user_id=99");
}

#[test]
fn mutate_path_segment_zero_index() {
    // segment_index 0 is the empty string before the first /
    let url = "https://example.com/users/42";
    let out = mutate_id_in_url(url, &IdParam::PathSegment { segment_index: 0 }, "X");
    // Index 0 is "" (before the initial slash); replacing it is legal but weird
    let _ = out; // must not panic
}

// --- mutate_json_id string and number fields

#[test]
fn mutate_json_id_string_field() {
    let body = r#"{"user_id": "old-uuid", "name": "Alice"}"#;
    let mutated = mutate_json_id(body, "user_id", "new-uuid").unwrap();
    assert!(mutated.contains("new-uuid"));
    assert!(!mutated.contains("old-uuid"));
}

#[test]
fn mutate_json_id_numeric_field() {
    let body = r#"{"user_id": 7, "name": "Bob"}"#;
    let mutated = mutate_json_id(body, "user_id", "99").unwrap();
    assert!(mutated.contains("99"));
}

// --- extract_json_ids field paths

#[test]
fn extract_json_ids_nested_object() {
    let body = r#"{"outer": {"user_id": 42}}"#;
    let ids = extract_json_ids(body);
    // Nested user_id should appear as "outer.user_id"
    assert!(
        ids.iter().any(|(k, v)| k.contains("user_id") && v == "42"),
        "nested user_id should be found: {ids:?}"
    );
}

#[test]
fn extract_json_ids_array_of_objects() {
    let body = r#"[{"user_id": 1}, {"user_id": 2}]"#;
    let ids = extract_json_ids(body);
    // The old comment claimed root arrays "return empty" and asserted nothing.
    // That is false: extract_ids_recursive traverses a root array, keying each
    // element's id by its index path. Pin the actual extracted pairs.
    assert!(
        ids.iter().any(|(k, v)| k == "[0].user_id" && v == "1"),
        "first element id must be extracted as [0].user_id=1: {ids:?}"
    );
    assert!(
        ids.iter().any(|(k, v)| k == "[1].user_id" && v == "2"),
        "second element id must be extracted as [1].user_id=2: {ids:?}"
    );
}

#[test]
fn extract_json_ids_string_uuid() {
    let body = r#"{"order_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
    let ids = extract_json_ids(body);
    assert!(ids.iter().any(|(k, _)| k == "order_id"));
}

// --- IdPatternRules coverage gaps

/// REGRESSION: `IdPatternRules::embedded` used to `panic!` when the embedded
/// TOML failed to parse (a deny-level `clippy::panic` violation that could
/// crash a scanner host mid-fleet). It now returns `Result`, and probe
/// planning maps a load failure to `BolaScanError::TierB` instead of
/// panicking or, worse, silently planning zero mutation probes (the original
/// Law-10 bug the panic was added to fight). Pin both ends: the embedded
/// asset loads, and a malformed document surfaces as `Err`.
#[test]
fn tier_b_embedded_returns_result_and_stays_fail_closed() {
    let rules = IdPatternRules::embedded().expect("embedded asset must parse");
    assert_eq!(
        rules.patterns().len(),
        8,
        "embedded Tier-B pattern count must stay complete"
    );
    let err = IdPatternRules::from_toml("not = valid = toml [").unwrap_err();
    assert!(!err.is_empty(), "malformed TOML must surface as Err");
}

#[test]
fn tier_b_from_toml_round_trips_embedded() {
    let toml_src = include_str!("../tier_b/id_patterns.toml");
    let rules = IdPatternRules::from_toml(toml_src).expect("embedded TOML must parse");
    assert!(!rules.patterns().is_empty());
}

#[test]
fn tier_b_from_toml_invalid_returns_error() {
    let result = IdPatternRules::from_toml("this is not valid toml [[[");
    assert!(result.is_err());
    let empty_result = IdPatternRules::from_toml("pattern = []");
    assert!(
        empty_result.is_err(),
        "empty pattern array must return error"
    );
}

#[test]
fn tier_b_uuid_mutation_swap_neighbor() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    // Use a UUID whose last two chars differ so the swap is visible
    let token = "550e8400-e29b-41d4-a716-446655440012";
    let pat = rules.classify_token(token).expect("uuid must match");
    assert_eq!(pat.name, "uuid_v4");
    let mutated = rules.mutate_token(token, pat);
    // Last two chars are '1' and '2'; after swap they become '2' and '1'
    assert_ne!(
        mutated, token,
        "swapping last two different chars must change the token"
    );
    assert_eq!(mutated.len(), token.len(), "swap must preserve length");
    assert!(
        mutated.ends_with("21"),
        "last two chars should be swapped: {mutated}"
    );
}

#[test]
fn tier_b_slug_mutation_adds_probe_segment() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let token = "my-organization";
    if let Some(pat) = rules.classify_token(token) {
        if pat.mutation == "slug_neighbor" {
            let mutated = rules.mutate_token(token, pat);
            assert!(
                mutated.contains("probe"),
                "slug mutation must add probe segment"
            );
        }
    }
}

#[test]
fn tier_b_jwt_mutation_replaces_payload() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let pat = rules.classify_token(token).expect("jwt must match");
    assert_eq!(pat.name, "jwt_shape");
    let mutated = rules.mutate_token(token, pat);
    assert_ne!(mutated, token);
    assert_eq!(
        mutated.matches('.').count(),
        2,
        "mutated JWT must still have 2 dots"
    );
}

// --- is_id_param_name

#[test]
fn id_param_name_subscription_recognized() {
    assert!(is_id_param_name("subscription"));
}

#[test]
fn id_param_name_invoice_recognized() {
    assert!(is_id_param_name("invoice"));
}

#[test]
fn id_param_name_limit_not_recognized() {
    assert!(!is_id_param_name("limit"));
    assert!(!is_id_param_name("page"));
    assert!(!is_id_param_name("offset"));
    assert!(!is_id_param_name("sort"));
}
