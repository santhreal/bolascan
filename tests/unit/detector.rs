//! Unit tests lifted from karyx `idor.rs`.

use bolascan::{
    compare_responses, extract_json_ids, extract_resource_ids, is_id_param_name, mutate_id_in_url,
    mutate_json_id, IdParam,
};

#[test]
fn extract_numeric_id_from_path() {
    let ids = extract_resource_ids("https://api.example.com/users/12345/orders");
    assert!(ids
        .iter()
        .any(|(p, v)| matches!(p, IdParam::PathSegment { .. }) && v == "12345"));
}

#[test]
fn extract_uuid_from_path() {
    let ids =
        extract_resource_ids("https://api.example.com/orders/550e8400-e29b-41d4-a716-446655440000");
    assert!(ids
        .iter()
        .any(|(_, v)| v == "550e8400-e29b-41d4-a716-446655440000"));
}

#[test]
fn extract_mongodb_objectid() {
    let ids = extract_resource_ids("https://api.example.com/docs/507f1f77bcf86cd799439011");
    assert!(ids.iter().any(|(_, v)| v == "507f1f77bcf86cd799439011"));
}

#[test]
fn extract_id_from_query_param() {
    let ids = extract_resource_ids("https://api.example.com/data?user_id=42&page=1");
    assert!(ids
        .iter()
        .any(|(p, v)| matches!(p, IdParam::QueryParam { name } if name == "user_id") && v == "42"));
}

#[test]
fn no_ids_in_static_path() {
    let ids = extract_resource_ids("https://example.com/about/team");
    assert!(ids.is_empty(), "Static paths should have no IDs: {ids:?}");
}

#[test]
fn id_param_name_detection() {
    assert!(is_id_param_name("user_id"));
    assert!(is_id_param_name("orderId"));
    assert!(is_id_param_name("id"));
    assert!(is_id_param_name("workspace"));
    assert!(!is_id_param_name("page"));
}

#[test]
fn idor_detected_same_response() {
    let body = br#"{"email": "user@example.com", "name": "John", "balance": 1000}"#;
    let (detected, confidence, _) = compare_responses(200, body, 200, body);
    assert!(detected);
    assert!(confidence >= 0.9, "confidence={confidence}");
}

#[test]
fn idor_denied_403() {
    let a_body = br#"{"email": "user@example.com"}"#;
    let b_body = b"Forbidden";
    let (detected, _, _) = compare_responses(200, a_body, 403, b_body);
    assert!(!detected);
}

#[test]
fn idor_denied_404() {
    let a_body = br#"{"data": "secret"}"#;
    let b_body = b"Not found";
    let (detected, _, _) = compare_responses(200, a_body, 404, b_body);
    assert!(!detected);
}

#[test]
fn idor_redirect_to_login() {
    let (detected, _, _) = compare_responses(200, b"data", 302, b"Redirecting");
    assert!(!detected);
}

#[test]
fn mutate_path_id() {
    let url = "https://api.example.com/users/123/orders";
    let mutated = mutate_id_in_url(url, &IdParam::PathSegment { segment_index: 4 }, "456");
    assert!(mutated.contains("/456/"), "mutated={mutated}");
}

#[test]
fn mutate_query_id() {
    let url = "https://api.example.com/data?user_id=42&page=1";
    let mutated = mutate_id_in_url(
        url,
        &IdParam::QueryParam {
            name: "user_id".to_string(),
        },
        "99",
    );
    assert!(mutated.contains("user_id=99"));
    assert!(mutated.contains("page=1"));
}

#[test]
fn mutate_path_id_preserves_query_string() {
    // Regression: splitting the whole URL on '/' glued `?page=1` onto the last
    // path segment, so mutating that segment silently dropped the query.
    let url = "https://api.example.com/users/123?page=1&sort=asc";
    let mutated = mutate_id_in_url(url, &IdParam::PathSegment { segment_index: 4 }, "456");
    assert!(mutated.contains("/users/456"), "id segment mutated: {mutated}");
    assert!(mutated.contains("?page=1&sort=asc"), "query preserved: {mutated}");
    assert!(!mutated.contains("123"), "old id gone: {mutated}");
}

#[test]
fn mutate_path_id_preserves_fragment() {
    let url = "https://api.example.com/users/123#section";
    let mutated = mutate_id_in_url(url, &IdParam::PathSegment { segment_index: 4 }, "456");
    assert!(mutated.contains("/users/456"), "{mutated}");
    assert!(mutated.ends_with("#section"), "fragment preserved: {mutated}");
}

#[test]
fn mutate_json_nested_dotted_path() {
    // Regression: only the last path component was looked up at the ROOT, so a
    // nested `outer.user_id` never got mutated.
    let body = r#"{"outer": {"user_id": "42", "keep": "x"}, "top": "y"}"#;
    let mutated = mutate_json_id(body, "outer.user_id", "99").expect("nested path resolves");
    let v: serde_json::Value = serde_json::from_str(&mutated).unwrap();
    assert_eq!(v["outer"]["user_id"], "99", "nested id mutated: {mutated}");
    assert_eq!(v["outer"]["keep"], "x", "sibling untouched");
    assert_eq!(v["top"], "y", "unrelated field untouched");
}

#[test]
fn mutate_json_array_indexed_path() {
    let body = r#"{"items": [{"id": 1}, {"id": 2}]}"#;
    let mutated = mutate_json_id(body, "items[1].id", "77").expect("array path resolves");
    let v: serde_json::Value = serde_json::from_str(&mutated).unwrap();
    assert_eq!(v["items"][0]["id"], 1, "index 0 untouched");
    assert_eq!(v["items"][1]["id"], 77, "index 1 mutated: {mutated}");
}

#[test]
fn mutate_json_root_array_path() {
    let body = r#"[{"user_id": "a"}, {"user_id": "b"}]"#;
    let mutated = mutate_json_id(body, "[0].user_id", "z").expect("root-array path resolves");
    let v: serde_json::Value = serde_json::from_str(&mutated).unwrap();
    assert_eq!(v[0]["user_id"], "z");
    assert_eq!(v[1]["user_id"], "b");
}

#[test]
fn mutate_json_unresolvable_path_returns_none() {
    let body = r#"{"user_id": "42"}"#;
    // A dotted path that doesn't exist must return None, not a silently
    // unchanged body pretending to be mutated.
    assert!(mutate_json_id(body, "nope.missing", "x").is_none());
}

#[test]
fn small_response_not_idor() {
    let (detected, _, _) = compare_responses(200, b"OK", 200, b"OK");
    assert!(!detected);
}

#[test]
fn extract_json_numeric_id() {
    let body = r#"{"user_id": 42, "name": "Alice"}"#;
    let ids = extract_json_ids(body);
    assert!(ids.iter().any(|(k, v)| k == "user_id" && v == "42"));
}

#[test]
fn extract_json_uuid_id() {
    let body = r#"{"order_id": "550e8400-e29b-41d4-a716-446655440000", "status": "pending"}"#;
    let ids = extract_json_ids(body);
    assert!(ids.iter().any(|(k, _)| k == "order_id"));
}

#[test]
fn mutate_json_numeric_id() {
    let body = r#"{"user_id": 42, "name": "Alice"}"#;
    let mutated = mutate_json_id(body, "user_id", "99").unwrap();
    assert!(mutated.contains("99"));
    assert!(!mutated.contains("42"));
}

#[test]
fn both_errors_not_idor() {
    let (detected, _, _) = compare_responses(500, b"Error", 500, b"Error");
    assert!(!detected);
}
#[test]
fn extract_resource_ids_strips_path_fragment() {
    let ids = extract_resource_ids("http://example.com/api/users/12345#profile");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].0, IdParam::PathSegment { segment_index: 5 });
    assert_eq!(ids[0].1, "12345");
}
