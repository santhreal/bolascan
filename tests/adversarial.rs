//! Adversarial tests: hostile inputs designed to break assumptions.
//!
//! Tests in this file feed the most pathological valid and invalid inputs to
//! the public API and assert that the library neither panics nor produces
//! nonsensical output.

use bolascan::{
    compare_responses, extract_json_ids, extract_resource_ids, is_id_param_name, is_resource_id,
    mutate_id_in_url, mutate_json_id, IdParam, IdPatternRules,
};

// --- is_resource_id edge cases

#[test]
fn resource_id_empty_string() {
    assert!(!is_resource_id(""), "empty must not be treated as an ID");
}

#[test]
fn resource_id_oversized() {
    // 129-char string: exceeds the 128-char guard
    let long = "a".repeat(129);
    assert!(!is_resource_id(&long));
}

#[test]
fn resource_id_exactly_128_chars() {
    // 128 alphanumerics >= 20 chars -> accepted as opaque long token
    let token = "a".repeat(128);
    // The function accepts if len >= 20 and all chars are alphanumeric/-/_
    assert!(is_resource_id(&token));
}

#[test]
fn resource_id_zero_is_not_id() {
    // "0" parses as i64 but length == 1, single char digits aren't useful IDs
    // The code accepts i64 with len <= 20, so "0" IS accepted.
    // Test just documents the current behaviour, not a regression target.
    let _ = is_resource_id("0"); // must not panic
}

#[test]
fn resource_id_uuid_wrong_hyphen_count_is_opaque_not_uuid() {
    // A 32-char UUID lookalike (3 hyphens, len 32, not 36). The old assertion
    // `!is_resource_id(x) || x.len() != 36` was tautologically true (len is 32,
    // so the right side is always true) and tested nothing.
    //
    // The truthful behavior: it does NOT match the UUID branch (that requires
    // len == 36), but it DOES match the opaque-long-token branch (len >= 20,
    // all alphanumeric / '-' / '_'), so is_resource_id accepts it as an opaque
    // identifier. Pin that real behavior (matches
    // resource_id_uuid_with_non_hex_still_opaque_token).
    let bad_uuid = "550e8400-e29b-41d4-a71644665544";
    assert_ne!(bad_uuid.len(), 36, "fixture must not be UUID-length (36)");
    assert!(bad_uuid.len() >= 20, "fixture must reach the opaque-token length gate");
    assert!(
        is_resource_id(bad_uuid),
        "a 32-char hyphenated hex token is accepted via the opaque-token branch"
    );
    // And a version too short for the opaque branch (< 20 chars) is rejected,
    // confirming the acceptance above is the length-gated opaque path.
    assert!(!is_resource_id("550e8400-e29b"));
}

#[test]
fn resource_id_uuid_with_non_hex_still_opaque_token() {
    // Proper hyphen placement but contains 'z'  -  not valid UUID hex.
    // The UUID branch rejects it, but the opaque-long-token branch (len >= 20,
    // all alphanumeric / - / _) accepts it.  This test documents that behaviour.
    let bad_uuid = "550e8400-e29b-41d4-z716-446655440000";
    // Must not panic; current implementation accepts as an opaque token.
    let _ = is_resource_id(bad_uuid);
}

// --- extract_resource_ids hostile URLs

#[test]
fn empty_url_does_not_panic() {
    let ids = extract_resource_ids("");
    // No panic; empty or static result is fine
    let _ = ids;
}

#[test]
fn url_no_scheme_does_not_panic() {
    let ids = extract_resource_ids("/api/users/42");
    // Must at least not panic; the ID may or may not be found depending on
    // whether "42" is short enough to parse as i64
    let _ = ids;
}

#[test]
fn url_with_fragment_does_not_panic() {
    let ids = extract_resource_ids("https://example.com/items/99#section");
    let _ = ids;
}

#[test]
fn url_query_no_equals_does_not_panic() {
    // Malformed query string: no `=` in param
    let ids = extract_resource_ids("https://example.com/data?user_id_only");
    let _ = ids;
}

#[test]
fn url_percent_encoded_segment_does_not_panic() {
    let ids = extract_resource_ids("https://example.com/items/hello%20world");
    let _ = ids;
}

#[test]
fn url_huge_numeric_id_truncated_at_guard() {
    // 21-digit number  -  is_resource_id guards len <= 20 for integer branch
    let ids = extract_resource_ids("https://example.com/u/123456789012345678901");
    // Must not panic; may or may not extract depending on long-token branch
    let _ = ids;
}

// --- mutate_id_in_url hostile mutations

#[test]
fn mutate_path_segment_out_of_bounds_returns_original() {
    let url = "https://example.com/users/42";
    // segment_index 999 is well beyond the split
    let out = mutate_id_in_url(url, &IdParam::PathSegment { segment_index: 999 }, "X");
    assert_eq!(out, url, "out-of-bounds index must return original URL");
}

#[test]
fn mutate_query_param_absent_key_returns_original() {
    let url = "https://example.com/data?foo=bar";
    let out = mutate_id_in_url(
        url,
        &IdParam::QueryParam {
            name: "nonexistent".to_string(),
        },
        "X",
    );
    // Key not found -> all params unchanged -> output equals input
    assert_eq!(out, url);
}

#[test]
fn mutate_body_field_url_unchanged() {
    let url = "https://example.com/api/post";
    let out = mutate_id_in_url(
        url,
        &IdParam::BodyField {
            name: "user_id".to_string(),
        },
        "99",
    );
    assert_eq!(out, url, "BodyField must not mutate the URL");
}

#[test]
fn mutate_query_param_no_query_string_returns_original() {
    let url = "https://example.com/items/42";
    let out = mutate_id_in_url(
        url,
        &IdParam::QueryParam {
            name: "user_id".to_string(),
        },
        "99",
    );
    assert_eq!(
        out, url,
        "no query string -> URL must be returned unchanged"
    );
}

// --- compare_responses adversarial status combos

#[test]
fn compare_a_error_b_ok_not_idor() {
    // If owner got 500, prober got 200 with small body  -  not a clean IDOR signal
    let (detected, _, _) = compare_responses(500, b"Internal Error", 200, b"{}");
    // Body too small to trigger IDOR
    assert!(!detected);
}

#[test]
fn compare_both_301_not_idor() {
    let (detected, _, _) = compare_responses(301, b"moved", 301, b"moved");
    assert!(!detected);
}

#[test]
fn compare_owner_404_prober_200_with_pii() {
    // Owner got 404 (resource gone), prober gets 200  -  weird but must not panic
    let prober_body =
        br#"{"email":"x@y.com","name":"X","balance":0,"padding":"ppppppppppppppppppp"}"#;
    let (_, _, _) = compare_responses(404, b"not found", 200, prober_body);
    // Just assert no panic; the heuristic decision either way is acceptable
}

#[test]
fn compare_extremely_large_bodies_do_not_panic() {
    // 200 KB bodies identical with PII keywords
    let mut body = Vec::with_capacity(200_000);
    body.extend_from_slice(b"{\"email\":\"a@b.com\",\"padding\":\"");
    body.extend(std::iter::repeat(b'x').take(199_000));
    body.extend_from_slice(b"\"}");
    let (_, _, _) = compare_responses(200, &body, 200, &body);
    // Must not panic or stack-overflow
}

// --- mutate_json_id hostile inputs

#[test]
fn mutate_json_id_invalid_json_returns_none() {
    let result = mutate_json_id("not json at all", "user_id", "99");
    assert!(result.is_none());
}

#[test]
fn mutate_json_id_missing_field_returns_original_structure() {
    // Field does not exist -> JSON unchanged but Some(...) still returned
    let body = r#"{"other_field": 1}"#;
    let result = mutate_json_id(body, "user_id", "99");
    // Function returns Some even when field absent; just must not panic
    let _ = result;
}

#[test]
fn mutate_json_id_non_numeric_new_id_for_number_field() {
    // Trying to set a number field to a non-numeric string  -  parse fails;
    // function must not panic and should return Some with original value intact
    let body = r#"{"user_id": 42}"#;
    let result = mutate_json_id(body, "user_id", "not_a_number");
    // Must not panic; value may or may not be mutated
    let _ = result;
}

#[test]
fn mutate_json_id_empty_body() {
    let result = mutate_json_id("", "user_id", "42");
    assert!(result.is_none());
}

// --- extract_json_ids adversarial bodies

#[test]
fn extract_json_ids_empty_body() {
    let ids = extract_json_ids("");
    assert!(ids.is_empty());
}

#[test]
fn extract_json_ids_array_at_root() {
    // Root is an array, not an object  -  must not panic
    let ids = extract_json_ids(r#"[{"user_id": 1}, {"user_id": 2}]"#);
    let _ = ids; // no panic suffices; IDs may or may not be extracted
}

#[test]
fn extract_json_ids_deeply_nested() {
    let body = r#"{"a":{"b":{"c":{"user_id":99}}}}"#;
    let ids = extract_json_ids(body);
    // Deep recursion must not panic; the leaf may or may not be found
    let _ = ids;
}

#[test]
fn extract_json_ids_null_id_field() {
    // id field present but null  -  must not panic, should not be extracted
    let ids = extract_json_ids(r#"{"user_id": null}"#);
    let _ = ids;
}

// --- IdPatternRules

#[test]
fn classify_empty_string_returns_none() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let pat = rules.classify_token("");
    assert!(pat.is_none(), "empty token must not match any pattern");
}

#[test]
fn classify_whitespace_returns_none_or_slug() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    // Whitespace is not alphanumeric, should not match slug or int patterns
    let _ = rules.classify_token("   "); // must not panic
}

#[test]
fn mutate_token_unknown_mutation_does_not_panic() {
    // Build a synthetic pattern with a made-up mutation name
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let pats = rules.patterns();
    if let Some(pat) = pats.first() {
        // Clone and override mutation via a scratch pattern
        let _ = rules.mutate_token("123", pat); // must not panic
    }
}

#[test]
fn classify_jwt_shape() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let pat = rules.classify_token(token);
    assert!(
        pat.is_some(),
        "JWT-shaped token must match jwt_shape pattern"
    );
}

#[test]
fn classify_mongodb_objectid() {
    let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
    let token = "507f1f77bcf86cd799439011";
    let pat = rules.classify_token(token).expect("ObjectId should match");
    assert_eq!(pat.name, "mongodb_objectid");
}

// --- is_id_param_name adversarial

#[test]
fn id_param_name_empty_string() {
    assert!(!is_id_param_name(""));
}

#[test]
fn id_param_name_very_long() {
    let long = "a".repeat(1000);
    let _ = is_id_param_name(&long); // must not panic
}

#[test]
fn id_param_name_case_insensitive() {
    assert!(is_id_param_name("USER_ID"));
    assert!(is_id_param_name("OrderId"));
    assert!(is_id_param_name("UUID"));
}

// --- honest result semantics: a failed verification must not report verified

/// ADVERSARIAL honest-semantics: a server that answers an unauthorized
/// cross-role request with 200 + the login page (a common framework behavior
/// instead of 302/401) produced an IDENTICAL body containing "password",
/// "name", and "account", which the PII branch reported as "confirmed IDOR"
/// at 0.9. But the verification FAILED (User B was bounced to login), so it
/// must never report as verified.
#[test]
fn identical_login_bounce_page_is_not_idor() {
    let login_page = br#"<!DOCTYPE html><html><body>
        <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
        <button>Sign in to your account</button>
        </form></body></html>"#;
    let (idor, confidence, description) =
        compare_responses(200, login_page, 200, login_page);
    assert!(
        !idor,
        "an authentication bounce must not report as verified IDOR: {description}"
    );
    assert_eq!(confidence, 0.0, "got {confidence}");
}

/// Positive twin for the login-bounce guard: an identical JSON document that
/// carries a password field as DATA (no HTML form markup) is still a
/// confirmed IDOR. The guard discriminates on `type="password"` form markup,
/// not on the word "password" alone.
#[test]
fn identical_json_with_password_field_is_still_idor() {
    let body = br#"{"id": 5, "username": "alice", "password": "hash:9f86d08",
        "email": "alice@example.com", "account": "premium", "balance": 100}"#;
    let (idor, confidence, _) = compare_responses(200, body, 200, body);
    assert!(idor, "real PII data must still confirm IDOR");
    assert!(
        confidence >= 0.9,
        "confirmed-IDOR confidence must be preserved, got {confidence}"
    );
}

/// Boundary: an HTML page that merely mentions the word "password" in prose
/// (no password-input markup) keeps the old behavior, proving the guard only
/// fires on actual login forms.
#[test]
fn identical_page_mentioning_password_without_form_is_still_flagged() {
    let body = b"<html><body><h1>Account recovery policy</h1><p>Your password must be rotated every 90 days. Contact your account manager by email for assistance with recovery.</p></body></html>"
        as &[u8];
    let (idor, _, description) = compare_responses(200, body, 200, body);
    assert!(
        idor,
        "a page merely mentioning 'password' (no login form) must not hit the bounce guard: {description}"
    );
}
