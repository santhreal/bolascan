use bolascan::compare_cross_role;

#[test]
fn respdiff_populated_on_compare() {
    let body =
        br#"{"email":"a@b.c","name":"Alice","balance":1000,"extra":"padding-padding-padding"}"#;
    let result = compare_cross_role(200, body, 200, body);
    assert!(result.idor_detected);
    assert!(result.respdiff.body_similarity >= 0.99);
}

#[test]
fn denied_has_zero_confidence_idor() {
    let body =
        br#"{"email":"a@b.c","name":"Alice","balance":1000,"extra":"padding-padding-padding"}"#;
    let result = compare_cross_role(200, body, 403, b"forbidden");
    assert!(!result.idor_detected);
}
#[test]
fn privacy_fields_extracted_from_nested_json() {
    let body = br#"{"data":{"user":{"email":"admin@example.com","secret_token":"xyz123"}},"extra":"padding-padding-padding-padding"}"#;
    let result = compare_cross_role(200, body, 200, body);
    assert!(result.leaked_privacy_fields.contains(&"email".to_string()));
    assert!(result.leaked_privacy_fields.contains(&"secret_token".to_string()));
}

#[test]
fn privacy_fields_extracted_from_json_array() {
    let body = br#"[{"ssn":"123-45-6789","name":"Bob"},{"ssn":"987-65-4321","name":"Alice"}]"#;
    let result = compare_cross_role(200, body, 200, body);
    assert!(result.leaked_privacy_fields.contains(&"ssn".to_string()));
}
#[test]
fn privacy_fields_extracted_from_non_json_text() {
    let body = b"email=user%40example.com&secret=my_secret_token_value_extra_padding";
    let result = compare_cross_role(200, body, 200, body);
    assert!(result.leaked_privacy_fields.contains(&"email".to_string()));
    assert!(result.leaked_privacy_fields.contains(&"secret".to_string()));
}
