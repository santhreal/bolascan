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
