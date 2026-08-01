//! Resource-ID extraction and mutation (lifted from karyx `idor.rs`).

use std::collections::HashMap;

/// Where the resource ID appears in a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdParam {
    /// In the URL path: `/api/users/{id}`.
    PathSegment {
        /// Zero-based index of the path segment holding the resource id.
        segment_index: usize,
    },
    /// In a query parameter: `?user_id=123`.
    QueryParam {
        /// Query parameter name (without `=`).
        name: String,
    },
    /// In the request body (JSON): `{"user_id": 123}`.
    BodyField {
        /// JSON field name or dotted path leaf used by [`mutate_json_id`].
        name: String,
    },
}

/// Endpoint with an identified resource reference to test.
#[derive(Debug, Clone)]
pub struct IdorTarget {
    /// Full request URL including scheme when known.
    pub url: String,
    /// HTTP method (e.g. `GET`, `POST`).
    pub method: String,
    /// Location of the resource identifier within the request.
    pub id_param: IdParam,
    /// Observed resource id for the authenticated owner role.
    pub original_id: String,
    /// Optional JSON or form body when the id appears in the body.
    pub body: Option<String>,
    /// Extra headers to replay with the probe.
    pub headers: HashMap<String, String>,
}

/// Extract resource IDs from a URL (path segments + query params).
#[must_use]
pub fn extract_resource_ids(url: &str) -> Vec<(IdParam, String)> {
    let mut ids = Vec::new();

    if let Some(path) = url.split('?').next() {
        let segments: Vec<&str> = path.split('/').collect();
        for (i, segment) in segments.iter().enumerate() {
            if is_resource_id(segment) {
                ids.push((
                    IdParam::PathSegment { segment_index: i },
                    segment.to_string(),
                ));
            }
        }
    }

    if let Some(query) = url.split('?').nth(1) {
        for param in query.split('&') {
            if let Some((name, value)) = param.split_once('=') {
                // Percent-decode before the ID/name checks so a percent-encoded
                // id (e.g. `id=%35%35%30...` or an encoded UUID) is still
                // recognized. Store the RAW name/value so downstream mutation
                // continues to operate on the URL's original encoded form.
                let decoded_name = percent_decode(name);
                let decoded_value = percent_decode(value);
                if is_id_param_name(&decoded_name) || is_resource_id(&decoded_value) {
                    ids.push((
                        IdParam::QueryParam {
                            name: name.to_string(),
                        },
                        value.to_string(),
                    ));
                }
            }
        }
    }

    ids
}

/// Minimal, dependency-free percent-decoder for URL components.
///
/// Decodes `%XX` escapes; leaves malformed escapes and all other bytes verbatim.
/// `+` is intentionally NOT treated as a space so path-style components are not
/// altered; this is used only to normalize a value before an ID heuristic check,
/// never to rewrite the request.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                // Safe: h,l < 16 so h*16+l < 256.
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Check if a string looks like a resource identifier.
#[must_use]
pub fn is_resource_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }

    if s.parse::<i64>().is_ok() && s.len() <= 20 {
        return true;
    }

    if s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4 {
        let hex_only = s.replace('-', "");
        if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    if s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    if s.len() >= 20
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return true;
    }

    false
}

/// Check if a parameter name suggests it's an ID field.
#[must_use]
pub fn is_id_param_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("_id")
        || lower.ends_with("id")
        || lower == "id"
        || lower == "uid"
        || lower == "uuid"
        || lower.ends_with("_key")
        || lower.ends_with("_token")
        || lower == "slug"
        || lower == "handle"
        || lower == "account"
        || lower == "user"
        || lower == "org"
        || lower == "project"
        || lower == "workspace"
        || lower == "order"
        || lower == "invoice"
        || lower == "subscription"
}

/// Compare two responses to determine if IDOR is present.
#[must_use]
pub fn compare_responses(
    user_a_status: u16,
    user_a_body: &[u8],
    user_b_status: u16,
    user_b_body: &[u8],
) -> (bool, f64, String) {
    if user_b_status == 401 || user_b_status == 403 {
        return (false, 0.0, "Access properly denied to User B".to_string());
    }

    if user_b_status == 404 && user_a_status == 200 {
        return (
            false,
            0.0,
            "Resource not found for User B (proper isolation)".to_string(),
        );
    }

    if user_a_status == 200 && user_b_status == 200 {
        let a_len = user_a_body.len();
        let b_len = user_b_body.len();

        if a_len < 50 || b_len < 50 {
            return (
                false,
                0.0,
                "Response too small to determine IDOR".to_string(),
            );
        }

        if user_a_body == user_b_body {
            let contains_ignore_case = |needle: &[u8]| -> bool {
                if needle.len() > user_a_body.len() || needle.is_empty() {
                    return false;
                }
                user_a_body
                    .windows(needle.len())
                    .any(|w| w.eq_ignore_ascii_case(needle))
            };

            let has_pii = contains_ignore_case(b"email")
                || contains_ignore_case(b"phone")
                || contains_ignore_case(b"address")
                || contains_ignore_case(b"name")
                || contains_ignore_case(b"account")
                || contains_ignore_case(b"balance")
                || contains_ignore_case(b"password")
                || contains_ignore_case(b"token")
                || contains_ignore_case(b"secret")
                || contains_ignore_case(b"private");

            if has_pii {
                return (
                    true,
                    0.9,
                    "User B received exact same response as User A including PII fields - confirmed IDOR"
                        .to_string(),
                );
            }
            return (
                true,
                0.5,
                "User B received identical response to User A - possible IDOR (may be public data)"
                    .to_string(),
            );
        }

        let size_ratio = a_len.min(b_len) as f64 / a_len.max(b_len) as f64;
        if size_ratio > 0.8 {
            return (
                true,
                0.7,
                format!(
                    "User B received different but similarly-sized response ({}B vs {}B) - likely IDOR with per-user data",
                    a_len, b_len
                ),
            );
        }

        if size_ratio > 0.3 {
            return (
                true,
                0.4,
                format!(
                    "User B received 200 with different content ({}B vs {}B) - potential IDOR, verify manually",
                    a_len, b_len
                ),
            );
        }
    }

    if user_b_status == 302 || user_b_status == 301 {
        return (
            false,
            0.0,
            "User B redirected (likely to login)".to_string(),
        );
    }

    if user_a_status >= 400 && user_b_status >= 400 {
        return (false, 0.0, "Both users got errors - not IDOR".to_string());
    }

    (
        false,
        0.1,
        format!(
            "Inconclusive: User A got {}, User B got {}",
            user_a_status, user_b_status
        ),
    )
}

/// Extract resource IDs from a JSON body.
#[must_use]
pub fn extract_json_ids(body: &str) -> Vec<(String, String)> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };

    let mut ids = Vec::new();
    extract_ids_recursive(&json, "", &mut ids);
    ids
}

fn extract_ids_recursive(value: &serde_json::Value, prefix: &str, ids: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if is_id_param_name(key) {
                    if let Some(s) = val.as_str() {
                        if is_resource_id(s) {
                            ids.push((path.clone(), s.to_string()));
                        }
                    } else if let Some(n) = val.as_i64() {
                        ids.push((path.clone(), n.to_string()));
                    }
                }
                extract_ids_recursive(val, &path, ids);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                extract_ids_recursive(val, &format!("{prefix}[{i}]"), ids);
            }
        }
        _ => {}
    }
}

/// One step in a JSON field path: an object key or an array index.
enum JsonAccessor {
    Key(String),
    Index(usize),
}

/// Parse a field path in the exact form [`extract_ids_recursive`] emits: object
/// keys joined by `.` and array elements as `[i]` (e.g. `outer.user_id`,
/// `items[0].id`, `[1].user_id`). Returns `None` for a malformed/empty path.
fn parse_json_field_path(path: &str) -> Option<Vec<JsonAccessor>> {
    let mut accessors = Vec::new();
    let mut key = String::new();
    let mut chars = path.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '.' => {
                chars.next();
                if !key.is_empty() {
                    accessors.push(JsonAccessor::Key(std::mem::take(&mut key)));
                }
            }
            '[' => {
                chars.next();
                if !key.is_empty() {
                    accessors.push(JsonAccessor::Key(std::mem::take(&mut key)));
                }
                let mut digits = String::new();
                while let Some(&d) = chars.peek() {
                    if d == ']' {
                        chars.next();
                        break;
                    }
                    digits.push(d);
                    chars.next();
                }
                accessors.push(JsonAccessor::Index(digits.parse::<usize>().ok()?));
            }
            _ => {
                key.push(c);
                chars.next();
            }
        }
    }
    if !key.is_empty() {
        accessors.push(JsonAccessor::Key(key));
    }
    if accessors.is_empty() {
        None
    } else {
        Some(accessors)
    }
}

/// Mutate a JSON body by replacing a resource ID field.
///
/// Traverses the full dotted/indexed `field_path` (e.g. `outer.user_id`,
/// `items[0].id`) so nested and array-nested IDs are mutated, not just
/// root-level keys. Returns `None` if the body is not JSON, the path does not
/// resolve to an existing string/number leaf, or (for numeric leaves) `new_id`
/// is not an integer.
#[must_use]
pub fn mutate_json_id(body: &str, field_path: &str, new_id: &str) -> Option<String> {
    let mut json: serde_json::Value = serde_json::from_str(body).ok()?;
    let accessors = parse_json_field_path(field_path)?;

    let mut target = &mut json;
    for accessor in &accessors {
        target = match accessor {
            JsonAccessor::Key(key) => target.as_object_mut()?.get_mut(key)?,
            JsonAccessor::Index(idx) => target.as_array_mut()?.get_mut(*idx)?,
        };
    }

    if target.is_string() {
        *target = serde_json::Value::String(new_id.to_string());
    } else if target.is_number() {
        // Preserve the number type; only mutate if new_id is a valid integer.
        *target = serde_json::json!(new_id.parse::<i64>().ok()?);
    } else {
        // Path resolved to a non-mutatable leaf (bool/null/object/array).
        return None;
    }

    serde_json::to_string(&json).ok()
}

/// Generate a mutated URL for IDOR testing by replacing the resource ID.
#[must_use]
pub fn mutate_id_in_url(url: &str, id_param: &IdParam, new_id: &str) -> String {
    match id_param {
        IdParam::PathSegment { segment_index } => {
            // Split off the query (and fragment) FIRST. Splitting the whole URL
            // on '/' glues the query onto the final path segment, so replacing
            // that segment would silently drop `?a=b` (and re-splitting an
            // earlier segment would leave the query stranded on the wrong one).
            let (path, suffix) = match url.split_once(['?', '#']) {
                Some((p, _)) => {
                    // Preserve the exact original delimiter + remainder.
                    let delim_at = p.len();
                    (p, &url[delim_at..])
                }
                None => (url, ""),
            };
            let segments: Vec<&str> = path.split('/').collect();
            let mutated_path = if *segment_index < segments.len() {
                let mut owned: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
                owned[*segment_index] = new_id.to_string();
                owned.join("/")
            } else {
                path.to_string()
            };
            format!("{mutated_path}{suffix}")
        }
        IdParam::QueryParam { name } => {
            if let Some((base, query)) = url.split_once('?') {
                let new_query: String = query
                    .split('&')
                    .map(|param| {
                        if let Some((n, _)) = param.split_once('=') {
                            if n == name {
                                format!("{n}={new_id}")
                            } else {
                                param.to_string()
                            }
                        } else {
                            param.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                format!("{base}?{new_query}")
            } else {
                url.to_string()
            }
        }
        IdParam::BodyField { .. } => url.to_string(),
    }
}

#[cfg(test)]
mod percent_decode_tests {
    use super::{extract_resource_ids, percent_decode, IdParam};

    #[test]
    fn percent_decode_decodes_hex_and_leaves_malformed_verbatim() {
        assert_eq!(percent_decode("%31%32%33"), "123");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("%zz"), "%zz"); // non-hex escape untouched
        assert_eq!(percent_decode("a%2"), "a%2"); // truncated escape untouched
    }

    #[test]
    fn extract_finds_percent_encoded_query_id_and_preserves_raw() {
        // ?q=%31%32%33%34%35 decodes to 12345 (a numeric id). The param name "q"
        // is NOT an id-name, so detection relies entirely on decoding the value:
        // the raw "%31..." fails every is_resource_id branch and was missed before.
        let ids = extract_resource_ids("https://api.example.com/list?q=%31%32%33%34%35");
        assert!(
            ids.iter().any(|(param, value)| {
                matches!(param, IdParam::QueryParam { name } if name == "q")
                    && value == "%31%32%33%34%35"
            }),
            "percent-encoded query id must be detected with the raw value preserved; got {ids:?}"
        );
    }
}
