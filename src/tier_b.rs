//! Tier-B ID pattern rules (`tier_b/id_patterns.toml`).

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct IdPattern {
    pub name: String,
    pub kind: String,
    pub r#match: String,
    pub regex: String,
    pub mutation: String,
}

#[derive(Clone, Debug, Deserialize)]
struct IdPatternsFile {
    pattern: Vec<IdPattern>,
}

/// Loaded Tier-B ID patterns.
#[derive(Clone, Debug)]
pub struct IdPatternRules {
    patterns: Vec<IdPattern>,
}

impl IdPatternRules {
    /// Load the compile-time-embedded Tier-B ID pattern set.
    ///
    /// The file is compiled into the binary via `include_str!`, so a parse
    /// failure is a build/data invariant violation, never a runtime input
    /// error, but the error is still returned rather than raised as a panic:
    /// a scanner host running many jobs must not crash on a bad data file,
    /// and an `Err` propagates up to the operator just as loudly. Failing
    /// closed here is mandatory either way: the former
    /// `unwrap_or_else(|_| empty)` silently yielded ZERO patterns, so
    /// `classify_token` matched nothing and the whole BOLA id-mutation probe
    /// surface went dark with no operator-visible signal (Law 10). The
    /// `embedded_patterns_load` test guards the asset at build time.
    pub fn embedded() -> Result<Self, String> {
        Self::from_toml(include_str!("../tier_b/id_patterns.toml"))
    }

    pub fn from_toml(toml_src: &str) -> Result<Self, String> {
        let file: IdPatternsFile = toml::from_str(toml_src).map_err(|e| e.to_string())?;
        Ok(Self {
            patterns: file.pattern,
        })
    }

    #[must_use]
    pub fn patterns(&self) -> &[IdPattern] {
        &self.patterns
    }

    /// First pattern whose regex matches the token value.
    #[must_use]
    pub fn classify_token(&self, token: &str) -> Option<&IdPattern> {
        self.patterns
            .iter()
            .find(|p| regex_matches(&p.regex, token))
    }

    /// Apply the pattern's mutation strategy to produce a probe token.
    #[must_use]
    pub fn mutate_token(&self, token: &str, pattern: &IdPattern) -> String {
        match pattern.mutation.as_str() {
            "increment" => mutate_increment(token),
            "swap_neighbor" => mutate_swap_neighbor(token),
            "flip_last_nibble" => mutate_flip_last_nibble(token),
            "base64_decode_increment" => mutate_base64_int(token),
            "slug_neighbor" => mutate_slug_neighbor(token),
            "jwt_payload_tweak" => mutate_jwt_payload(token),
            _ => mutate_increment(token),
        }
    }
}

fn regex_matches(regex: &str, value: &str) -> bool {
    // Lightweight pattern checks without pulling in the `regex` crate.
    match regex {
        r"^[0-9]{1,20}$" => value.parse::<u64>().is_ok() && value.len() <= 20,
        r"^[0-9]{17,20}$" => value.parse::<u64>().is_ok() && (17..=20).contains(&value.len()),
        r"^[0-9a-fA-F]{24}$" => value.len() == 24 && value.chars().all(|c| c.is_ascii_hexdigit()),
        r"^[0-9a-fA-F]{32}$" => value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()),
        r"^[a-z0-9][a-z0-9_-]{2,63}$" => {
            let lower = value.to_ascii_lowercase();
            lower.len() >= 3
                && lower.len() <= 64
                && lower
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        }
        r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" => {
            value.starts_with("eyJ") && value.matches('.').count() == 2
        }
        r"^[A-Za-z0-9+/]{8,}={0,2}$" => {
            value.len() >= 8
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        }
        _ if regex.contains("uuid") || regex.contains('-') => {
            value.len() == 36
                && value.chars().filter(|c| *c == '-').count() == 4
                && value
                    .replace('-', "")
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
        }
        _ => false,
    }
}

fn mutate_increment(token: &str) -> String {
    if let Ok(n) = token.parse::<u64>() {
        return (n.saturating_add(1)).to_string();
    }
    if let Ok(n) = token.parse::<i64>() {
        return (n.saturating_add(1)).to_string();
    }
    format!("{token}x")
}

fn mutate_swap_neighbor(token: &str) -> String {
    // Guard on the CHARACTER count, not token.len() (byte length). A single
    // multi-byte char (e.g. "é" is 2 bytes, 1 char) passed the old byte-length
    // guard and then indexed chars[len - 2] with len == 1, underflowing usize
    // and panicking.
    let mut chars: Vec<char> = token.chars().collect();
    let len = chars.len();
    if len < 2 {
        return format!("{token}0");
    }
    chars.swap(len - 2, len - 1);
    chars.into_iter().collect()
}

fn mutate_flip_last_nibble(token: &str) -> String {
    let mut out = token.to_string();
    if let Some(last) = out.pop() {
        let flipped = match last {
            '0'..='9' => ((last as u8).wrapping_sub(b'0').wrapping_add(1) % 10 + b'0') as char,
            'a'..='f' => ((last as u8).wrapping_sub(b'a').wrapping_add(1) % 6 + b'a') as char,
            'A'..='F' => ((last as u8).wrapping_sub(b'A').wrapping_add(1) % 6 + b'A') as char,
            other => other,
        };
        out.push(flipped);
    }
    out
}

fn mutate_base64_int(token: &str) -> String {
    let padded = token.trim_end_matches('=');
    let mut buf = Vec::new();
    if base64_decode(padded, &mut buf) {
        if let Ok(s) = std::str::from_utf8(&buf) {
            if let Ok(n) = s.parse::<u64>() {
                return base64_encode(&(n + 1).to_string());
            }
        }
    }
    mutate_increment(token)
}

fn base64_decode(input: &str, out: &mut Vec<u8>) -> bool {
    const TABLE: [i8; 128] = {
        let mut t = [-1i8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i as i8;
            t[(b'a' + i) as usize] = i as i8 + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = d as i8 + 52;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=').collect();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in bytes {
        if b >= 128 {
            return false;
        }
        let v = TABLE[b as usize];
        if v < 0 {
            return false;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    !out.is_empty()
}

fn base64_encode(s: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map(u32::from).unwrap_or(0);
        let b2 = chunk.get(2).copied().map(u32::from).unwrap_or(0);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn mutate_slug_neighbor(token: &str) -> String {
    if let Some((head, tail)) = token.rsplit_once('-') {
        return format!("{head}-probe-{tail}");
    }
    format!("{token}-probe")
}

fn mutate_jwt_payload(token: &str) -> String {
    let mut parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 {
        parts[1] = "eyJwcm9iZSI6dHJ1ZX0";
        return parts.join(".");
    }
    format!("{token}.t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_patterns_load() {
        let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
        // Assert the exact embedded set, not merely non-empty: a truncated or
        // partially-parsed ruleset silently shrinks the BOLA probe surface.
        assert_eq!(rules.patterns().len(), 8, "embedded Tier-B pattern count");
        let names: Vec<&str> = rules.patterns().iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"sequential_int"));
        assert!(names.contains(&"uuid_v4"));
        assert!(names.contains(&"jwt_shape"));
        assert!(names.contains(&"snowflake"));
    }

    #[test]
    fn from_toml_rejects_malformed_source() {
        // Negative twin: malformed TOML must surface as Err, never a silent empty
        // ruleset. embedded() turns this same Err into a loud panic.
        let err = IdPatternRules::from_toml("this is = not [valid toml").unwrap_err();
        assert!(!err.is_empty(), "parse error must carry context");
        // A syntactically valid file missing the `pattern` array is also rejected.
        assert!(IdPatternRules::from_toml("unrelated = 1").is_err());
    }

    #[test]
    fn classifies_sequential_int() {
        let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
        let pat = rules.classify_token("42").expect("pattern");
        assert_eq!(pat.mutation, "increment");
    }

    #[test]
    fn swap_neighbor_single_multibyte_char_does_not_panic() {
        // "é" is 1 char but 2 bytes: the old `token.len() < 2` byte guard let it
        // through and then underflowed on chars[len - 2] with len == 1.
        assert_eq!(mutate_swap_neighbor("é"), "é0");
        // Other single-char tokens (multi-byte and ASCII) take the short branch.
        assert_eq!(mutate_swap_neighbor("中"), "中0");
        assert_eq!(mutate_swap_neighbor("a"), "a0");
        assert_eq!(mutate_swap_neighbor(""), "0");
    }

    #[test]
    fn swap_neighbor_swaps_last_two_chars() {
        assert_eq!(mutate_swap_neighbor("abcd"), "abdc");
        // Multi-byte chars swap by character, not byte.
        assert_eq!(mutate_swap_neighbor("aé"), "éa");
    }
}
