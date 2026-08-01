use bolascan::{extract_resource_ids, mutate_id_in_url, IdParam, IdPatternRules};
use proptest::prelude::*;

proptest! {
    #[test]
    fn mutate_path_preserves_host_suffix(id in 0u64..1_000_000u64) {
        let url = format!("https://api.example.com/users/{id}/profile");
        let ids = extract_resource_ids(&url);
        prop_assume!(id > 0);
        prop_assume!(!ids.is_empty());
        let (param, _) = &ids[0];
        let mutated = mutate_id_in_url(&url, param, "999");
        prop_assert!(mutated.contains("api.example.com"));
        prop_assert!(mutated.contains("999"));
        prop_assert_ne!(mutated, url);
    }

    #[test]
    fn mutate_query_preserves_other_params(id in 1u64..1_000_000u64, page in 1u32..100u32) {
        let url = format!("https://api.example.com/data?user_id={id}&page={page}");
        let mutated = mutate_id_in_url(
            &url,
            &IdParam::QueryParam { name: "user_id".into() },
            "999",
        );
        prop_assert!(mutated.contains("user_id=999"));
        let page_param = format!("page={page}");
        prop_assert!(mutated.contains(page_param.as_str()));
    }

    #[test]
    fn tier_b_increment_changes_numeric_token(n in 1u64..999_999u64) {
        let rules = IdPatternRules::embedded().expect("embedded Tier-B rules must parse");
        let token = n.to_string();
        if let Some(pat) = rules.classify_token(&token) {
            let mutated = rules.mutate_token(&token, pat);
            prop_assert_ne!(mutated, token);
        }
    }
}

#[test]
fn static_about_path_has_no_ids() {
    let url = "https://example.com/about/team/contact";
    let ids = extract_resource_ids(url);
    assert!(ids.is_empty());
}
