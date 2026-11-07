/// Identity attribute kind and verifier evidence for a Minecraft profile.
pub const GAME_PROFILE: &str = "game_profile";

/// Common identity form values for game management terminals.
pub struct Suggestions;

impl client::management::Suggestions for Suggestions {
    fn for_field(&self, field: &str) -> Vec<String> {
        match field {
            "service" => vec!["application"],
            "permission" => vec!["read", "write", "admin", "use", "manage"],
            "kind" => vec![GAME_PROFILE],
            "evidence" => vec!["institutional_email", GAME_PROFILE],
            _ => Vec::new(),
        }
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
}

/// Canonical Minecraft profile UUID: 32 lowercase hexadecimal digits, without separators.
pub fn validate_game_profile(value: &str) -> crate::Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(crate::Error::Denied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_forms_offer_game_kind_and_verifier_evidence() {
        let forms =
            client::management::execute_with(client::management::Request::Forms, &Suggestions)
                .unwrap();
        let forms = forms.as_array().unwrap();
        for action in ["bind_attribute", "unbind_attribute"] {
            let form = forms.iter().find(|form| form["action"] == action).unwrap();
            let kind = form["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["name"] == "kind")
                .unwrap();
            assert_eq!(kind["suggestions"], serde_json::json!([GAME_PROFILE]));
        }
        let verifier = forms
            .iter()
            .find(|form| form["action"] == "authorize_verifier")
            .unwrap();
        let evidence = verifier["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == "evidence")
            .unwrap();
        assert_eq!(
            evidence["suggestions"],
            serde_json::json!(["institutional_email", GAME_PROFILE])
        );
    }

    #[test]
    fn game_profiles_require_canonical_uuid_text() {
        for valid in [
            "00000000000000000000000000000000",
            "0123456789abcdef0123456789abcdef",
            "ffffffffffffffffffffffffffffffff",
        ] {
            assert!(validate_game_profile(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "01234567-89ab-cdef-0123-456789abcdef",
            "g123456789abcdef0123456789abcdef",
            " 123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcde\n",
            "０１２３４５６７８９abcdef",
        ] {
            assert!(
                matches!(validate_game_profile(invalid), Err(crate::Error::Denied)),
                "{invalid:?}"
            );
        }
    }
}
