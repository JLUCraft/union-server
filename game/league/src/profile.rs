/// Identity attribute kind and verifier evidence for a Minecraft profile.
pub const GAME_PROFILE: &str = "game_profile";

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
