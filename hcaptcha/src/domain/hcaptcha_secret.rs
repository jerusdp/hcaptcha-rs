use crate::{Code, HcaptchaError};
use std::collections::HashSet;
use std::fmt;

#[cfg(feature = "ext")]
const SECRET_LEN: usize = 42;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct HcaptchaSecret(String);

impl fmt::Display for HcaptchaSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl HcaptchaSecret {
    #[cfg(not(feature = "ext"))]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Simple check of secret.", skip(s), level = "debug")
    )]
    pub fn parse(s: String) -> Result<Self, HcaptchaError> {
        if s.trim().is_empty() {
            let mut codes = HashSet::new();
            codes.insert(Code::MissingSecret);

            #[cfg(feature = "trace")]
            tracing::debug!("Secret string is missing");
            Err(HcaptchaError::Codes(codes))
        } else {
            Ok(HcaptchaSecret(s))
        }
    }

    #[cfg(feature = "ext")]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Extended check of secret.", skip(s), level = "debug")
    )]
    pub fn parse(s: String) -> Result<Self, HcaptchaError> {
        let is_empty_or_whitespace = s.trim().is_empty();
        let is_wrong_length = s.len() != SECRET_LEN;
        let is_not_a_hex_string = !is_hex_string(&s);
        let mut codes = HashSet::new();
        if is_empty_or_whitespace {
            codes.insert(Code::MissingSecret);
        };
        if is_wrong_length {
            codes.insert(Code::InvalidSecretExtWrongLen);
        };
        if is_not_a_hex_string {
            codes.insert(Code::InvalidSecretExtNotHex);
        };
        if codes.is_empty() {
            Ok(HcaptchaSecret(s))
        } else {
            #[cfg(feature = "trace")]
            tracing::debug!("Extended check found errors in secret string: {:?}", &codes);
            Err(HcaptchaError::Codes(codes))
        }
    }
}

#[cfg(feature = "ext")]
#[cfg_attr(
    feature = "trace",
    tracing::instrument(name = "Check for hex string.", skip(s), level = "debug")
)]
fn is_hex_string(s: &str) -> bool {
    if s.len() != SECRET_LEN {
        return false;
    };

    let start_is_valid = &s[0..2] == "0x";
    let string_is_valid = hex::decode(s.trim_start_matches("0x")).is_ok();

    start_is_valid && string_is_valid
}

#[cfg(test)]
mod tests {
    use super::HcaptchaSecret;
    use crate::Code;
    use crate::HcaptchaError;
    use claims::{assert_err, assert_ok};

    #[test]
    fn whitespace_only_secrets_are_rejected() {
        let secret = " ".to_string();
        assert_err!(HcaptchaSecret::parse(secret));
    }
    #[test]
    fn empty_string_is_rejected() {
        let secret = "".to_string();
        assert_err!(HcaptchaSecret::parse(secret));
    }
    #[cfg(feature = "ext")]
    #[test]
    fn secret_longer_than_secret_len_is_rejected() {
        let secret = "1234567890123456789012345678901234567890123".to_string();
        assert_err!(HcaptchaSecret::parse(secret));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn secret_shorter_than_secret_len_is_rejected() {
        let secret = "12345678901234567890123456789012345678901".to_string();
        assert_err!(HcaptchaSecret::parse(secret));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn secret_that_is_not_a_valid_hex_string_is_rejected() {
        let secret = "abcdefghijklmnopqrstuv".to_string();
        assert_err!(HcaptchaSecret::parse(secret));
    }

    #[test]
    fn error_set_contains_missing_secret_error() {
        let secret = "".to_string();
        if let Err(HcaptchaError::Codes(hs)) = HcaptchaSecret::parse(secret) {
            assert!(hs.contains(&Code::MissingSecret));
        }
    }

    #[cfg(feature = "ext")]
    #[test]
    fn error_set_contains_invalid_secret_error() {
        let secret = "abcdefghijklmnopqrstuvxyzabcdefghijk".to_string();
        if let Err(HcaptchaError::Codes(hs)) = HcaptchaSecret::parse(secret) {
            assert!(hs.contains(&Code::InvalidSecretExtNotHex));
            assert!(hs.contains(&Code::InvalidSecretExtWrongLen));
        }
    }

    #[test]
    fn test_secret_key_is_valid() {
        let secret = "0x0000000123456789abcdefABCDEF000000000000".to_string();
        assert_ok!(HcaptchaSecret::parse(secret));
    }
}
