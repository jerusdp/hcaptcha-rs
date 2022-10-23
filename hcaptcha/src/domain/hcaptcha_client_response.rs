use crate::{Code, HcaptchaError};
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct HcaptchaClientResponse(String);

impl HcaptchaClientResponse {
    pub fn parse(s: String) -> Result<HcaptchaClientResponse, HcaptchaError> {
        if s.trim().is_empty() {
            let mut codes = HashSet::new();
            codes.insert(Code::MissingResponse);

            Err(HcaptchaError::Codes(codes))
        } else {
            Ok(HcaptchaClientResponse(s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HcaptchaClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::HcaptchaClientResponse;
    use crate::Code;
    use crate::HcaptchaError;
    use claims::assert_err;

    #[test]
    fn whitespace_only_names_are_rejected() {
        let response = " ".to_string();
        assert_err!(HcaptchaClientResponse::parse(response));
    }

    #[test]
    fn empty_string_is_rejected() {
        let response = "".to_string();
        assert_err!(HcaptchaClientResponse::parse(response));
    }

    #[test]
    fn error_set_contains_missing_response_error() {
        let response = "".to_string();

        if let Err(HcaptchaError::Codes(hs)) = HcaptchaClientResponse::parse(response) {
            assert!(hs.contains(&Code::MissingResponse));
        }
    }
}
